#!/usr/bin/env python3
"""
leakguard.py — Prevent secrets from being committed to public GitHub repos.

Usage:
    python leakguard.py                     # scan all git-staged files
    python leakguard.py file1.py file2.env  # scan specific files (bypasses .leakguardignore)
    python leakguard.py --install           # install git pre-commit hook

Inline suppression: append  # leakguard:ignore  to any line to skip it.
Path suppression:   list fnmatch patterns in .leakguardignore (one per line).
"""

import argparse
import fnmatch
import math
import os
import re
import stat
import subprocess
import sys

# ---------------------------------------------------------------------------
# ANSI colour helpers (only when stdout is a real terminal)
# ---------------------------------------------------------------------------
_USE_COLOUR = sys.stdout.isatty()

# Use UTF-8 symbols only when the terminal encoding supports them
_UTF8 = (getattr(sys.stdout, "encoding", "") or "").lower().replace("-", "") in (
    "utf8", "utf8bom"
)
_CROSS  = "\u2716" if _UTF8 else "X"
_CHECK  = "\u2714" if _UTF8 else "OK"

def _c(code: str, text: str) -> str:
    """Wrap *text* in an ANSI escape code when colours are enabled."""
    return f"\033[{code}m{text}\033[0m" if _USE_COLOUR else text

def _red(t: str) -> str:    return _c("31;1", t)
def _green(t: str) -> str:  return _c("32;1", t)
def _yellow(t: str) -> str: return _c("33", t)
def _dim(t: str) -> str:    return _c("2", t)
def _cyan(t: str) -> str:   return _c("36", t)


# ---------------------------------------------------------------------------
# Secret patterns
# ---------------------------------------------------------------------------
# Each entry: "Secret Type Label" -> compiled regex.
# The regex must have at least one capturing group (group 1) that holds
# the actual secret value so we can build the masked preview.
PATTERNS: dict[str, re.Pattern] = {
    # AWS access key ID  (AKIA + 16 uppercase alphanumeric chars)
    "AWS Access Key ID": re.compile(
        r"(AKIA[0-9A-Z]{16})"
    ),
    # AWS secret access key — 40-char base64, usually on a line with aws_secret
    "AWS Secret Key": re.compile(
        r"(?i)aws.{0,20}['\"]?([A-Za-z0-9/+]{40})['\"]?"
    ),
    # GitHub personal access token  (classic and fine-grained)
    "GitHub Token": re.compile(
        r"(gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{82,})"
    ),
    # Google API key
    "Google API Key": re.compile(
        r"(AIza[0-9A-Za-z\-_]{35})"
    ),
    # OpenAI / Anthropic style keys
    "OpenAI / Anthropic Key": re.compile(
        r"(sk-ant-[A-Za-z0-9\-_]{32,}|sk-[A-Za-z0-9]{32,})"
    ),
    # Slack tokens  (bot, app, user, workspace, …)
    "Slack Token": re.compile(
        r"(xox[baprs]-[0-9A-Za-z\-]{10,})"
    ),
    # PEM private key block header
    "Private Key Block": re.compile(
        r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)"
    ),
    # Generic high-risk assignment:  password = "abc123"  # leakguard:ignore
    "Generic Secret Assignment": re.compile(
        r"(?i)(?:^|[\s;,{(\[])(?:password|passwd|secret|api_key|apikey|token|auth_token)"
        r"\s*[=:]\s*['\"]?([^'\"\s\\]{4,})"
    ),
    # JSON Web Token  (three base64url segments separated by dots)
    "JWT": re.compile(
        r"(ey[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})"
    ),
}

# File extensions for which we run the entropy check
_ENTROPY_EXTENSIONS = {
    ".py", ".js", ".ts", ".env", ".yaml", ".yml",
    ".json", ".toml", ".cfg", ".ini", ".sh",
}

# Sensitive filenames/patterns that warrant a warning regardless of content
_SENSITIVE_NAMES = [".env", "id_rsa", "credentials.json"]
_SENSITIVE_GLOBS = ["*.pem", ".env.*"]

# Inline suppression marker
_IGNORE_MARKER = "# leakguard:ignore"

# Minimum token length and entropy threshold for the entropy heuristic
_ENTROPY_MIN_LEN = 20
_ENTROPY_THRESHOLD = 4.0

# Delimiters used to split a line into tokens for entropy scanning
_TOKEN_RE = re.compile(r"['\"\s,;{}()\[\]=:]+")


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def shannon_entropy(s: str) -> float:
    """Return the Shannon entropy (bits per character) of *s*."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length)
                for count in freq.values())


def is_binary(path: str) -> bool:
    """Return True if *path* looks like a binary file (contains a null byte)."""
    try:
        with open(path, "rb") as fh:
            return b"\x00" in fh.read(8192)
    except OSError:
        return False


def load_ignore_patterns() -> list[str]:
    """
    Read .leakguardignore from the current working directory.
    Returns a list of fnmatch-style patterns; blank lines and # comments skipped.
    """
    ignore_file = ".leakguardignore"
    if not os.path.isfile(ignore_file):
        return []
    patterns = []
    with open(ignore_file, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if line and not line.startswith("#"):
                patterns.append(line)
    return patterns


def _is_ignored(path: str, patterns: list[str]) -> bool:
    """Return True if *path* matches any pattern in *patterns* (fnmatch)."""
    # Normalise to forward slashes for consistent fnmatch behaviour on Windows
    norm = path.replace("\\", "/")
    for pat in patterns:
        norm_pat = pat.replace("\\", "/").rstrip("/")
        # Allow "demo/" to match "demo/anything"
        if fnmatch.fnmatch(norm, pat) or fnmatch.fnmatch(norm, norm_pat + "/*"):
            return True
        # Also match the basename alone
        if fnmatch.fnmatch(os.path.basename(norm), pat):
            return True
    return False


def _is_sensitive_filename(path: str) -> bool:
    """Return True if the file's basename matches a known sensitive-name pattern."""
    name = os.path.basename(path)
    if name in _SENSITIVE_NAMES:
        return True
    for pat in _SENSITIVE_GLOBS:
        if fnmatch.fnmatch(name, pat):
            return True
    return False


def _mask(value: str) -> str:
    """Return a masked preview: first 4 chars + ****."""
    if len(value) <= 4:
        return value + "****"
    return value[:4] + "****"


# ---------------------------------------------------------------------------
# File scanner
# ---------------------------------------------------------------------------

def scan_file(path: str, ignore_patterns: list[str], bypass_ignore: bool = False) -> list[dict]:
    """
    Scan *path* for secrets.

    Parameters
    ----------
    path:            File to scan.
    ignore_patterns: Patterns from .leakguardignore.
    bypass_ignore:   When True (explicit CLI arg), skip the ignore-pattern check.

    Returns a list of finding dicts:
        {file, line, type, preview}
    """
    findings: list[dict] = []

    # Normalise path separators
    path = path.replace("\\", "/")

    # Always skip .git/ internals
    if "/.git/" in path or path.startswith(".git/"):
        return findings

    # Apply .leakguardignore (unless this file was passed explicitly)
    if not bypass_ignore and _is_ignored(path, ignore_patterns):
        return findings

    # Sensitive filename — flag once, regardless of content
    if _is_sensitive_filename(path):
        findings.append({
            "file": path,
            "line": 0,
            "type": "Sensitive Filename",
            "preview": _mask(os.path.basename(path)),
        })
        # Don't return yet — also scan the content

    # Skip binary files
    if is_binary(path):
        return findings

    # Determine whether to run the entropy check for this file
    _, ext = os.path.splitext(path)
    run_entropy = ext.lower() in _ENTROPY_EXTENSIONS

    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError as exc:
        print(_dim(f"  [skip] cannot read {path}: {exc}"), file=sys.stderr)
        return findings

    for lineno, raw_line in enumerate(lines, start=1):
        # Inline suppression: skip the entire line
        if _IGNORE_MARKER in raw_line:
            continue

        line_text = raw_line.rstrip("\n")

        # --- Regex pattern checks ---
        for label, pattern in PATTERNS.items():
            for match in pattern.finditer(line_text):
                secret = match.group(1)  # leakguard:ignore
                findings.append({
                    "file": path,
                    "line": lineno,
                    "type": label,
                    "preview": _mask(secret),
                })

        # --- Shannon entropy check ---
        if run_entropy:
            for token in _TOKEN_RE.split(line_text):
                if len(token) >= _ENTROPY_MIN_LEN and shannon_entropy(token) > _ENTROPY_THRESHOLD:
                    # Avoid double-reporting what a regex already caught
                    already_flagged = any(
                        f["file"] == path and f["line"] == lineno
                        for f in findings
                    )
                    if not already_flagged:
                        findings.append({
                            "file": path,
                            "line": lineno,
                            "type": "High Entropy String",
                            "preview": _mask(token),
                        })

    return findings


# ---------------------------------------------------------------------------
# Git integration
# ---------------------------------------------------------------------------

def get_staged_files() -> list[str]:
    """Return the list of files currently staged in git (--cached)."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            capture_output=True,
            text=True,
            check=True,
        )
        return [f for f in result.stdout.splitlines() if f.strip()]
    except subprocess.CalledProcessError as exc:
        print(_red(f"[leakguard] git error: {exc.stderr.strip()}"), file=sys.stderr)
        return []
    except FileNotFoundError:
        print(_red("[leakguard] git not found in PATH."), file=sys.stderr)
        return []


# ---------------------------------------------------------------------------
# Git hook installer
# ---------------------------------------------------------------------------

HOOK_TEMPLATE = """\
#!/bin/sh
# LeakGuard pre-commit hook — installed by: python leakguard.py --install
python "{script_path}"
"""

def install_hook() -> None:
    """Write a pre-commit hook into .git/hooks/ that runs leakguard."""
    hooks_dir = os.path.join(".git", "hooks")
    if not os.path.isdir(hooks_dir):
        print(_red("[leakguard] .git/hooks/ not found -- are you inside a git repo?"))
        sys.exit(1)

    hook_path = os.path.join(hooks_dir, "pre-commit")
    script_path = os.path.abspath(__file__)

    # On Windows paths in shell scripts need forward slashes
    script_path_posix = script_path.replace("\\", "/")

    content = HOOK_TEMPLATE.format(script_path=script_path_posix)  # leakguard:ignore

    with open(hook_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)

    # Make executable  (rwxr-xr-x equivalent)
    os.chmod(hook_path, (
        stat.S_IRWXU |                          # owner: rwx
        stat.S_IRGRP | stat.S_IXGRP |           # group: r-x
        stat.S_IROTH | stat.S_IXOTH             # other: r-x
    ))

    print(_green(f"[leakguard] {_CHECK}  Pre-commit hook installed at: {hook_path}"))
    print(_dim("             Every  git commit  will now run leakguard automatically."))


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def print_finding(finding: dict) -> None:
    """Print a single finding to stdout in a readable, coloured format."""
    loc = f"{finding['file']}:{finding['line']}" if finding['line'] else finding['file']
    print(
        f"  {_red(_CROSS)}  {_yellow(loc)}"
        f"  {_cyan(finding['type'])}"
        f"  {_dim(finding['preview'])}"
    )


def print_summary(total: int, n_files: int) -> None:
    """Print the final summary line."""
    if total == 0:
        print(_green(f"\n{_CHECK}  No secrets found."))
    else:
        print(
            _red(f"\n{_CROSS}  {total} secret{'s' if total != 1 else ''} found"
                 f" in {n_files} file{'s' if n_files != 1 else ''}.")
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="leakguard",
        description="Scan files for secrets before committing to git.",
    )
    parser.add_argument(
        "files",
        nargs="*",
        metavar="FILE",
        help="Files to scan (bypasses .leakguardignore). "
             "Defaults to all git-staged files.",
    )
    parser.add_argument(
        "--install",
        action="store_true",
        help="Install a git pre-commit hook that runs leakguard automatically.",
    )
    args = parser.parse_args()

    if args.install:
        install_hook()
        return

    # Determine the list of files to scan
    explicit = bool(args.files)
    files_to_scan = args.files if explicit else get_staged_files()

    if not files_to_scan:
        print(_dim("[leakguard] No files to scan."))
        sys.exit(0)

    ignore_patterns = load_ignore_patterns()

    all_findings: list[dict] = []
    files_with_findings: set[str] = set()

    print(_dim(f"[leakguard] Scanning {len(files_to_scan)} file(s)...\n"))

    for path in files_to_scan:
        # When files are given explicitly they bypass .leakguardignore;
        # inline # leakguard:ignore is always respected (handled inside scan_file).
        findings = scan_file(path, ignore_patterns, bypass_ignore=explicit)
        if findings:
            files_with_findings.add(path)
            for f in findings:
                print_finding(f)
        all_findings.extend(findings)

    print_summary(len(all_findings), len(files_with_findings))

    sys.exit(1 if all_findings else 0)


if __name__ == "__main__":
    main()
