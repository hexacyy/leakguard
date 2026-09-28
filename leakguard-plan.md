# LeakGuard — Plan

## Top-Level Overview

Build a single-file Python CLI tool (`leakguard.py`) with no external dependencies that scans files for secrets before they are committed to git. The tool is self-contained: it runs regex + entropy checks, supports allowlisting, installs a git pre-commit hook, and ships with a demo folder to prove it works end-to-end.

Files to create:
- `leakguard.py` — the entire tool
- `README.md` — user-facing documentation
- `demo/fake_config.py` — test data with obviously fake secrets
- `.leakguardignore` — workspace-level allowlist that skips the `demo/` folder

---

## Sub-Tasks

---

### Sub-Task 1 — Core scanner engine (`leakguard.py`)

**Intent**
Implement the scanning logic inside `leakguard.py`. This is the heart of the tool: it must read files, run regex patterns and entropy checks, apply allowlist rules, and return structured findings.

**Expected Outcomes**
- `leakguard.py` exists and is importable / runnable.
- A `PATTERNS` dict maps secret-type names to compiled regex objects covering all required types.
- A `shannon_entropy(s)` function returns the Shannon entropy of a string.
- A `is_binary(path)` function returns True if a file contains null bytes.
- A `load_ignore_patterns()` function reads `.leakguardignore` and returns a list of fnmatch patterns.
- A `scan_file(path, ignore_patterns)` function returns a list of finding dicts: `{file, line, type, preview}`.
  - Skips `.git/` paths, binary files, and paths matched by ignore patterns.
  - Skips lines containing the inline comment `# leakguard:ignore`.
  - Flags files whose basename matches `.env`, `.env.*`, `id_rsa`, `*.pem`, `credentials.json` with finding type `"sensitive filename"`.
  - Runs all regex patterns line-by-line.
  - Runs entropy check only for files with extensions: `.py .js .ts .env .yaml .yml .json .toml .cfg .ini .sh`; only on tokens of length >= 20 with entropy > 4.0.
  - Preview is: first 4 chars + `****` mask.
- A `get_staged_files()` function runs `git diff --cached --name-only` and returns the list.

**Todo List**
1. Create `leakguard.py` with a module-level docstring explaining the tool.
2. Define `PATTERNS` dict with all required regex patterns (AWS key IDs, AWS secret keys, GitHub tokens, Google API keys, OpenAI/Anthropic keys, Slack tokens, private key blocks, generic assignments, JWTs).
3. Implement `shannon_entropy(s: str) -> float`.
4. Implement `is_binary(path: str) -> bool` using a null-byte probe.
5. Implement `load_ignore_patterns() -> list[str]` reading `.leakguardignore`.
6. Implement `get_staged_files() -> list[str]` using subprocess.
7. Implement `scan_file(path, ignore_patterns) -> list[dict]` with all detection logic.

**Relevant Context**
- All regex patterns must use raw strings and be compiled at module level for efficiency.
- AWS key ID pattern: `AKIA[0-9A-Z]{16}`.
- AWS secret key: 40-char base64 string, often found after `=` on same line as `aws_secret`.
- GitHub token prefixes: `ghp_`, `gho_`, `github_pat_`.
- Google API key: `AIza[0-9A-Za-z\-_]{35}`.
- OpenAI/Anthropic: `sk-[A-Za-z0-9]{32,}` and `sk-ant-[A-Za-z0-9\-_]{32,}`.
- Slack: `xox[baprs]-[0-9A-Za-z\-]{10,}`.
- Private key block: `-----BEGIN [A-Z ]*PRIVATE KEY-----`.
- Generic assignment: `(?i)(password|secret|api_key|token)\s*[=:]\s*["\']?([^"\'\\s]{4,})`.
- JWT: three base64url segments separated by dots.
- Shannon entropy: H = -sum(p * log2(p)) for each unique character's frequency.
- Entropy check applies only to extensions: `.py .js .ts .env .yaml .yml .json .toml .cfg .ini .sh`.

**Status** `[ ] pending`

---

### Sub-Task 2 — CLI interface and output formatting

**Intent**
Wire up `argparse`, ANSI colored output, the summary line, and the exit-code logic so the tool is fully runnable from the command line.

**Expected Outcomes**
- `python leakguard.py` with no arguments scans staged files.
- `python leakguard.py file1 file2 ...` scans the given files.
- `python leakguard.py --install` installs the pre-commit hook (Sub-Task 3).
- Each finding is printed in color: red label for type, yellow for file:line, dim for masked preview.
- Summary line: `✖  X secrets found in Y files` (red) or `✔  No secrets found` (green).
- Exit code 1 when findings exist, 0 otherwise.
- ANSI codes are only emitted when stdout is a TTY; fall back to plain text otherwise.

**Todo List**
1. Add ANSI color constants at module top (RED, YELLOW, GREEN, DIM, RESET), gated by `sys.stdout.isatty()`.
2. Implement `print_finding(finding)` using the color constants.
3. Implement `print_summary(total_findings, total_files)`.
4. Implement `main()` with argparse: positional `files` (nargs=`*`), `--install` flag.
5. In `main()`: if no files given, call `get_staged_files()`; iterate, call `scan_file`, collect findings, print them, print summary, `sys.exit(1 if findings else 0)`.
6. Guard with `if __name__ == "__main__": main()`.

**Relevant Context**
- When staged file list is empty and no files are given, print a friendly message and exit 0.
- TTY detection: `sys.stdout.isatty()`.

**Status** `[ ] pending`

---

### Sub-Task 3 — Git hook installer

**Intent**
Implement `--install` which writes a `pre-commit` shell script into `.git/hooks/` and makes it executable, so the scanner runs automatically before every `git commit`.

**Expected Outcomes**
- `python leakguard.py --install` creates/overwrites `.git/hooks/pre-commit`.
- The hook script calls `python leakguard.py` (using the absolute path to the script).
- The hook is made executable via `os.chmod`.
- A success message is printed; if `.git/` does not exist the error is reported clearly.

**Todo List**
1. Implement `install_hook()` function.
2. Resolve the absolute path of `leakguard.py` using `os path abspath(__file__)`.
3. Write the hook script content (shebang `#!/bin/sh`, then `python "<abs_path>"`).
4. Apply `chmod +x` equivalent using `os.chmod` with `stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH`.
5. Print confirmation message.

**Relevant Context**
- `.git/hooks/` must exist; guard against the case where the tool is run outside a git repo.
- Use `os.path.abspath(__file__)` so the hook works regardless of working directory.

**Status** `[ ] pending`

---

### Sub-Task 4 — Demo folder and allowlist

**Intent**
Create `demo/fake_config.py` with obviously fake test secrets to prove all detection patterns fire, plus one line marked `# leakguard:ignore` to demonstrate suppression. Add `.leakguardignore` to skip `demo/` by default so working in this repo doesn't trigger false alarms.

**Expected Outcomes**
- `demo/fake_config.py` contains at least one fake secret per detection category (AWS, GitHub, Google, OpenAI, Slack, private key block, generic assignment, JWT, entropy).
- One line in `demo/fake_config.py` has `# leakguard:ignore` and is NOT flagged.
- `.leakguardignore` contains `demo/` so normal staged-file scans skip it.
- Running `python leakguard.py demo/fake_config.py` explicitly does scan it (direct file argument bypasses ignore patterns for path-based ignore only — or alternatively the demo/ ignore entry in `.leakguardignore` is noted as intentional and the README explains how to scan directly).

**Design note on ignore behavior:** `.leakguardignore` path patterns apply when scanning staged files automatically. When files are passed explicitly as arguments, `.leakguardignore` is still respected (fnmatch on the path). To scan the demo folder despite the ignore entry, the user removes or comments out the `demo/` line, or the README documents using a flag. Given simplicity is paramount, the simplest approach: `.leakguardignore` is always respected, and the README instructs the reader to scan demo directly by temporarily commenting out the `demo/` line, or we make `--no-ignore` a future note. Actually, the cleanest solution for the demo: put `demo/*.py` in `.leakguardignore` for staged-file protection, but note in the README that explicit file args also respect the ignore file. The demo section of the README will show the output from a run where the ignore entry is absent or overridden.

**Todo List**
1. Create `demo/` directory with `fake_config.py`.
2. Add one fake secret per pattern category, clearly labeled with comments like `# fake - do not use`.
3. Add one line with `# leakguard:ignore` demonstrating suppression.
4. Create `.leakguardignore` at the workspace root with a `demo/` entry.
5. Add a `# leakguard:ignore` example comment in `.leakguardignore` itself as documentation.

**Status** `[ ] pending`

---

### Sub-Task 5 — README.md

**Intent**
Write a clear, honest README that covers the required sections, includes the detection coverage table, limitations, and a placeholder for the "How I used IBM Bob" section.

**Expected Outcomes**
- `README.md` exists with all six required sections.
- Detection coverage table maps each secret type to its detection method (regex or entropy).
- Sample output section shows real-looking terminal output (can be written by hand to match what the demo produces).
- Limitations section is honest about false positives and the entropy heuristic.
- "How I used IBM Bob" section is a heading with placeholder text.

**Todo List**
1. Write the Problem section.
2. Write the What It Does section.
3. Write the Quick Start section with one-liner hook install and manual scan command.
4. Write the Sample Output section (formatted as a code block matching actual demo output).
5. Write the Detection Coverage table.
6. Write the Limitations section.
7. Write the "How I used IBM Bob" placeholder section.

**Status** `[ ] pending`

---

## Execution Order

```
Sub-Task 1 → Sub-Task 2 → Sub-Task 3 → Sub-Task 4 → Sub-Task 5
```

Sub-Tasks 1, 2, and 3 all go into the same file (`leakguard.py`) and should be implemented together in one pass. Sub-Tasks 4 and 5 are independent files.

## Files Created

| File | Sub-Tasks |
|------|-----------|
| `leakguard.py` | 1, 2, 3 |
| `demo/fake_config.py` | 4 |
| `.leakguardignore` | 4 |
| `README.md` | 5 |

## Design Decisions

- **Ignore bypass**: Explicit file args passed on the CLI bypass `.leakguardignore`. Inline `# leakguard:ignore` comments always apply in all modes.
