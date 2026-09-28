# LeakGuard

> **Stop secrets before they hit GitHub.**  
> A single-file Python scanner with no external dependencies.

---

## Problem

Developers leak API keys, passwords, and tokens to public repositories every day — often under time pressure, when moving fast, or when copy-pasting config files. Automated bots scan every public GitHub push in near-real-time and harvest leaked credentials within **minutes** of exposure. A leaked AWS key can spin up thousands of cloud instances in your name before you even notice the commit. Rotating secrets after the fact is painful and sometimes impossible if downstream services have already been compromised.

The safest fix is to block secrets at the source: before the `git commit` ever completes.

---

## What It Does

LeakGuard is a pre-commit scanner that inspects files you are about to commit and refuses the commit if it finds anything suspicious. It uses two complementary techniques:

| Technique | What it catches |
|---|---|
| **Regex patterns** | Known secret formats: AWS keys, GitHub tokens, Google API keys, OpenAI/Anthropic keys, Slack tokens, PEM private-key headers, JWTs, generic `password=` / `api_key=` assignments |
| **Shannon entropy** | Long random-looking strings (≥ 20 chars, entropy > 4.0 bits/char) that don't match any known pattern but look like secrets anyway |

It also flags **sensitive filenames** (`.env`, `*.pem`, `id_rsa`, `credentials.json`) regardless of content.

**Allowlisting** keeps false positives from blocking your work:

- Add paths or glob patterns to `.leakguardignore` to skip entire files or directories during staged-file scans.
- Append `# leakguard:ignore` to any individual line to suppress that specific finding everywhere.

---

## Quick Start

### 1. Install the pre-commit hook (one command)

```bash
python leakguard.py --install
```

Every subsequent `git commit` will automatically run the scanner. The commit is blocked if any secrets are found.

### 2. Scan manually

```bash
# Scan all currently staged files
python leakguard.py

# Scan specific files directly (bypasses .leakguardignore)
python leakguard.py path/to/config.py path/to/.env
```

### 3. Suppress a false positive inline

```python
# This line won't be flagged, even if it looks like a secret:
INTERNAL_TOKEN = "some-value-here"  # leakguard:ignore
```

### 4. Suppress an entire path

Add a line to `.leakguardignore`:

```
tests/fixtures/
*.example.env
```

---

## Sample Output

Running `python leakguard.py demo/fake_config.py` against the included demo file:

```
[leakguard] Scanning 1 file(s)...

  X  demo/fake_config.py:8   AWS Access Key ID           AKIA****
  X  demo/fake_config.py:9   High Entropy String         wJal****
  X  demo/fake_config.py:12  GitHub Token                ghp_****
  X  demo/fake_config.py:15  Google API Key              AIza****
  X  demo/fake_config.py:18  High Entropy String         sk-p****
  X  demo/fake_config.py:21  OpenAI / Anthropic Key      sk-a****
  X  demo/fake_config.py:24  Slack Token                 xoxb****
  X  demo/fake_config.py:27  Private Key Block           ----****
  X  demo/fake_config.py:30  Generic Secret Assignment   Sup3****
  X  demo/fake_config.py:31  Generic Secret Assignment   my-s****
  X  demo/fake_config.py:34  JWT                         eyJh****
  X  demo/fake_config.py:37  High Entropy String         aB3k****

X  12 secrets found in 1 file.
```

The last line of `demo/fake_config.py` (which has `# leakguard:ignore`) is **not** reported, demonstrating inline suppression.

In a real terminal the `X` markers are bold red, file paths are yellow, secret types are cyan, and masked previews are dimmed. Output falls back to plain text when stdout is not a TTY (CI logs, pipes).

---

## Detection Coverage

| Secret Type | Pattern / Method |
|---|---|
| AWS Access Key ID | Regex: `AKIA[0-9A-Z]{16}` |
| AWS Secret Access Key | Regex: `aws` keyword + 40-char base64 string |
| GitHub Token | Regex: `ghp_`, `gho_`, `ghs_`, `ghu_`, `ghr_`, `github_pat_` prefixes |
| Google API Key | Regex: `AIza` prefix + 35 alphanumeric chars |
| OpenAI / Anthropic Key | Regex: `sk-` or `sk-ant-` prefix + long alphanumeric string |
| Slack Token | Regex: `xoxb-`, `xoxa-`, `xoxp-`, `xoxr-`, `xoxs-` prefixes |
| PEM Private Key | Regex: `-----BEGIN ... PRIVATE KEY-----` header |
| Generic assignments | Regex: case-insensitive `password`, `secret`, `api_key`, `token` followed by a value |
| JSON Web Token (JWT) | Regex: three dot-separated base64url segments starting with `ey` |
| Unknown / novel secrets | Shannon entropy ≥ 4.0 bits/char on tokens ≥ 20 chars (scoped to `.py .js .ts .env .yaml .yml .json .toml .cfg .ini .sh`) |
| Sensitive filenames | Filename match: `.env`, `.env.*`, `id_rsa`, `*.pem`, `credentials.json` |

---

## Limitations

- **False positives are possible.** Regex patterns may match test fixtures, example values, or documentation. The entropy check in particular can flag long random-looking strings that are not secrets (e.g. minified identifiers, UUIDs, base64-encoded content). Use `.leakguardignore` and `# leakguard:ignore` to manage them.
- **False negatives are possible.** LeakGuard only knows about the patterns it was built with. A novel secret format, an obfuscated key, or a secret split across multiple lines will not be caught.
- **Not a replacement for secret rotation.** If a secret was ever committed — even briefly, even in a branch — assume it is compromised and rotate it immediately. LeakGuard prevents *future* leaks; it cannot undo past ones.
- **Regex-only scanning of binary files is skipped.** Binary files are detected by null-byte probe and skipped entirely.
- **The hook only covers `git commit`.** Force-pushes, direct API pushes, and `git am` are not covered. For full protection, combine with a server-side secret scanning solution (e.g. GitHub's built-in secret scanning).

---

## How I Used IBM Bob

Bob built the entire tool in one session — scanner, CLI, hook installer, demo, and README — but the more interesting moment was a design decision it raised before writing a single line of code.

**The question:** should `.leakguardignore` be respected when files are passed as explicit CLI arguments?

Bob presented two options:

- **Option A** — Explicit file args bypass `.leakguardignore`. Running `python leakguard.py demo/fake_config.py` always scans the file, even if `demo/` is listed in the ignore file. The inline `# leakguard:ignore` marker still applies in all modes.
- **Option B** — `.leakguardignore` is always respected. The README would explain how to temporarily comment out the `demo/` entry to run the demo scan.

Option B is the "safer default" — consistent behaviour, no surprises. But Option A is the *right* UX: if you explicitly name a file on the command line, you clearly want it scanned. Suppressing it silently because of a broad ignore pattern would be confusing. Bob flagged this as a genuine design trade-off rather than just picking one, which was the right call.

<!-- Add your own notes about the session here. -->

---

## License

MIT — use freely, modify freely, no warranty.
