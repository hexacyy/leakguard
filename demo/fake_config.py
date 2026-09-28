# demo/fake_config.py
# ============================================================
# THIS FILE CONTAINS DELIBERATELY FAKE SECRETS FOR TESTING.
# Do NOT use any of these values in real code or infrastructure.
# ============================================================

# --- AWS ---
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"          # fake - do not use
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # fake

# --- GitHub token ---
GITHUB_TOKEN = "ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"  # fake

# --- Google API key ---
GOOGLE_API_KEY = "AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY"  # fake

# --- OpenAI key ---
OPENAI_API_KEY = "sk-proj-XXXX-DEMO-NOTAREAL-OPENAI-KEY-REPLACE-ME"  # fake

# --- Anthropic key ---
ANTHROPIC_API_KEY = "sk-ant-api03-XXXX-DEMO-NOTAREAL-KEY-REPLACE-ME"  # fake

# --- Slack token ---
SLACK_BOT_TOKEN = "xoxb-XXXX-DEMO-NOTAREAL-TOKEN-REPLACE-ME"  # fake

# --- Private key block ---
PRIVATE_KEY_HEADER = "-----BEGIN RSA PRIVATE KEY-----"  # fake

# --- Generic secret assignment ---
password = "Sup3rS3cr3tPassw0rd!"  # fake
api_key = "my-super-secret-api-key-value-here"  # fake

# --- JWT (fake, non-decodable) ---
JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkZha2VVc2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"  # fake

# --- High-entropy string (looks like a random token) ---
RANDOM_TOKEN = "aB3kQ9zXpL7mN2vRtY5wCeHfGjKsDqUo"  # fake - high entropy

# --- This line is intentionally suppressed with an inline ignore comment ---
IGNORED_SECRET = "sk-this-line-should-not-be-flagged-at-all"  # leakguard:ignore
