import re

SECRET_PATTERNS = {

    # 🔐 HIGH CONFIDENCE
    "Google API Key": re.compile(r'AIza[0-9A-Za-z-_]{35}'),
    "Firebase API Key": re.compile(r'AIza[0-9A-Za-z-_]{35}'),
    "Amazon AWS Access Key ID": re.compile(r'A[SK]IA[0-9A-Z]{16}'),
    "AWS Secret Key": re.compile(r"aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?", re.IGNORECASE),
    "Stripe API Key": re.compile(r'sk_(live|test)_[0-9a-zA-Z]{24}'),
    "Slack Token": re.compile(r'xox[baprs]-[0-9a-zA-Z]{10,48}'),
    "JWT": re.compile(r'ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),

    # 🔑 PRIVATE KEYS
    "RSA Private Key": re.compile(r'-----BEGIN RSA PRIVATE KEY-----'),
    "EC Private Key": re.compile(r'-----BEGIN EC PRIVATE KEY-----'),

    # ⚠ CONTEXTUAL (handled carefully)
    "Bearer Token": re.compile(
        r'Authorization:\s*Bearer\s+([A-Za-z0-9\-._~+/]+=*)',
        re.IGNORECASE
    ),

    # 🚫 GENERIC — DISABLED BY DEFAULT
    # Enable ONLY in research mode
    "Generic Assignment": re.compile(
        r'(?:api[_-]?key|secret|password)\s*[:=]\s*[\'"]([A-Za-z0-9_\-]{20,})[\'"]',
        re.IGNORECASE
    ),
}
