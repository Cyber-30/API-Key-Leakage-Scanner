import re
import hashlib
from scanner.regex_patterns import SECRET_PATTERNS

SEVERITY_MAP = {
    "Google API Key": "HIGH",
    "Firebase API Key": "HIGH",
    "Amazon AWS Access Key ID": "CRITICAL",
    "JSON Web Token (JWT)": "MEDIUM",
    "Slack Token": "HIGH",
    "Generic Secret": "LOW"
}

# Toggle this
SHOW_FULL_SECRET = True  # 🔥 set False for masking

def mask_secret(value):
    if SHOW_FULL_SECRET:
        return value
    if len(value) <= 8:
        return "***"
    return value[:4] + "*" * (len(value) - 8) + value[-4:]

def is_false_positive(secret, secret_type):
    # Filter obvious junk
    if secret_type == "Generic Secret":
        if len(secret) < 20:
            return True
        if secret.lower() in ["users", "token", "header", "version"]:
            return True
    return False

def scan_text(content, source, global_seen):
    findings = []
    lines = content.splitlines()

    for line_no, line in enumerate(lines, start=1):
        for secret_type, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(line):
                secret = match.group(0)

                if is_false_positive(secret, secret_type):
                    continue

                # Global deduplication key
                unique_key = hashlib.sha256(
                    f"{source}|{line_no}|{secret}".encode()
                ).hexdigest()

                if unique_key in global_seen:
                    continue

                global_seen.add(unique_key)

                findings.append({
                    "source": source,
                    "line": line_no,
                    "type": secret_type,
                    "severity": SEVERITY_MAP.get(secret_type, "INFO"),
                    "secret": mask_secret(secret)
                })

    return findings
