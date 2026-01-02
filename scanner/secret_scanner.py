import re
import hashlib
from scanner.regex_patterns import SECRET_PATTERNS

SEVERITY_MAP = {
    "Google API Key": "HIGH",
    "Firebase API Key": "HIGH",
    "Amazon AWS Access Key ID": "CRITICAL",
    "JSON Web Token (JWT)": "MEDIUM",
    "Slack Token": "HIGH",
    "OAuth Token": "MEDIUM",
    "Generic Secret": "LOW"
}

# 🔥 Toggle behavior
SHOW_FULL_SECRET = True        # False → mask output
ENABLE_GENERIC_SECRET = False # Disable noisy rule by default


def mask_secret(value):
    if SHOW_FULL_SECRET:
        return value
    if len(value) <= 8:
        return "***"
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def is_false_positive(secret, secret_type):
    if secret_type == "Generic Secret":
        if not ENABLE_GENERIC_SECRET:
            return True
        if len(secret) < 20:
            return True
        if secret.lower() in {
            "users", "token", "header", "version",
            "enableeventlisteners", "disableeventlisteners"
        }:
            return True
    return False


def extract_secret(match):
    """
    Always extract the REAL secret value
    """
    if match.lastindex:
        return match.group(match.lastindex)
    return match.group(0)


def scan_text(content, source, global_seen):
    findings = []
    lines = content.splitlines()

    for line_no, line in enumerate(lines, start=1):
        for secret_type, pattern in SECRET_PATTERNS.items():

            for match in pattern.finditer(line):
                secret = extract_secret(match)

                if is_false_positive(secret, secret_type):
                    continue

                # 🔑 Deduplicate by source + secret (NOT line number)
                dedup_key = hashlib.sha256(
                    f"{source}|{secret}".encode()
                ).hexdigest()

                if dedup_key in global_seen:
                    continue

                global_seen.add(dedup_key)

                findings.append({
                    "source": source,
                    "line": line_no,
                    "type": secret_type,
                    "severity": SEVERITY_MAP.get(secret_type, "INFO"),
                    "secret": mask_secret(secret)
                })

    return findings
