import hashlib

from scanner.regex_patterns import SECRET_PATTERNS
from core.analyzer import analyze
from filters.vendor_filter import is_vendor


SEVERITY_MAP = {
    "Google API Key": "HIGH",
    "Firebase API Key": "HIGH",
    "Amazon AWS Access Key ID": "CRITICAL",
    "AWS Secret Key": "CRITICAL",
    "OAuth Token": "MEDIUM",
    "Slack Token": "HIGH",
    "Stripe API Key": "CRITICAL",
    "Twilio API Key": "HIGH",
    "Generic Secret": "LOW",
}

SHOW_FULL_SECRET = True
ENABLE_GENERIC_SECRET = False


def mask_secret(secret):
    if SHOW_FULL_SECRET:
        return secret
    if len(secret) <= 8:
        return "***"
    return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]


def extract_secret(match):
    """
    Extract the real secret:
    - Prefer named group
    - Else last capture group
    - Else full match
    """
    if match.groupdict():
        return next(v for v in match.groupdict().values() if v)

    if match.lastindex:
        return match.group(match.lastindex)

    return match.group(0)


def is_false_positive(secret, secret_type):
    if secret_type == "Generic Secret":
        if not ENABLE_GENERIC_SECRET:
            return True
        if len(secret) < 20:
            return True
        if secret.lower() in {
            "password",
            "token",
            "secret",
            "apikey",
            "accesskey",
            "users",
            "version",
            "config"
        }:
            return True

    return False


def scan_text(content, source, global_seen):
    """
    Main scanning function.
    - Uses analyzer pipeline for JWTs
    - Uses regex for other API keys
    """
    findings = []

    # 🔹 1. Skip vendor files early
    if is_vendor(source):
        return findings

    # 🔹 2. JWT detection via analyzer (NOT regex)
    analyzer_findings = analyze(content, source)

    for finding in analyzer_findings:
        dedup_key = hashlib.sha256(
            f"{source}|{finding['type']}|{finding['masked_secret']}".encode()
        ).hexdigest()

        if dedup_key in global_seen:
            continue

        global_seen.add(dedup_key)

        findings.append({
            "source": source,
            "line": finding.get("line", "-"),
            "type": finding["type"],
            "severity": finding["severity"],
            "confidence": finding["confidence"],
            "secret": finding["masked_secret"],
        })

    # 🔹 3. Non-JWT secrets (regex-based)
    lines = content.splitlines()

    for line_no, line in enumerate(lines, start=1):

        if not line.strip():
            continue

        for secret_type, pattern in SECRET_PATTERNS.items():

            # ❌ JWTs are handled ONLY by analyzer
            if "JWT" in secret_type:
                continue

            for match in pattern.finditer(line):

                raw_match = match.group(0)
                secret = extract_secret(match)

                # 🚨 Hard validations
                if secret not in raw_match:
                    continue

                if secret not in line:
                    continue

                if is_false_positive(secret, secret_type):
                    continue

                dedup_key = hashlib.sha256(
                    f"{source}|{secret_type}|{secret}".encode()
                ).hexdigest()

                if dedup_key in global_seen:
                    continue

                global_seen.add(dedup_key)

                findings.append({
                    "source": source,
                    "line": line_no,
                    "type": secret_type,
                    "severity": SEVERITY_MAP.get(secret_type, "INFO"),
                    "confidence": None,
                    "secret": mask_secret(secret),
                })

    return findings
