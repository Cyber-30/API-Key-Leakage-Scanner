from scanner.regex_patterns import SECRET_PATTERNS

SEVERITY_MAP = {
    "AWS_ACCESS_KEY": "CRITICAL",
    "AWS_SECRET_KEY": "CRITICAL",
    "GOOGLE_API_KEY": "INFO",
    "JWT_TOKEN": "HIGH",
    "GENERIC_API_KEY": "MEDIUM",
    "BEARER_TOKEN": "HIGH"
}

def mask_secret(value):
    if len(value) <= 8:
        return "***"
    return value[:4] + "*" * (len(value) - 8) + value[-4:]

def scan_text(content, source):
    findings = []

    for line_no, line in enumerate(content.splitlines(), start=1):

        # 🔹 Skip huge minified lines (noise reduction)
        if len(line) > 2000:
            continue

        for secret_type, pattern in SECRET_PATTERNS.items():
            match = pattern.search(line)
            if match:
                secret = match.group(0)

                findings.append({
                    "source": source,
                    "line": line_no,
                    "type": secret_type,
                    "severity": SEVERITY_MAP.get(secret_type, "LOW"),
                    "secret": mask_secret(secret),
                })

    return findings
