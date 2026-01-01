from scanner.regex_patterns import SECRET_PATTERNS

SEVERITY_MAP = {
    "AWS_ACCESS_KEY": "CRITICAL",
    "GOOGLE_API_KEY": "HIGH",
    "FIREBASE_API_KEY": "HIGH",
    "JWT_TOKEN": "HIGH",
    "SLACK_TOKEN": "CRITICAL",
    "GENERIC_SECRET": "MEDIUM",
}

def mask_secret(value):
    if len(value) <= 8:
        return "***"
    return value[:4] + "*" * (len(value) - 8) + value[-4:]

def scan_text(content, source):
    findings = []
    seen = set()  # Deduplication
    lines = content.splitlines()

    for line_no, line in enumerate(lines, start=1):
        for secret_type, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(line):
                raw_secret = match.group(0)
                severity = SEVERITY_MAP.get(secret_type, "INFO")

                key = (source, secret_type, raw_secret)
                if key in seen:
                    continue
                seen.add(key)

                print(f"[!] {severity} FINDING: Detected {secret_type} in {source}")

                findings.append({
                    "source": source,
                    "line": line_no,
                    "type": secret_type,
                    "severity": severity,
                    "secret": mask_secret(raw_secret),
                })

    return findings
