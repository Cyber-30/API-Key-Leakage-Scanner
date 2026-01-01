from scanner.regex_patterns import SECRET_PATTERNS

def scan_file(file_path):
    findings = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_no, line in enumerate(f, start=1):
                for secret_type, pattern in SECRET_PATTERNS.items():
                    if pattern.search(line):
                        findings.append({
                            "file": file_path,
                            "line": line_no,
                            "type": secret_type,
                            "content": line.strip()
                        })
    except Exception:
        pass

    return findings
