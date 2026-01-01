import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from scanner.regex_patterns import SECRET_PATTERNS

def scan_text(content, source):
    findings = []

    for line_no, line in enumerate(content.splitlines(), start=1):
        for secret_type, pattern in SECRET_PATTERNS.items():
            if pattern.search(line):
                findings.append({
                    "source": source,
                    "line": line_no,
                    "type": secret_type,
                    "content": line.strip()
                })

    return findings


def scan_website(url):
    findings = []

    try:
        resp = requests.get(url, timeout=10)
    except Exception:
        return findings

    soup = BeautifulSoup(resp.text, "html.parser")

    # 🔹 Scan inline JS + HTML
    findings.extend(scan_text(resp.text, url))

    # 🔹 Scan linked JS files
    for script in soup.find_all("script"):
        src = script.get("src")
        if not src:
            continue

        js_url = urljoin(url, src)

        try:
            js_resp = requests.get(js_url, timeout=10)
            if js_resp.status_code == 200:
                findings.extend(scan_text(js_resp.text, js_url))
        except Exception:
            pass

    return findings
