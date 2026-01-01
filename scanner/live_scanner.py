import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from scanner.secret_scanner import scan_text

def scan_website(url):
    findings = []

    try:
        resp = requests.get(url, timeout=10)
    except Exception:
        return findings

    soup = BeautifulSoup(resp.text, "html.parser")

    findings.extend(scan_text(resp.text, url))

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
