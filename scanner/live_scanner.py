import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from scanner.secret_scanner import scan_text

def scan_website(start_url, max_pages=10):
    visited = set()
    to_visit = [start_url]
    findings = []

    base_domain = urlparse(start_url).netloc

    while to_visit and len(visited) < max_pages:
        current_url = to_visit.pop(0)

        if current_url in visited:
            continue

        visited.add(current_url)

        try:
            resp = requests.get(current_url, timeout=10)
        except Exception:
            continue

        findings.extend(scan_text(resp.text, current_url))

        soup = BeautifulSoup(resp.text, "html.parser")

        # 🔹 Extract JS files
        for script in soup.find_all("script"):
            src = script.get("src")
            if not src:
                continue

            js_url = urljoin(current_url, src)

            try:
                js_resp = requests.get(js_url, timeout=10)
                if js_resp.status_code == 200:
                    findings.extend(scan_text(js_resp.text, js_url))
            except Exception:
                pass

        # 🔹 Extract internal links
        for link in soup.find_all("a", href=True):
            href = link.get("href")
            full_url = urljoin(current_url, href)
            parsed = urlparse(full_url)

            if parsed.netloc == base_domain:
                if full_url not in visited:
                    to_visit.append(full_url)

    return findings
