import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from scanner.secret_scanner import scan_text

REQUEST_DELAY = 1.0

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Accept": "text/html,application/javascript",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "close"
}

def same_domain(url, base_domain):
    parsed = urlparse(url)
    return parsed.netloc == base_domain or parsed.netloc == f"www.{base_domain}"

def safe_get(url):
    time.sleep(REQUEST_DELAY)
    return requests.get(
        url,
        headers=HEADERS,
        timeout=10,
        allow_redirects=True
    )

def scan_website(start_url, max_pages=10, delay=1.0):
    visited = set()
    to_visit = [start_url]
    findings = []

    parsed_base = urlparse(start_url)
    base_domain = parsed_base.netloc.replace("www.", "")

    while to_visit and len(visited) < max_pages:
        current_url = to_visit.pop(0)

        if current_url in visited:
            continue

        visited.add(current_url)

        try:
            resp = safe_get(current_url)
        except Exception:
            continue

        findings.extend(scan_text(resp.text, current_url))

        soup = BeautifulSoup(resp.text, "html.parser")

        # 🔹 Same-domain JS only
        for script in soup.find_all("script"):
            src = script.get("src")
            if not src:
                continue

            js_url = urljoin(current_url, src)

            if not same_domain(js_url, base_domain):
                continue

            try:
                js_resp = safe_get(js_url)
                if js_resp.status_code == 200:
                    findings.extend(scan_text(js_resp.text, js_url))
            except Exception:
                pass

        # 🔹 Same-domain page links
        for link in soup.find_all("a", href=True):
            href = link.get("href")
            full_url = urljoin(current_url, href)

            if same_domain(full_url, base_domain):
                if full_url not in visited:
                    to_visit.append(full_url)

    return findings
