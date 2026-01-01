import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlunparse
from scanner.secret_scanner import scan_text

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Accept": "text/html,application/javascript",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "close"
}


def normalize_url(url):
    """Normalize URL: keep scheme, netloc, path, query; remove fragment"""
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", parsed.query, ""))


def same_domain(url, base_domain):
    """Check if url belongs to the same domain (ignores subdomains)"""
    parsed = urlparse(url)
    return parsed.netloc.replace("www.", "") == base_domain


def safe_get(url, delay=1.0):
    """Fetch URL with delay"""
    time.sleep(delay)
    return requests.get(
        url,
        headers=HEADERS,
        timeout=10,
        allow_redirects=True
    )


def scan_website(start_url, max_pages=10, delay=1.0):
    visited_pages = set()
    visited_js = set()
    to_visit = [normalize_url(start_url)]
    findings = []

    base_domain = urlparse(start_url).netloc.replace("www.", "")

    while to_visit and len(visited_pages) < max_pages:
        current_url = normalize_url(to_visit.pop(0))

        if current_url in visited_pages:
            continue
        visited_pages.add(current_url)

        try:
            resp = safe_get(current_url, delay)
        except Exception as e:
            print(f"[DEBUG] Page fetch error: {e}")
            continue

        # 🔹 Scan HTML itself
        findings.extend(scan_text(resp.text, current_url))

        soup = BeautifulSoup(resp.text, "html.parser")

        # 🔹 Fetch and scan JS files
        for script in soup.find_all("script", src=True):
            js_url = normalize_url(urljoin(current_url, script["src"]))

            # Skip already scanned JS
            if js_url in visited_js:
                continue
            visited_js.add(js_url)

            # Only same-domain JS
            if not same_domain(js_url, base_domain):
                continue

            # Only .js files
            if not js_url.endswith(".js"):
                continue

            try:
                js_resp = safe_get(js_url, delay)
                if js_resp.status_code == 200 and js_resp.text:
                    findings.extend(scan_text(js_resp.text, js_url))
            except Exception as e:
                print(f"[DEBUG] JS fetch error: {e}")

        # 🔹 Crawl same-domain links
        for link in soup.find_all("a", href=True):
            next_url = normalize_url(urljoin(current_url, link["href"]))
            if same_domain(next_url, base_domain) and next_url not in visited_pages:
                to_visit.append(next_url)

    return findings
