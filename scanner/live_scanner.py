import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from scanner.secret_scanner import scan_text

HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Accept": "text/html,application/javascript"
}

def normalize_url(url):
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}{p.path}"

def same_domain(url, base):
    return urlparse(url).netloc.replace("www.", "") == base

def safe_get(url, delay):
    time.sleep(delay)
    return requests.get(url, headers=HEADERS, timeout=10)

def scan_website(start_url, max_pages=10, delay=1.0):
    visited = set()
    queue = [normalize_url(start_url)]
    findings = []
    global_seen = set()

    base_domain = urlparse(start_url).netloc.replace("www.", "")

    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            r = safe_get(url, delay)
        except:
            continue

        findings += scan_text(r.text, url, global_seen)

        soup = BeautifulSoup(r.text, "html.parser")

        # JS files
        for s in soup.find_all("script", src=True):
            js_url = normalize_url(urljoin(url, s["src"]))
            if not same_domain(js_url, base_domain):
                continue

            try:
                js = safe_get(js_url, delay)
                findings += scan_text(js.text, js_url, global_seen)
            except:
                pass

        # Crawl links
        for a in soup.find_all("a", href=True):
            nxt = normalize_url(urljoin(url, a["href"]))
            if same_domain(nxt, base_domain) and nxt not in visited:
                queue.append(nxt)

    return findings
