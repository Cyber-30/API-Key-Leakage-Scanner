VENDOR_KEYWORDS = ['vendor', 'bootstrap', 'jquery', 'min.js']

def is_vendor(url):
    return any(v in url.lower() for v in VENDOR_KEYWORDS)
