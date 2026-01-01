import re

SECRET_PATTERNS = {
    "AWS_ACCESS_KEY": re.compile(r'AKIA[0-9A-Z]{16}'),
    "AWS_SECRET_KEY": re.compile(r'(?i)aws(.{0,20})?(secret|access)?.{0,20}?["\'][0-9a-zA-Z\/+=]{40}["\']'),
    "GOOGLE_API_KEY": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    "JWT_TOKEN": re.compile(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
    "GENERIC_API_KEY": re.compile(r'(?i)(api_key|apikey|token|secret)["\']?\s*[:=]\s*["\'][A-Za-z0-9\-_=]{16,}["\']'),
    "BEARER_TOKEN": re.compile(r'Bearer\s+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+')
}