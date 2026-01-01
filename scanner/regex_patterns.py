import re

SECRET_PATTERNS = {
    "GOOGLE_API_KEY": re.compile(r'AIza[0-9A-Za-z-_]{35}'),
    "FIREBASE_API_KEY": re.compile(r'AIza[0-9A-Za-z-_]{35}'),
    "AWS_ACCESS_KEY": re.compile(r'AKIA[0-9A-Z]{16}'),
    "JWT_TOKEN": re.compile(r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'),
    "SLACK_TOKEN": re.compile(r'xox[baprs]-[0-9a-zA-Z]{10,48}'),
    "GENERIC_SECRET": re.compile(
        r'(?i)(key|api|secret|token|auth)["\s]*[:=]["\s]*["\']?([0-9a-zA-Z-_]{16,64})["\']?'
    )
}
