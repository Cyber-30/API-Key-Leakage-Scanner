import re

SECRET_PATTERNS = {
    "Google API Key": re.compile(r'AIza[0-9A-Za-z-_]{35}'),
    "Firebase API Key": re.compile(r'AIza[0-9A-Za-z-_]{35}'),
    "Amazon AWS Access Key ID": re.compile(r'AKIA[0-9A-Z]{16}'),

    # JWT
    "JSON Web Token (JWT)": re.compile(
        r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
    ),

    # OAuth tokens in URLs
    "OAuth Token": re.compile(
        r'[?&]oauth_token=([A-Za-z0-9_-]{20,100})'
    )
}
