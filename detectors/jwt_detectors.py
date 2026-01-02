JWT_REGEX = r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'

def find_jwts(text):
    import re
    return re.findall(JWT_REGEX, text)
