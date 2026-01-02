import base64, json

def is_valid_jwt(token):
    try:
        h, p, s = token.split('.')

        def b64(x):
            return base64.urlsafe_b64decode(x + '=' * (-len(x) % 4))

        json.loads(b64(h))
        json.loads(b64(p))
        return True
    except:
        return False
