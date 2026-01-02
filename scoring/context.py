POSITIVE = ['token', 'apikey', 'authorization', 'secret', 'bearer']
NEGATIVE = ['dropdown', 'dismiss', 'event', 'keydown', 'keyup']

def context_score(text):
    score = 0
    for p in POSITIVE:
        if p in text.lower(): score += 2
    for n in NEGATIVE:
        if n in text.lower(): score -= 2
    return score
