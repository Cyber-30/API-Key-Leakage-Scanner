from detectors.jwt_detector import find_jwts
from validators.jwt_validator import is_valid_jwt
from scoring.entropy import entropy
from scoring.context import context_score
from filters.vendor_filter import is_vendor


# Confidence thresholds
MIN_CONFIDENCE = 6
HIGH_CONFIDENCE = 8


def analyze(text, url):
    """
    Analyze content and detect high-confidence JWTs.
    Uses:
    - Strict regex
    - Structural validation
    - Entropy scoring
    - Context scoring
    - Vendor filtering
    """
    findings = []

    # Vendor files are noisy; skip early
    if is_vendor(url):
        return findings

    for token in find_jwts(text):
        score = 0
        reasons = []

        # 1️⃣ Regex match
        score += 2
        reasons.append("JWT regex match")

        # 2️⃣ Structural validation
        if is_valid_jwt(token):
            score += 4
            reasons.append("Valid JWT structure")
        else:
            continue

        # 3️⃣ Entropy check
        token_entropy = entropy(token)
        if token_entropy > 3.5:
            score += 2
            reasons.append("High entropy")
        else:
            reasons.append("Low entropy")

        # 4️⃣ Context scoring
        ctx_score = context_score(text)
        score += ctx_score
        if ctx_score > 0:
            reasons.append("Auth-related keywords nearby")
        elif ctx_score < 0:
            reasons.append("Likely non-secret context")

        # 5️⃣ Vendor penalty (extra safety)
        if is_vendor(url):
            score -= 4
            reasons.append("Vendor JS penalty")

        # 6️⃣ Final decision
        if score < MIN_CONFIDENCE:
            continue

        findings.append({
            "type": "JWT",
            "severity": "HIGH" if score >= HIGH_CONFIDENCE else "MEDIUM",
            "confidence": score,
            "masked_secret": token[:6] + "..." + token[-4:],
            "reason": reasons,
        })

    return findings
