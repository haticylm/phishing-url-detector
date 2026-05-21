"""
Risk scoring logic for the Phishing URL Detection Tool.
"""

from features import extract_features


def get_risk_level(score):
    """Convert a numeric score into a human-readable risk level."""
    if score <= 2:
        return "Low Risk"
    if score <= 5:
        return "Medium Risk"
    return "High Risk"


def analyze_url(url):
    """
    Analyze a URL, calculate a phishing risk score, and explain the result.
    """
    features = extract_features(url)
    score = 0
    reasons = []

    if not features["uses_https"]:
        score += 2
        reasons.append("HTTPS is not used")

    if features["is_ip_address"]:
        score += 3
        reasons.append("IP address is used instead of a domain")

    if features["has_at_symbol"]:
        score += 3
        reasons.append("@ symbol is used in the URL")

    if features["url_length"] > 75:
        score += 2
        reasons.append("URL is unusually long")

    word_count = len(features["suspicious_words"])

    if word_count > 0:
        if word_count == 1:
            score += 2
        elif word_count == 2:
            score += 3
        else:
            score += 4

        found_words = ", ".join(features["suspicious_words"])
        reasons.append(f"Suspicious words found: {found_words}")

    if features["dot_count"] > 3:
        score += 1
        reasons.append("URL contains more than 3 dots")

    if features["has_hyphen_in_domain"]:
        score += 1
        reasons.append("Hyphen is used in the domain")

    if features["is_shortened_url"]:
        score += 2
        reasons.append("URL uses a known shortening service")

    if features["domain_length"] > 30:
        score += 1
        reasons.append("Domain is unusually long")

    risk_level = get_risk_level(score)

    return {
        "url": url,
        "score": score,
        "risk_level": risk_level,
        "features": features,
        "reasons": reasons,
    }