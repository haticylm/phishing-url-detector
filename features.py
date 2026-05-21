"""
Feature extraction functions for the Phishing URL Detection Tool.

The project is intentionally rule-based and beginner-friendly. Each function
checks one simple property of the URL, and extract_features() combines them.
"""

import re
from urllib.parse import urlparse


SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "account",
    "update",
    "secure",
    "bank",
    "paypal",
    "password",
    "signin",
    "confirm",
    "webscr",
]

SHORTENER_DOMAINS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "buff.ly",
    "ow.ly",
]


def add_scheme_if_missing(url):
    """
    urlparse works best when the URL has a scheme like http:// or https://.
    If the user enters example.com, this helper treats it as http://example.com.
    """
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        return "http://" + url
    return url


def get_domain(url):
    """Return the domain/host part of a URL without a leading www."""
    parsed_url = urlparse(add_scheme_if_missing(url))
    domain = parsed_url.hostname or ""
    domain = domain.lower()

    if domain.startswith("www."):
        domain = domain[4:]

    return domain


def uses_https(url):
    """Check whether the URL uses HTTPS."""
    parsed_url = urlparse(add_scheme_if_missing(url))
    return parsed_url.scheme.lower() == "https"


def has_at_symbol(url):
    """Check whether the URL contains the @ symbol."""
    return "@" in url


def has_hyphen_in_domain(url):
    """Check whether the domain contains a hyphen."""
    return "-" in get_domain(url)


def is_ip_address(domain):
    """
    Check whether the domain is an IPv4 address.

    This simple pattern is enough for this beginner project. It checks the
    common format: four groups of numbers separated by dots.
    """
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    return re.match(ip_pattern, domain) is not None


def count_dots(url):
    """Count the number of dots in the full URL."""
    return url.count(".")


def find_suspicious_words(url):
    """Return suspicious words that appear anywhere in the URL."""
    lower_url = url.lower()
    found_words = []

    for word in SUSPICIOUS_WORDS:
        if word in lower_url:
            found_words.append(word)

    return found_words


def is_shortened_url(domain):
    """Check whether the domain belongs to a known URL shortening service."""
    return domain in SHORTENER_DOMAINS


def extract_features(url):
    """
    Extract URL-based features and return them as a dictionary.
    """
    domain = get_domain(url)
    suspicious_words = find_suspicious_words(url)

    features = {
        "url_length": len(url),
        "uses_https": uses_https(url),
        "has_at_symbol": has_at_symbol(url),
        "has_hyphen_in_domain": has_hyphen_in_domain(url),
        "is_ip_address": is_ip_address(domain),
        "domain_length": len(domain),
        "dot_count": count_dots(url),
        "suspicious_words": suspicious_words,
        "is_shortened_url": is_shortened_url(domain),
    }

    return features
