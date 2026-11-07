"""TrustLens Intelligence — Lexical Feature Extraction.

Extracts text-level, statistical, and information-theoretic features from URLs.
"""

from collections import Counter
import math
import re
from urllib.parse import urlparse

from trustlens_intelligence.common.url_utils import extract_safe_hostname

# Keywords frequently weaponized in phishing, credential-harvesting, and scam URLs
SUSPICIOUS_KEYWORDS = frozenset(
    [
        "account",
        "banking",
        "billing",
        "confirm",
        "credential",
        "customer",
        "ebayisapi",
        "identity",
        "invoice",
        "kyc",
        "login",
        "logon",
        "notice",
        "oauth",
        "password",
        "payment",
        "paypal",
        "recover",
        "security",
        "session",
        "signin",
        "sign-in",
        "support",
        "update",
        "upgrade",
        "validation",
        "verify",
        "wallet",
        "webscr",
    ]
)

# File extensions frequently associated with malware payloads, droppers, and trojans
EXECUTABLE_EXTENSIONS = frozenset(
    [
        ".exe", ".bin", ".zip", ".rar", ".7z", ".tar", ".gz", ".apk", ".dll",
        ".iso", ".msi", ".bat", ".cmd", ".sh", ".vbs", ".ps1", ".scr", ".elf",
        ".dmg", ".vhd", ".jar", ".dat", ".sys", ".drv", ".class",
    ]
)

# Keywords frequently associated with malware staging, dropper delivery, and C2 gates
MALWARE_KEYWORDS = frozenset(
    [
        "download", "downloads", "descargas", "payload", "bin", "drops", "c2",
        "gate", "install", "installer", "setup", "updater", "raw", "bot",
        "rat", "miner", "stage", "stager", "beacon", "inject", "exec",
    ]
)


def calculate_shannon_entropy(text: str) -> float:
    """Calculate the Shannon entropy of a string in bits per character.

    Returns:
        Entropy float value >= 0.0. Higher values indicate higher randomness.
    """
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def count_suspicious_keywords(text: str) -> int:
    """Count occurrences of known credential-harvesting and deceptive keywords."""
    if not text:
        return 0
    lower_text = text.lower()
    count = 0
    # Match tokens delimited by common URL separators
    tokens = re.split(r"[\W_]+", lower_text)
    for token in tokens:
        if token in SUSPICIOUS_KEYWORDS:
            count += 1
    return count


def extract_lexical_features(url: str) -> dict[str, int | float | bool]:
    """Extract lexical features from a given URL string.

    Args:
        url: URL string to inspect.

    Returns:
        Dictionary of computed lexical metrics.
    """
    if not url:
        return {
            "url_length": 0,
            "host_length": 0,
            "path_length": 0,
            "query_length": 0,
            "url_entropy": 0.0,
            "host_entropy": 0.0,
            "digit_count": 0,
            "special_char_count": 0,
            "suspicious_keyword_count": 0,
            "has_executable_extension": False,
            "malware_keyword_count": 0,
        }

    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        path = parsed.path or ""
        query = parsed.query or ""
    except Exception:
        path = ""
        query = ""

    host = extract_safe_hostname(url)

    # Special characters common in obfuscated or adversarial URLs
    special_chars = set("@-_%?=&/.~+")
    special_count = sum(1 for c in url if c in special_chars)
    digit_count = sum(1 for c in url if c.isdigit())

    # Calculate entropy
    url_entropy = calculate_shannon_entropy(url)
    host_entropy = calculate_shannon_entropy(host)

    # Keywords in host, path, and query
    keywords = count_suspicious_keywords(f"{host} {path} {query}")

    # Malware delivery indicators
    path_lower = path.lower()
    has_exec_ext = any(path_lower.endswith(ext) for ext in EXECUTABLE_EXTENSIONS)
    tokens = re.split(r"[\W_]+", f"{path_lower} {query.lower()}")
    malware_kws = sum(1 for t in tokens if t in MALWARE_KEYWORDS)

    return {
        "url_length": len(url),
        "host_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "url_entropy": url_entropy,
        "host_entropy": host_entropy,
        "digit_count": digit_count,
        "special_char_count": special_count,
        "suspicious_keyword_count": keywords,
        "has_executable_extension": has_exec_ext,
        "malware_keyword_count": malware_kws,
    }

