"""TrustLens Intelligence — Dataset Preparation Pipeline for ML Classification.

Provides domain-aware dataset splitting, balanced sample generators, and reproducible feature extraction.
Prevents data leakage by ensuring that domains present in the training set never appear in the test set.
"""

from dataclasses import dataclass
import random
from typing import Any
from urllib.parse import urlparse
import numpy as np
import pandas as pd

from trustlens_intelligence.features.extractor import FeatureExtractor
from trustlens_intelligence.schemas.evidence import (
    CookieEvidence,
    DomainIntelligenceEvidence,
    HttpEvidence,
    ScanEvidence,
    ThreatIntelEvidence,
    TlsCertificateEvidence,
)

# Representative seed URLs across classes for dataset generation and benchmarking
SEED_LEGITIMATE_DATA: list[dict[str, Any]] = [
    {
        "url": "https://www.google.com/search?q=trustlens+security",
        "domain": "google.com",
        "domain_age": 9800,
        "is_https": True,
        "hsts": True,
        "csp": True,
        "valid_cert": True,
        "label": 0,  # Benign
    },
    {
        "url": "https://en.wikipedia.org/wiki/Computer_security",
        "domain": "wikipedia.org",
        "domain_age": 8500,
        "is_https": True,
        "hsts": True,
        "csp": True,
        "valid_cert": True,
        "label": 0,
    },
    {
        "url": "https://github.com/torvalds/linux/commits/master",
        "domain": "github.com",
        "domain_age": 6000,
        "is_https": True,
        "hsts": True,
        "csp": True,
        "valid_cert": True,
        "label": 0,
    },
    {
        "url": "https://docs.python.org/3/library/urllib.parse.html",
        "domain": "python.org",
        "domain_age": 10500,
        "is_https": True,
        "hsts": True,
        "csp": True,
        "valid_cert": True,
        "label": 0,
    },
    {
        "url": "https://stackoverflow.com/questions/tagged/python",
        "domain": "stackoverflow.com",
        "domain_age": 5900,
        "is_https": True,
        "hsts": True,
        "csp": True,
        "valid_cert": True,
        "label": 0,
    },
    {
        "url": "https://aws.amazon.com/security/introduction/",
        "domain": "amazon.com",
        "domain_age": 10800,
        "is_https": True,
        "hsts": True,
        "csp": True,
        "valid_cert": True,
        "label": 0,
    },
    {
        "url": "https://www.apple.com/privacy/",
        "domain": "apple.com",
        "domain_age": 11500,
        "is_https": True,
        "hsts": True,
        "csp": True,
        "valid_cert": True,
        "label": 0,
    },
    {
        "url": "https://www.bbc.com/news/technology",
        "domain": "bbc.com",
        "domain_age": 9200,
        "is_https": True,
        "hsts": True,
        "csp": False,
        "valid_cert": True,
        "label": 0,
    },
]

SEED_PHISHING_DATA: list[dict[str, Any]] = [
    {
        "url": "http://paypal-verification-account-secure.com/login?token=847392",
        "domain": "paypal-verification-account-secure.com",
        "domain_age": 3,
        "is_https": False,
        "hsts": False,
        "csp": False,
        "valid_cert": None,
        "label": 1,  # Malicious
    },
    {
        "url": "http://192.168.10.45/bankofamerica/signin.php?session=update",
        "domain": "192.168.10.45",
        "domain_age": None,
        "is_https": False,
        "hsts": False,
        "csp": False,
        "valid_cert": None,
        "label": 1,
    },
    {
        "url": "https://secure-login-apple-id.xn--e1aybc.com/verify-identity",
        "domain": "secure-login-apple-id.xn--e1aybc.com",
        "domain_age": 12,
        "is_https": True,
        "hsts": False,
        "csp": False,
        "valid_cert": False,
        "label": 1,
    },
    {
        "url": "http://wellsfargo-online-banking-security.net/kyc/customer",
        "domain": "wellsfargo-online-banking-security.net",
        "domain_age": 5,
        "is_https": False,
        "hsts": False,
        "csp": False,
        "valid_cert": None,
        "label": 1,
    },
    {
        "url": "http://update-chase-account-validation.xyz/login.html",
        "domain": "update-chase-account-validation.xyz",
        "domain_age": 8,
        "is_https": False,
        "hsts": False,
        "csp": False,
        "valid_cert": None,
        "label": 1,
    },
    {
        "url": "http://microsoft-office365-password-reset.info/auth/login",
        "domain": "microsoft-office365-password-reset.info",
        "domain_age": 15,
        "is_https": False,
        "hsts": False,
        "csp": False,
        "valid_cert": None,
        "label": 1,
    },
]

SEED_MALWARE_DATA: list[dict[str, Any]] = [
    {
        "url": "http://89.248.163.78/bins/arm7.payload",
        "domain": "89.248.163.78",
        "domain_age": None,
        "is_https": False,
        "hsts": False,
        "csp": False,
        "valid_cert": None,
        "label": 1,
    },
    {
        "url": "http://malware-drop-site.biz/downloads/invoice_pdf.exe",
        "domain": "malware-drop-site.biz",
        "domain_age": 10,
        "is_https": False,
        "hsts": False,
        "csp": False,
        "valid_cert": None,
        "label": 1,
    },
    {
        "url": "http://fast-dropper-payloads.ru/dll/updater.scr",
        "domain": "fast-dropper-payloads.ru",
        "domain_age": 2,
        "is_https": False,
        "hsts": False,
        "csp": False,
        "valid_cert": None,
        "label": 1,
    },
    {
        "url": "http://185.220.101.5/loader.sh",
        "domain": "185.220.101.5",
        "domain_age": None,
        "is_https": False,
        "hsts": False,
        "csp": False,
        "valid_cert": None,
        "label": 1,
    },
]

SEED_SUSPICIOUS_DATA: list[dict[str, Any]] = [
    {
        "url": "http://temporary-marketing-campaign.club/click?ref=social",
        "domain": "temporary-marketing-campaign.club",
        "domain_age": 25,
        "is_https": False,
        "hsts": False,
        "csp": False,
        "valid_cert": None,
        "label": 1,
    },
    {
        "url": "https://unverified-ecommerce-store.shop/checkout/billing",
        "domain": "unverified-ecommerce-store.shop",
        "domain_age": 45,
        "is_https": True,
        "hsts": False,
        "csp": False,
        "valid_cert": True,
        "label": 0,
    },
    {
        "url": "http://free-crypto-giveaway-airdrop.top/claim",
        "domain": "free-crypto-giveaway-airdrop.top",
        "domain_age": 4,
        "is_https": False,
        "hsts": False,
        "csp": False,
        "valid_cert": None,
        "label": 1,
    },
]


@dataclass
class DatasetSplits:
    """Train and test splits along with feature names."""

    X_train: pd.DataFrame
    y_train: pd.Series
    X_test: pd.DataFrame
    y_test: pd.Series
    feature_names: list[str]
    train_domains: list[str]
    test_domains: list[str]


def seed_record_to_evidence(record: dict[str, Any]) -> ScanEvidence:
    """Convert seed record to normalized ScanEvidence."""
    url = record["url"]
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    host = parsed.netloc.split(":")[0]

    http_ev = HttpEvidence(
        status_code=200,
        final_url=url,
        security_headers={
            "strict-transport-security": "max-age=31536000" if record.get("hsts") else None,
            "content-security-policy": "default-src 'self'" if record.get("csp") else None,
            "x-content-type-options": "nosniff" if record.get("hsts") else None,
        },
        cookies=[
            CookieEvidence(name="session", secure=bool(record.get("is_https")), httponly=True, samesite="Lax")
        ]
        if record.get("is_https")
        else [],
    )

    tls_ev = None
    if scheme == "https":
        tls_valid = record.get("valid_cert")
        tls_ev = TlsCertificateEvidence(
            valid=tls_valid,
            chain_valid=tls_valid,
            hostname_match=tls_valid,
            days_until_expiry=90 if tls_valid else -5,
            is_expired=(not tls_valid and tls_valid is not None),
            protocol_version="TLSv1.3",
            issuer="Let's Encrypt Authority",
        )

    domain_ev = None
    if record.get("domain_age") is not None:
        domain_ev = DomainIntelligenceEvidence(domain_age_days=record["domain_age"])

    is_malicious = record.get("label") == 1
    threat_ev = ThreatIntelEvidence(
        openphish_match=is_malicious and "paypal" in url,
        openphish_status="match" if (is_malicious and "paypal" in url) else "no_match",
        urlhaus_match=is_malicious and "malware" in url,
        urlhaus_status="match" if (is_malicious and "malware" in url) else "no_match",
        urlhaus_url_status="online" if (is_malicious and "malware" in url) else None,
    )

    return ScanEvidence(
        scan_id=f"sample_{random.randint(1000, 9999)}",
        original_url=url,
        canonical_url=url,
        host=host,
        scheme=scheme,
        http=http_ev,
        tls=tls_ev,
        domain_intelligence=domain_ev,
        threat_intelligence=threat_ev,
    )


def generate_benchmark_dataset(
    sample_multiplier: int = 10,
    seed: int = 42,
) -> tuple[pd.DataFrame, pd.Series, list[str]]:
    """Generate a reproducible benchmark dataset using feature extraction on seed URLs.

    Args:
        sample_multiplier: Multiplier to generate realistic variants with slight perturbations.
        seed: Random seed for reproducibility.

    Returns:
        X (DataFrame), y (Series), domains (list[str])
    """
    random.seed(seed)
    np.random.seed(seed)

    all_seeds = (
        SEED_LEGITIMATE_DATA
        + SEED_PHISHING_DATA
        + SEED_MALWARE_DATA
        + SEED_SUSPICIOUS_DATA
    )

    extractor = FeatureExtractor()
    rows: list[dict[str, Any]] = []
    labels: list[int] = []
    domains: list[str] = []

    for seed_item in all_seeds:
        base_ev = seed_record_to_evidence(seed_item)
        features = extractor.extract(base_ev)
        feature_dict = features.to_ml_dict()

        rows.append(feature_dict)
        labels.append(seed_item["label"])
        domains.append(seed_item["domain"])

        # Create slight realistic variations (e.g. paths, query parameters)
        for i in range(1, sample_multiplier):
            mutated = dict(seed_item)
            sep = "&" if "?" in mutated["url"] else "?"
            mutated["url"] = f"{mutated['url']}{sep}v={i}"
            ev = seed_record_to_evidence(mutated)
            f_dict = extractor.extract(ev).to_ml_dict()

            rows.append(f_dict)
            labels.append(mutated["label"])
            domains.append(mutated["domain"])

    df_X = pd.DataFrame(rows)
    df_y = pd.Series(labels, name="label")

    return df_X, df_y, domains


def create_domain_aware_splits(
    df_X: pd.DataFrame,
    df_y: pd.Series,
    domains: list[str],
    test_size: float = 0.25,
    seed: int = 42,
) -> DatasetSplits:
    """Split dataset ensuring that no domain appears in both train and test sets.

    This prevents data leakage where a model simply memorizes a specific domain name.
    """
    random.seed(seed)
    unique_domains = list(set(domains))
    random.shuffle(unique_domains)

    split_idx = int(len(unique_domains) * (1.0 - test_size))
    train_domains = set(unique_domains[:split_idx])
    test_domains = set(unique_domains[split_idx:])

    train_mask = [d in train_domains for d in domains]
    test_mask = [d in test_domains for d in domains]

    X_train = df_X[train_mask].reset_index(drop=True)
    y_train = df_y[train_mask].reset_index(drop=True)
    X_test = df_X[test_mask].reset_index(drop=True)
    y_test = df_y[test_mask].reset_index(drop=True)

    train_domain_list = [d for d, m in zip(domains, train_mask) if m]
    test_domain_list = [d for d, m in zip(domains, test_mask) if m]

    return DatasetSplits(
        X_train=X_train,
        y_train=y_train,
        X_test=X_test,
        y_test=y_test,
        feature_names=list(df_X.columns),
        train_domains=train_domain_list,
        test_domains=test_domain_list,
    )
