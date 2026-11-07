"""Tests for TrustLens Dataset Engineering, Processing, Splitting, and Storage Pipeline."""

from datetime import datetime, timezone
import io
from pathlib import Path
import tempfile
import zipfile
import pandas as pd
import pytest

from trustlens_intelligence.datasets.feature_pipeline import BatchFeaturePipeline
from trustlens_intelligence.datasets.pipeline import DatasetPipeline
from trustlens_intelligence.datasets.processing.allowlist import (
    ML_INTRINSIC_FEATURE_NAMES,
    THREAT_FEED_EXCLUDED_FEATURES,
    filter_allowlisted_features,
)
from trustlens_intelligence.datasets.processing.deduplicator import DatasetDeduplicator
from trustlens_intelligence.datasets.processing.label_validator import (
    LabelValidator,
    ValidatedSample,
)
from trustlens_intelligence.datasets.processing.normalizer import (
    URLNormalizer,
    extract_registrable_domain,
)
from trustlens_intelligence.datasets.sources.benign_deep import BenignDeepSource
from trustlens_intelligence.datasets.sources.malware_catalog import (
    MalwareCatalogSource,
    clean_adblock_url,
)
from trustlens_intelligence.datasets.sources.openphish import OpenPhishSource
from trustlens_intelligence.datasets.sources.phishtank import PhishTankSource
from trustlens_intelligence.datasets.sources.registry import (
    APPROVED_SOURCES,
    LabelCategory,
    RawRecord,
    SourceLicense,
    SourceRegistry,
)
from trustlens_intelligence.datasets.sources.tranco import TrancoSource
from trustlens_intelligence.datasets.sources.urlhaus import URLhausSource
from trustlens_intelligence.datasets.splits.domain_split import (
    DomainSplitter,
    verify_zero_domain_leakage,
)
from trustlens_intelligence.datasets.splits.temporal_split import TemporalSplitter
from trustlens_intelligence.datasets.storage.manifest import (
    DatasetManifest,
    create_manifest_from_dataframe,
)
from trustlens_intelligence.datasets.storage.parquet_store import ParquetStore


def test_source_registry_and_licensing():
    """Verify registry loads all approved sources and enforces licensing terms."""
    registry = SourceRegistry()
    sources = registry.list_sources()
    assert len(sources) >= 4

    source_ids = {s.source_id for s in sources}
    assert {"tranco", "openphish", "urlhaus", "phishtank"}.issubset(source_ids)

    # Tranco and URLhaus permit research and commercial use (CC BY 4.0)
    assert registry.validate_source_permitted("tranco", commercial=False) is True
    assert registry.validate_source_permitted("tranco", commercial=True) is True
    assert registry.validate_source_permitted("urlhaus", commercial=True) is True

    # OpenPhish community is research-only
    assert registry.validate_source_permitted("openphish", commercial=False) is True
    assert registry.validate_source_permitted("openphish", commercial=True) is False

    # PhishTank has proprietary research terms
    assert registry.validate_source_permitted("phishtank", commercial=False) is True
    assert registry.validate_source_permitted("phishtank", commercial=True) is False

    # Unknown source rejected
    assert registry.validate_source_permitted("unknown_malicious_feed") is False


def test_tranco_source_parsing_and_mock():
    """Test Tranco CSV parsing, ZIP handling, and mock generator."""
    tranco = TrancoSource()

    # 1. Parse CSV lines
    raw_lines = [
        "# Tranco Top Sites list\n",
        "1,google.com\n",
        "2,github.com\n",
        "\n",
        "3,sub.domain.co.uk\n",
    ]
    records = list(tranco.parse_lines(raw_lines))
    assert len(records) == 3
    assert records[0].url == "https://google.com/"
    assert records[0].metadata["rank"] == 1
    assert records[0].raw_label == LabelCategory.LEGITIMATE.value
    assert records[1].metadata["domain"] == "github.com"

    # 2. Parse in-memory ZIP bytes
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("top-1m.csv", "1,wikipedia.org\n2,python.org\n")
    zip_bytes = zip_buffer.getvalue()

    zip_records = list(tranco.parse_zip_bytes(zip_bytes))
    assert len(zip_records) == 2
    assert zip_records[0].url == "https://wikipedia.org/"

    # 3. Generate mock records
    mocks = tranco.generate_mock_records(count=25)
    assert len(mocks) == 25
    assert all(m.source_id == "tranco" for m in mocks)
    assert all(m.raw_label == "legitimate" for m in mocks)


def test_openphish_source_parsing_and_mock():
    """Test OpenPhish feed parsing and mock generation."""
    openphish = OpenPhishSource()
    raw_lines = [
        "# OpenPhish Community Feed\n",
        "http://paypal-security-update.com/login\n",
        "\n",
        "https://apple-id-verify.com/auth\n",
    ]
    records = list(openphish.parse_lines(raw_lines))
    assert len(records) == 2
    assert records[0].url == "http://paypal-security-update.com/login"
    assert records[0].raw_label == LabelCategory.PHISHING.value
    assert records[0].confidence == 0.95

    mocks = openphish.generate_mock_records(count=15)
    assert len(mocks) == 15
    assert all(m.source_id == "openphish" for m in mocks)


def test_urlhaus_source_parsing_and_mock():
    """Test URLhaus CSV parsing and threat tag extraction."""
    urlhaus = URLhausSource()
    raw_lines = [
        "# URLhaus CSV database\n",
        "id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n",
        '1001,"2026-01-03 10:00:00","http://89.248.163.78/bins/payload.elf","online","2026-01-03","malware_download","mirai,elf","https://urlhaus.abuse.ch/url/1001/","reporter1"\n',
        '1002,"2026-01-03 11:30:00","http://malware.org/drop.exe","offline","2026-01-03","malware_download","agenttesla","https://urlhaus.abuse.ch/url/1002/","reporter2"\n',
    ]
    records = list(urlhaus.parse_lines(raw_lines))
    assert len(records) == 2
    assert records[0].url == "http://89.248.163.78/bins/payload.elf"
    assert records[0].raw_label == LabelCategory.MALWARE.value
    assert records[0].metadata["threat"] == "malware_download"
    assert "mirai" in records[0].metadata["tags"]
    assert records[0].confidence == 1.0  # online

    mocks = urlhaus.generate_mock_records(count=12)
    assert len(mocks) == 12
    assert all(m.source_id == "urlhaus" for m in mocks)


def test_phishtank_source_parsing_and_mock():
    """Test PhishTank CSV parsing and verified filter."""
    phishtank = PhishTankSource()
    raw_lines = [
        "phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target\n",
        '901,"http://chase-login-verify.com/portal","http://phishtank.com/901","2026-01-04T12:00:00+00:00","yes","2026-01-04T12:05:00+00:00","yes","Chase"\n',
        '902,"http://unverified-sample.com/phish","http://phishtank.com/902","2026-01-04T13:00:00+00:00","no","","yes","Unknown"\n',
    ]
    # Filter only verified
    verified_only = list(phishtank.parse_lines(raw_lines, only_verified=True))
    assert len(verified_only) == 1
    assert verified_only[0].metadata["target"] == "Chase"

    # Allow unverified
    all_records = list(phishtank.parse_lines(raw_lines, only_verified=False))
    assert len(all_records) == 2

    mocks = phishtank.generate_mock_records(count=10)
    assert len(mocks) == 10
    assert all(m.source_id == "phishtank" for m in mocks)


def test_benign_deep_source_parsing_and_mock():
    """Test BenignDeepSource parsing and mock generation."""
    source = BenignDeepSource()
    raw_lines = [
        "https://en.wikipedia.org/wiki/Computer_security\n",
        "docs.python.org/3/library/urllib.parse.html\n",
    ]
    records = list(source.parse_lines(raw_lines))
    assert len(records) == 2
    assert records[0].raw_label == LabelCategory.LEGITIMATE.value
    assert records[0].url == "https://en.wikipedia.org/wiki/Computer_security"
    assert records[1].url.startswith("https://docs.python.org")

    mocks = source.generate_mock_records(count=15)
    assert len(mocks) == 15
    assert all(m.source_id == "benign_deep" for m in mocks)


def test_malware_catalog_source_parsing_and_adblock_clean():
    """Test MalwareCatalogSource parsing and clean_adblock_url logic."""
    assert clean_adblock_url("||codeload.github.com/user/repo/zip/master^$all") == "http://codeload.github.com/user/repo/zip/master"
    assert clean_adblock_url("||github.com^$all") is None  # bare root domain filtered
    assert clean_adblock_url("! comment line") is None

    source = MalwareCatalogSource()
    raw_lines = [
        "||bad-domain.ru/loader.exe^$all\n",
        "http://crypto-miner-distrib.su/xmrig.tar.gz\n",
    ]
    records = list(source.parse_lines(raw_lines))
    assert len(records) == 2
    assert records[0].raw_label == LabelCategory.MALWARE.value
    assert records[0].url == "http://bad-domain.ru/loader.exe"

    mocks = source.generate_mock_records(count=10)
    assert len(mocks) == 10
    assert all(m.source_id == "malware_research" for m in mocks)


def test_url_normalizer_rfc3986_compliance():
    """Verify strict URL canonicalization, Punycode encoding, and domain extraction."""
    normalizer = URLNormalizer()

    # 1. Scheme, host lowercase, default port stripped
    n1 = normalizer.normalize("HTTP://EXAMPLE.COM:80/path/test?b=2&a=1#frag")
    assert n1.scheme == "http"
    assert n1.host == "example.com"
    assert n1.port is None  # port 80 stripped for http
    assert n1.canonical_url == "http://example.com/path/test?a=1&b=2"
    assert n1.registrable_domain == "example.com"

    # 2. Non-standard port retained
    n2 = normalizer.normalize("https://secure.bank.com:8443/login")
    assert n2.port == 8443
    assert n2.canonical_url == "https://secure.bank.com:8443/login"

    # 3. Path normalization (collapse duplicate slashes and resolve dot segments)
    n3 = normalizer.normalize("http://example.org/dir1//dir2/../dir3/./index.html")
    assert n3.canonical_url == "http://example.org/dir1/dir3/index.html"

    # 4. Userinfo isolation
    n4 = normalizer.normalize("http://admin:secret@192.168.1.1/dashboard")
    assert n4.has_userinfo is True
    assert n4.userinfo == "admin:secret"

    # 5. Two-part TLD registrable domain extraction
    assert extract_registrable_domain("portal.secure.bbc.co.uk") == "bbc.co.uk"
    assert extract_registrable_domain("sub.bank.com.au") == "bank.com.au"
    assert extract_registrable_domain("sub.example.com") == "example.com"
    assert extract_registrable_domain("192.168.1.1") == "192.168.1.1"


def test_dataset_deduplicator():
    """Verify exact URL, canonical hash deduplication, and domain frequency caps."""
    normalizer = URLNormalizer()
    dedup = DatasetDeduplicator(normalizer=normalizer, max_samples_per_domain=2)

    now = datetime.now(timezone.utc)
    records = [
        RawRecord(url="http://example.com/test", source_id="source1", raw_label="legitimate", timestamp=now),
        # Exact duplicate
        RawRecord(url="http://example.com/test", source_id="source2", raw_label="legitimate", timestamp=now),
        # Canonical duplicate (different case, default port)
        RawRecord(url="HTTP://EXAMPLE.COM:80/test", source_id="source3", raw_label="legitimate", timestamp=now),
        # Distinct URL same domain (sample 2 for example.com)
        RawRecord(url="http://example.com/other", source_id="source1", raw_label="legitimate", timestamp=now),
        # Sample 3 for example.com (must be dropped by max_samples_per_domain=2)
        RawRecord(url="http://example.com/third", source_id="source1", raw_label="legitimate", timestamp=now),
        # Distinct domain
        RawRecord(url="http://different-domain.org/path", source_id="source1", raw_label="legitimate", timestamp=now),
    ]

    retained = dedup.deduplicate_list(records)
    assert len(retained) == 3
    assert dedup.stats.total_processed == 6
    assert dedup.stats.exact_duplicates_dropped == 1
    assert dedup.stats.canonical_duplicates_dropped == 1
    assert dedup.stats.domain_cap_dropped == 1
    assert dedup.stats.total_retained == 3


def test_label_validator_and_conflict_resolution():
    """Verify label taxonomy mapping and cross-source conflict resolution."""
    validator = LabelValidator()

    assert validator.normalize_label("legitimate") == LabelCategory.LEGITIMATE
    assert validator.normalize_label("clean") == LabelCategory.LEGITIMATE
    assert validator.normalize_label("malware_download") == LabelCategory.MALWARE
    assert validator.normalize_label("phish") == LabelCategory.PHISHING

    assert validator.to_binary_label(LabelCategory.LEGITIMATE) == 0
    assert validator.to_binary_label(LabelCategory.PHISHING) == 1
    assert validator.to_binary_label(LabelCategory.MALWARE) == 1

    # Conflict: Tranco lists domain as legitimate, OpenPhish reports active phishing URL
    now = datetime.now(timezone.utc)
    conflicting = [
        RawRecord(
            url="http://compromised-site.com/login",
            source_id="tranco",
            raw_label="legitimate",
            confidence=0.8,
            timestamp=now,
            metadata={"registrable_domain": "compromised-site.com"},
        ),
        RawRecord(
            url="http://compromised-site.com/login",
            source_id="openphish",
            raw_label="phishing",
            confidence=0.95,
            timestamp=now,
            metadata={"registrable_domain": "compromised-site.com"},
        ),
    ]
    resolved = validator.resolve_conflicts(conflicting)
    # High-confidence verified threat takes precedence over generic ranking
    assert resolved.label_category == LabelCategory.PHISHING
    assert resolved.binary_label == 1
    assert resolved.source_id == "openphish"
    assert "tranco" in resolved.metadata["conflict_sources"]


def test_ml_feature_allowlist():
    """ML Feature Allowlist must retain intrinsic features and exclude threat feed match flags."""
    raw_feature_dict = {
        "url_length": 55,
        "is_ip_host": True,
        "is_https": False,
        "url_entropy": 4.5,
        "has_homoglyphs": False,
        "openphish_match": 1.0,  # Target leakage!
        "urlhaus_match": 1.0,  # Target leakage!
        "urlhaus_online": 1.0,  # Target leakage!
        "community_confirmed_reports": 5.0,  # External signal!
    }

    filtered = filter_allowlisted_features(raw_feature_dict)
    assert len(filtered) == len(ML_INTRINSIC_FEATURE_NAMES)

    # Intrinsic features preserved
    assert filtered["url_length"] == 55
    assert filtered["is_ip_host"] == 1.0
    assert filtered["url_entropy"] == 4.5

    # Leaked threat feed flags excluded
    for excluded in THREAT_FEED_EXCLUDED_FEATURES:
        assert excluded not in filtered


def test_parquet_store_read_write_and_batches():
    """Verify ParquetStore table writing, appending, reading, and batch iteration."""
    store = ParquetStore()

    df = pd.DataFrame({
        "url": ["https://example.com/1", "https://example.com/2"],
        "registrable_domain": ["example.com", "example.com"],
        "binary_label": [0, 0],
        "url_length": [21, 21],
    })

    with tempfile.TemporaryDirectory() as tmp_dir:
        p_path = Path(tmp_dir) / "test.parquet"

        # Write
        store.write_table(df, p_path)
        assert p_path.exists()

        # Read
        loaded_df = store.read_dataframe(p_path)
        assert len(loaded_df) == 2
        assert list(loaded_df["binary_label"]) == [0, 0]

        # Append
        df2 = pd.DataFrame({
            "url": ["https://malware.org/payload"],
            "registrable_domain": ["malware.org"],
            "binary_label": [1],
            "url_length": [26],
        })
        store.append_chunk(df2, p_path)
        combined_df = store.read_dataframe(p_path)
        assert len(combined_df) == 3

        # Stream batches
        batches = list(store.iter_batches(p_path, batch_size=2))
        assert len(batches) == 2
        assert len(batches[0]) == 2
        assert len(batches[1]) == 1


def test_domain_aware_split_guarantees_zero_leakage():
    """DomainSplitter must partition dataset so that train, val, and test domains are disjoint."""
    splitter = DomainSplitter()

    rows = []
    # 10 distinct domains, 5 samples each = 50 records
    for d_idx in range(10):
        domain = f"domain{d_idx}.com"
        for s_idx in range(5):
            rows.append({
                "url": f"https://{domain}/path/{s_idx}",
                "registrable_domain": domain,
                "binary_label": d_idx % 2,
                "url_length": 25,
            })
    df = pd.DataFrame(rows)

    result = splitter.split(df, train_ratio=0.7, val_ratio=0.15, test_ratio=0.15, seed=42)

    # Invariant: zero domain overlap
    assert verify_zero_domain_leakage(result) is True
    assert len(set(result.train_domains).intersection(set(result.val_domains))) == 0
    assert len(set(result.train_domains).intersection(set(result.test_domains))) == 0
    assert len(set(result.val_domains).intersection(set(result.test_domains))) == 0

    assert len(result.train_df) > 0
    assert len(result.val_df) > 0
    assert len(result.test_df) > 0
    assert len(result.train_df) + len(result.val_df) + len(result.test_df) == len(df)

    # Edge case: split ratios not summing to 1.0
    with pytest.raises(ValueError, match="Split ratios must sum"):
        splitter.split(df, train_ratio=0.5, val_ratio=0.1, test_ratio=0.1)

    # Edge case: missing domain column
    with pytest.raises(KeyError):
        splitter.split(pd.DataFrame({"url": [1]}), 0.7, 0.15, 0.15)

    # Edge case: fewer than 3 domains
    small_df = pd.DataFrame({
        "url": ["https://d1.com/", "https://d2.com/"],
        "registrable_domain": ["d1.com", "d2.com"],
        "binary_label": [0, 1],
    })
    small_res = splitter.split(small_df, train_ratio=0.5, val_ratio=0.25, test_ratio=0.25)
    assert len(small_res.train_df) >= 1


def test_temporal_split():
    """TemporalSplitter must partition records chronologically without lookahead bias."""
    splitter = TemporalSplitter()

    timestamps = [
        "2026-01-01T10:00:00+00:00",
        "2026-01-02T10:00:00+00:00",
        "2026-01-03T10:00:00+00:00",
        "2026-01-04T10:00:00+00:00",
        "2026-01-05T10:00:00+00:00",
    ]
    df = pd.DataFrame({
        "url": [f"http://example.com/{i}" for i in range(5)],
        "registrable_domain": ["example.com"] * 5,
        "timestamp": timestamps,
        "binary_label": [0, 0, 1, 1, 1],
    })

    val_cut = datetime(2026, 1, 3, 0, 0, tzinfo=timezone.utc)
    test_cut = datetime(2026, 1, 4, 12, 0, tzinfo=timezone.utc)

    result = splitter.split_by_cutoffs(df, val_cutoff=val_cut, test_cutoff=test_cut)
    assert len(result.train_df) == 2  # Jan 1, Jan 2
    assert len(result.val_df) == 2  # Jan 3, Jan 4 morning
    assert len(result.test_df) == 1  # Jan 5

    # Test quantile split
    q_result = splitter.split_by_quantiles(df, train_quantile=0.6, val_quantile=0.8)
    assert len(q_result.train_df) == 3
    assert len(q_result.val_df) == 1
    assert len(q_result.test_df) == 1
    assert q_result.metadata["split_type"] == "temporal_quantile"

    # Missing timestamp column raises KeyError
    with pytest.raises(KeyError):
        splitter.split_by_cutoffs(pd.DataFrame({"url": ["a"]}), val_cut, test_cut)
    with pytest.raises(KeyError):
        splitter.split_by_quantiles(pd.DataFrame({"url": ["a"]}))


def test_batch_feature_pipeline_and_evidence_generation():
    """Verify ValidatedSample -> ScanEvidence -> allowlisted feature extraction."""
    pipeline = BatchFeaturePipeline()
    sample = ValidatedSample(
        url="http://192.168.1.1:8080/admin/login?pwd=test",
        canonical_url="http://192.168.1.1:8080/admin/login?pwd=test",
        registrable_domain="192.168.1.1",
        label_category=LabelCategory.PHISHING,
        binary_label=1,
        confidence=0.95,
        source_id="test_source",
        timestamp=datetime.now(timezone.utc),
        metadata={"domain_age_days": 10},
    )

    row = pipeline.extract_row(sample)
    assert row["url"] == sample.url
    assert row["binary_label"] == 1
    assert row["is_ip_host"] == 1.0
    assert row["has_non_standard_port"] == 1.0
    assert row["domain_age_days"] == 10.0
    # Leaked features must NOT be in extracted row
    assert "openphish_match" not in row
    assert "urlhaus_match" not in row

    df = pipeline.extract_dataframe([sample])
    assert len(df) == 1
    assert "url_entropy" in df.columns
    assert "is_ip_host" in df.columns


def test_dataset_pipeline_end_to_end_orchestration():
    """Test full DatasetPipeline orchestration from mock generation to Parquet and manifest."""
    pipeline = DatasetPipeline()

    # Generate 10 mock records per source = 40 records
    raw_records = pipeline.generate_benchmark_records(samples_per_source=10)
    assert len(raw_records) == 40

    with tempfile.TemporaryDirectory() as tmp_dir:
        res = pipeline.run_pipeline(
            raw_records=raw_records,
            output_dir=tmp_dir,
            dataset_name="trustlens-ci-test",
            version="2.0.0",
            train_ratio=0.7,
            val_ratio=0.15,
            test_ratio=0.15,
            seed=42,
        )

        assert res.manifest.total_samples > 0
        assert res.manifest.unique_domains > 0
        assert res.file_paths["full_dataset"].exists()
        assert res.file_paths["train"].exists()
        assert res.file_paths["val"].exists()
        assert res.file_paths["test"].exists()
        assert res.file_paths["manifest"].exists()

        # Validate manifest content
        manifest = DatasetManifest.load(res.file_paths["manifest"])
        assert manifest.dataset_name == "trustlens-ci-test"
        assert len(manifest.source_attributions) == 4
        assert "full_dataset" in manifest.files
        assert len(manifest.files["full_dataset"]["sha256"]) == 64
