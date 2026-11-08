"""Unit tests for dataset diversity profiling and quality analysis."""

from certificate_dataset.quality.diversity import DiversityProfiler


def test_diversity_profiler(synthetic_fixtures):
    profile = DiversityProfiler.profile(synthetic_fixtures)
    assert profile["total_records"] == len(synthetic_fixtures)
    assert profile["unique_certificates"] == len(synthetic_fixtures)
    assert profile["duplicate_fingerprints_count"] == 0
    assert "RSA" in profile["public_key_algorithm_distribution"]
    assert "ECDSA" in profile["public_key_algorithm_distribution"]
    assert profile["anomalies_detected_count"] > 0  # Fixtures intentionally include anomalies

