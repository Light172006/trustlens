"""Unit tests for temporal integrity, reference-time evaluation, and absence of look-ahead bias."""

from datetime import datetime, timezone
from certificate_dataset.labeling.labeler import CertificateLabeler


def test_expiration_evaluated_at_past_reference_time(synthetic_fixtures):
    fixture_expired = next(f for f in synthetic_fixtures if f.get("fixture_type") == "EXPIRED")
    labeler = CertificateLabeler()

    # not_before is ~400 days ago, not_after is ~30 days ago.
    # Evaluated at reference_time = 200 days ago, the certificate WAS TIME_VALID and NOT EXPIRED!
    not_before_dt = datetime.fromisoformat(fixture_expired["validity"]["not_before"].replace("Z", "+00:00"))
    past_ref_time = datetime.fromtimestamp(not_before_dt.timestamp() + 50 * 86400, tz=timezone.utc)

    eval_past = labeler.evaluate(fixture_expired, reference_time=past_ref_time)
    assert eval_past["labels"]["TIME_VALID"] == "PASS"
    assert eval_past["labels"]["EXPIRED"] == "FAIL"

    # Evaluated at reference_time = now, the certificate IS EXPIRED!
    eval_now = labeler.evaluate(fixture_expired, reference_time=datetime.now(timezone.utc))
    assert eval_now["labels"]["TIME_VALID"] == "FAIL"
    assert eval_now["labels"]["EXPIRED"] == "PASS"


def test_not_yet_valid_evaluation(synthetic_fixtures):
    fixture_future = next(f for f in synthetic_fixtures if f.get("fixture_type") == "NOT_YET_VALID")
    labeler = CertificateLabeler()

    # Evaluated now, it is NOT_YET_VALID
    eval_now = labeler.evaluate(fixture_future, reference_time=datetime.now(timezone.utc))
    assert eval_now["labels"]["NOT_YET_VALID"] == "PASS"
    assert eval_now["labels"]["TIME_VALID"] == "FAIL"

