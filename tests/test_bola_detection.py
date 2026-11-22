from scanner.authz_intel.config import ScannerConfig
from scanner.authz_intel.detectors.bola_delete import DeleteBOLADetector
from scanner.authz_intel.verification.confidence_engine import read_confidence
from scanner.authz_intel.verification.response_comparator import compare_object_response
from scanner.authz_intel.verification.state_verifier import state_changed, write_verified


def test_response_match_requires_resource_identity_and_marker():
    baseline = {
        "id": 1001,
        "owner": "alice",
        "tenant": "tenant-a",
        "content": "ALICE_PRIVATE_DOCUMENT_MARKER_1001",
    }
    observed = dict(baseline)

    comparison = compare_object_response(baseline, observed)
    level, confidence = read_confidence(comparison)
    assert level == "CONFIRMED"
    assert confidence >= 0.95

    observed.pop("content")
    comparison = compare_object_response(baseline, observed)
    assert comparison["same_marked_content"] is False


def test_200_without_object_identity_is_inconclusive():
    comparison = compare_object_response(
        {"id": 1001, "owner": "alice", "tenant": "tenant-a", "content": "private"},
        {"detail": "Request was processed"},
    )
    level, _ = read_confidence(comparison)
    assert level == "INCONCLUSIVE"


def test_write_confirmation_requires_persisted_marker():
    original = {"id": 1001, "title": "Alice", "content": "original"}
    changed = {"id": 1001, "title": "Alice", "content": "BOB_WRITE_MARKER"}

    assert state_changed(original, changed) is True
    assert write_verified(original, changed, "BOB_WRITE_MARKER") is True
    assert write_verified(original, original, "BOB_WRITE_MARKER") is False


def test_destructive_testing_is_disabled_by_default():
    config = ScannerConfig(
        base_url="http://127.0.0.1:8000",
        openapi_url=None,
        allowed_hosts=frozenset({"127.0.0.1"}),
        timeout=10.0,
        principals=(),
        allow_write_tests=False,
        allow_destructive_tests=False,
    )
    assert DeleteBOLADetector().run(config) == []
