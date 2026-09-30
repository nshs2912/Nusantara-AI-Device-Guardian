from src.detection.android_detectors import run_android_detectors
from src.security.android_sample import sample_android_evidence

def test_android_detectors_cover_multiple_domains():
    findings = run_android_detectors(sample_android_evidence())
    domains = {item["domain"] for item in findings}
    assert "Spyware" in domains
    assert "Privacy" in domains
    assert "App Integrity" in domains
    assert "Network" in domains

def test_android_detector_is_non_destructive():
    evidence = sample_android_evidence()
    before = repr(evidence)
    run_android_detectors(evidence)
    assert repr(evidence) == before
