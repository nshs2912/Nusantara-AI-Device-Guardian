from src.detection.windows_detectors import run_windows_detectors
from src.security.windows_sample import sample_windows_evidence
from src.security.windows_schema import validate_windows_telemetry

def test_windows_sample_is_valid_and_detected():
    evidence = sample_windows_evidence()
    assert validate_windows_telemetry(evidence) is True
    findings = run_windows_detectors(evidence)
    domains = {item["domain"] for item in findings}
    assert {"Malware", "Persistence", "Network"}.issubset(domains)

def test_windows_detector_does_not_mutate_evidence():
    evidence = sample_windows_evidence()
    before = repr(evidence)
    run_windows_detectors(evidence)
    assert repr(evidence) == before
