from src.detection.detectors import run_detectors
from src.security.sample_data import sample_device_evidence

def test_sample_detectors_return_findings():
    findings = run_detectors(sample_device_evidence())
    assert len(findings) == 2
    assert {f["domain"] for f in findings} == {"Network", "Persistence"}
