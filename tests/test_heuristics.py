from src.detection.detectors import run_detectors

def test_heuristic_detectors():
    evidence = {
        "device": {},
        "indicators": [],
        "events": [{"command": "powershell -enc suspicious_payload", "network": "periodic outbound beacon"}],
    }
    findings = run_detectors(evidence)
    assert any(f["domain"] == "Malware" for f in findings)
    assert any(f["domain"] == "Network" for f in findings)
