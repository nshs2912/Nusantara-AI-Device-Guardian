def sample_device_evidence():
    return {
        "device": {"platform": "Sample Device", "agent": "safe-simulator-v0.1"},
        "indicators": [
            {"id": "sample-network", "title": "Unusual outbound connection pattern",
             "severity": "MEDIUM", "domain": "Network", "weight": 18,
             "description": "A simulated telemetry record contains a connection pattern outside the device baseline.",
             "evidence": "simulated connection burst to an unclassified destination"},
            {"id": "sample-persistence", "title": "Unknown startup entry",
             "severity": "LOW", "domain": "Persistence", "weight": 8,
             "description": "A simulated startup item has not yet been classified.",
             "evidence": "simulated startup entry: unknown-service"},
        ],
    }
