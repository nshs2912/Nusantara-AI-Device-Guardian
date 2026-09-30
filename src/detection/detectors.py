import re

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SUSPICIOUS_PATTERNS = {
    "Malware": [
        (r"powershell.*-enc", "Encoded PowerShell execution", "HIGH", 24),
        (r"\b(base64|payload|dropper|trojan|ransom)\b", "Malware-related keyword", "HIGH", 22),
    ],
    "Persistence": [
        (r"startup|autorun|scheduled task|run key|launch agent", "Persistence indicator", "MEDIUM", 16),
    ],
    "Network": [
        (r"beacon|periodic outbound|unclassified destination|suspicious dns", "Suspicious network pattern", "MEDIUM", 15),
    ],
    "Spyware": [
        (r"keylog|screen capture|credential theft|microphone.*background|camera.*background", "Spyware/privacy indicator", "HIGH", 25),
    ],
    "Phishing": [
        (r"credential.*link|urgent.*login|password.*verify|account.*suspend", "Phishing language indicator", "MEDIUM", 14),
    ],
}

def _pattern_findings(text):
    results = []
    normalized = text.lower()
    for domain, patterns in SUSPICIOUS_PATTERNS.items():
        for pattern, title, severity, weight in patterns:
            if re.search(pattern, normalized):
                results.append({
                    "id": f"pattern-{domain.lower()}-{len(results)}",
                    "title": title,
                    "severity": severity,
                    "description": "A heuristic pattern matched supplied telemetry. This is an indicator, not proof of compromise.",
                    "evidence": text[:500],
                    "domain": domain,
                    "weight": weight,
                })
    return results

def run_detectors(evidence):
    findings = []
    for item in evidence.get("indicators", []):
        severity = str(item.get("severity", "LOW")).upper()
        if severity in SEVERITY_ORDER:
            findings.append({
                "id": str(item["id"]),
                "title": str(item["title"]),
                "severity": severity,
                "description": str(item["description"]),
                "evidence": str(item["evidence"])[:500],
                "domain": str(item.get("domain", "General")),
                "weight": max(0.0, float(item.get("weight", 0))),
            })
    for event in evidence.get("events", []):
        if isinstance(event, dict):
            text = " ".join(str(v) for v in event.values())
            findings.extend(_pattern_findings(text))
    return _deduplicate(findings)

def _deduplicate(findings):
    seen = set()
    result = []
    for finding in findings:
        key = (finding["title"], finding["domain"])
        if key not in seen:
            seen.add(key)
            result.append(finding)
    return result
