def run_detectors(evidence):
    findings = []
    for item in evidence.get("indicators", []):
        severity = item.get("severity", "LOW").upper()
        if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            findings.append({
                "id": item["id"], "title": item["title"], "severity": severity,
                "description": item["description"], "evidence": item["evidence"],
                "domain": item.get("domain", "General"), "weight": float(item.get("weight", 0)),
            })
    return findings
