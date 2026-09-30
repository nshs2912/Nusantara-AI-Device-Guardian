ANDROID_RULES = (
    ("Spyware", "Accessibility service enabled on unknown-source app", "HIGH", 28,
     lambda a: a.get("source") == "Unknown source" and a.get("accessibility_enabled") is True),
    ("Privacy", "Sensitive permissions on unknown-source app", "HIGH", 24,
     lambda a: a.get("source") == "Unknown source" and any(a.get(k) for k in ("camera", "microphone", "location"))),
    ("App Integrity", "App installed from unknown source", "MEDIUM", 16,
     lambda a: a.get("source") == "Unknown source"),
)

def run_android_detectors(telemetry):
    findings = []
    for app in telemetry.get("apps", []):
        for domain, title, severity, weight, predicate in ANDROID_RULES:
            if predicate(app):
                findings.append({
                    "id": f"android-{domain.lower().replace(' ', '-')}-{app['package']}",
                    "title": title,
                    "severity": severity,
                    "description": "Android telemetry matched a defensive heuristic. Verify the app and user intent before taking action.",
                    "evidence": f"{app.get('label', app['package'])} ({app['package']}); source={app.get('source')}",
                    "domain": domain,
                    "weight": weight,
                })
    for item in telemetry.get("network", []):
        if item.get("periodic") and item.get("dns_suspicious"):
            findings.append({
                "id": "android-network-suspicious-periodic-dns",
                "title": "Suspicious periodic network activity",
                "severity": "MEDIUM",
                "description": "A periodic connection coincides with a suspicious DNS indicator.",
                "evidence": str(item),
                "domain": "Network",
                "weight": 18,
            })
    device = telemetry.get("device", {})
    if device.get("root_detected") or device.get("bootloader_unlocked"):
        findings.append({
            "id": "android-device-tampering",
            "title": "Device integrity configuration requires review",
            "severity": "HIGH",
            "description": "Root or an unlocked bootloader was reported by telemetry.",
            "evidence": f"root_detected={device.get('root_detected')}; bootloader_unlocked={device.get('bootloader_unlocked')}",
            "domain": "Root/Tampering",
            "weight": 22,
        })
    return _deduplicate(findings)

def _deduplicate(findings):
    seen = set()
    result = []
    for finding in findings:
        key = (finding["id"], finding["domain"])
        if key not in seen:
            seen.add(key)
            result.append(finding)
    return result
