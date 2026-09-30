import re

def _items(value):
    if isinstance(value, dict):
        data = value.get("data", [])
        return data if isinstance(data, list) else [data] if isinstance(data, dict) else []
    return value if isinstance(value, list) else []

def run_windows_detectors(evidence):
    findings = []
    security = evidence.get("security", {})
    defender = security.get("defender", {})
    defender_data = defender.get("data", {}) if isinstance(defender, dict) else {}
    if defender.get("available") and defender_data and not defender_data.get("RealTimeProtectionEnabled", True):
        findings.append({
            "id": "windows-defender-disabled",
            "title": "Microsoft Defender real-time protection disabled",
            "severity": "HIGH",
            "description": "Windows reports that real-time antivirus protection is disabled.",
            "evidence": str(defender_data)[:500],
            "domain": "Device Security",
            "weight": 30,
        })
    firewall = security.get("firewall", {})
    disabled = [p.get("Name") for p in _items(firewall)
                if isinstance(p, dict) and p.get("Enabled") is False]
    if disabled:
        findings.append({
            "id": "windows-firewall-profile-disabled",
            "title": "Windows Firewall profile disabled",
            "severity": "MEDIUM",
            "description": "One or more Windows Firewall profiles report disabled status.",
            "evidence": ", ".join(str(x) for x in disabled),
            "domain": "Network",
            "weight": 18,
        })
    process_text = " ".join(
        str(p.get("CommandLine", "")) for p in _items(evidence.get("processes"))
        if isinstance(p, dict)
    )
    if re.search(r"powershell(?:\.exe)?[^\n]*-enc(?:odedcommand)?\b", process_text, re.I):
        findings.append({
            "id": "windows-encoded-powershell",
            "title": "Encoded PowerShell execution observed",
            "severity": "HIGH",
            "description": "A process command line contains an encoded PowerShell execution pattern.",
            "evidence": process_text[:500],
            "domain": "Malware",
            "weight": 24,
        })
    startup = _items(evidence.get("startup"))
    if startup:
        findings.append({
            "id": "windows-startup-entry",
            "title": "Automatic startup entry observed",
            "severity": "LOW",
            "description": "Windows exposes one or more automatic startup entries for review.",
            "evidence": str(startup[:5])[:500],
            "domain": "Persistence",
            "weight": 8,
        })
    return findings
