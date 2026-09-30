import re


def _items(value):
    if isinstance(value, dict):
        data = value.get("data", [])
        return data if isinstance(data, list) else [data] if isinstance(data, dict) else []
    return value if isinstance(value, list) else []


def _data(value):
    return value.get("data", {}) if isinstance(value, dict) else {}


def run_windows_detectors(evidence):
    findings = []
    security = evidence.get("security", {})

    defender = security.get("defender", {})
    defender_data = _data(defender)
    if (
        defender.get("available")
        and defender_data
        and not defender_data.get("RealTimeProtectionEnabled", True)
    ):
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
    disabled = [
        p.get("Name")
        for p in _items(firewall)
        if isinstance(p, dict) and p.get("Enabled") is False
    ]
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

    process_items = _items(evidence.get("processes"))
    encoded = [
        p for p in process_items
        if isinstance(p, dict) and p.get("HasEncodedPowerShell") is True
    ]
    if encoded:
        names = [str(p.get("Name", "PowerShell")) for p in encoded[:5]]
        findings.append({
            "id": "windows-encoded-powershell",
            "title": "Encoded PowerShell execution observed",
            "severity": "HIGH",
            "description": (
                "A process reported an encoded PowerShell execution pattern. "
                "The raw command line is intentionally not collected."
            ),
            "evidence": ", ".join(names),
            "domain": "Malware",
            "weight": 24,
        })

    secure_boot = _data(security.get("secure_boot", {}))
    if secure_boot.get("Supported") is True and secure_boot.get("Enabled") is False:
        findings.append({
            "id": "windows-secure-boot-disabled",
            "title": "Secure Boot is disabled",
            "severity": "MEDIUM",
            "description": "Windows reports that UEFI Secure Boot is supported but currently disabled.",
            "evidence": "Secure Boot: disabled",
            "domain": "Device Security",
            "weight": 12,
        })

    tpm = _data(security.get("tpm", {}))
    if tpm.get("TpmPresent") is False:
        findings.append({
            "id": "windows-tpm-unavailable",
            "title": "Trusted Platform Module unavailable",
            "severity": "LOW",
            "description": "Windows did not report an available TPM. This is a posture indicator, not proof of compromise.",
            "evidence": "TPM present: false",
            "domain": "Device Security",
            "weight": 6,
        })

    uac = _data(security.get("uac", {}))
    if uac.get("EnableLUA") == 0:
        findings.append({
            "id": "windows-uac-disabled",
            "title": "User Account Control is disabled",
            "severity": "MEDIUM",
            "description": "Windows reports that User Account Control is disabled.",
            "evidence": "EnableLUA: 0",
            "domain": "Device Security",
            "weight": 14,
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
