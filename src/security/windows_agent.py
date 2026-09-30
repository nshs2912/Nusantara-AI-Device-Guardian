import json
import os
import platform
import shutil
import subprocess
from datetime import datetime, timezone

POWERSHELL = shutil.which("powershell") or shutil.which("pwsh")

def _run_powershell_json(script, timeout=12):
    if os.name != "nt" or not POWERSHELL:
        return {"available": False, "error": "Windows PowerShell is unavailable on this host."}
    try:
        completed = subprocess.run(
            [POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-Command", script],
            capture_output=True, text=True, timeout=timeout, check=False, shell=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"available": False, "error": str(exc)}
    if completed.returncode != 0:
        return {"available": False, "error": completed.stderr.strip()[:500] or "PowerShell command failed."}
    raw = completed.stdout.strip()
    if not raw:
        return {"available": True, "data": None}
    try:
        return {"available": True, "data": json.loads(raw)}
    except json.JSONDecodeError:
        return {"available": True, "data": raw[:1000]}

def collect_windows_telemetry():
    """Collect minimized, read-only Windows security telemetry."""
    if os.name != "nt":
        raise RuntimeError("Windows read-only collection is only available on Windows.")
    ps = {
        "system": r"$o=Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,LastBootUpTime; $o | ConvertTo-Json -Compress",
        "defender": r"$o=Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntispywareEnabled,AntivirusSignatureVersion,AntivirusSignatureLastUpdated; $o | ConvertTo-Json -Compress",
        "firewall": r"$o=Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction; @($o) | ConvertTo-Json -Compress",
        "processes": r"$o=Get-CimInstance Win32_Process | Select-Object Name,ProcessId,ExecutablePath,CommandLine; @($o) | ConvertTo-Json -Compress",
        "services": r"$o=Get-CimInstance Win32_Service | Where-Object {$_.StartMode -eq 'Auto'} | Select-Object Name,State,StartMode,PathName; @($o) | ConvertTo-Json -Compress",
        "network": r"$o=Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess; @($o) | ConvertTo-Json -Compress",
        "startup": r"$o=Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User; @($o) | ConvertTo-Json -Compress",
    }
    collected = {name: _run_powershell_json(script) for name, script in ps.items()}
    return {
        "schema_version": "windows-read-only-v0.1",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "device": {
            "platform": "Windows",
            "hostname": platform.node(),
            "os_version": platform.platform(),
            "agent_version": "windows-read-only-v0.1",
        },
        "system": collected["system"],
        "security": {"defender": collected["defender"], "firewall": collected["firewall"]},
        "processes": collected["processes"],
        "services": collected["services"],
        "network_connections": collected["network"],
        "startup": collected["startup"],
    }
