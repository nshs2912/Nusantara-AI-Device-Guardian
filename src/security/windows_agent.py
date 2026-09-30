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
            [
                POWERSHELL,
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"available": False, "error": str(exc)}
    if completed.returncode != 0:
        return {
            "available": False,
            "error": completed.stderr.strip()[:500] or "PowerShell command failed.",
        }
    raw = completed.stdout.strip()
    if not raw:
        return {"available": True, "data": None}
    try:
        return {"available": True, "data": json.loads(raw)}
    except json.JSONDecodeError:
        return {"available": True, "data": raw[:1000]}


def collect_windows_telemetry():
    """Collect minimized, read-only Windows security telemetry.

    Process command-line arguments are deliberately not returned because they can
    contain passwords, tokens, file paths, or other sensitive user data.
    """
    if os.name != "nt":
        raise RuntimeError("Windows read-only collection is only available on Windows.")

    ps = {
        "system": r"$o=Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,LastBootUpTime; $o | ConvertTo-Json -Compress",
        "defender": r"$o=Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntispywareEnabled,AntivirusSignatureVersion,AntivirusSignatureLastUpdated; $o | ConvertTo-Json -Compress",
        "firewall": r"$o=Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction; @($o) | ConvertTo-Json -Compress",
        "processes": r"""$o=Get-CimInstance Win32_Process | ForEach-Object {
            $cmd=[string]$_.CommandLine
            [pscustomobject]@{
                Name=$_.Name
                ProcessId=$_.ProcessId
                ExecutablePath=$_.ExecutablePath
                HasEncodedPowerShell=([bool]($cmd -match '(?i)powershell(?:.exe)?[^
]*-enc(?:odedcommand)?'))
            }
        }; @($o) | ConvertTo-Json -Compress""",
        "services": r"$o=Get-CimInstance Win32_Service | Where-Object {$_.StartMode -eq 'Auto'} | Select-Object Name,State,StartMode,PathName; @($o) | ConvertTo-Json -Compress",
        "network": r"$o=Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess; @($o) | ConvertTo-Json -Compress",
        "startup": r"$o=Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User; @($o) | ConvertTo-Json -Compress",
        "secure_boot": r"try {$o=Confirm-SecureBootUEFI -ErrorAction Stop; [pscustomobject]@{Supported=$true;Enabled=[bool]$o} | ConvertTo-Json -Compress} catch {[pscustomobject]@{Supported=$false;Enabled=$null;Reason=$_.Exception.Message} | ConvertTo-Json -Compress}",
        "tpm": r"try {$o=Get-Tpm -ErrorAction Stop | Select-Object TpmPresent,TpmReady,ManufacturerIdTxt,ManufacturerVersion; $o | ConvertTo-Json -Compress} catch {[pscustomobject]@{TpmPresent=$false;TpmReady=$false} | ConvertTo-Json -Compress}",
        "uac": r"$o=Get-ItemProperty 'HKLM:SOFTWAREMicrosoftWindowsCurrentVersionPoliciesSystem' -ErrorAction SilentlyContinue | Select-Object EnableLUA,ConsentPromptBehaviorAdmin; $o | ConvertTo-Json -Compress",
    }

    collected = {name: _run_powershell_json(script) for name, script in ps.items()}

    return {
        "schema_version": "windows-read-only-v0.2",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "device": {
            "platform": "Windows",
            "hostname": platform.node(),
            "os_version": platform.platform(),
            "agent_version": "windows-read-only-v0.2",
        },
        "system": collected["system"],
        "security": {
            "defender": collected["defender"],
            "firewall": collected["firewall"],
            "secure_boot": collected["secure_boot"],
            "tpm": collected["tpm"],
            "uac": collected["uac"],
        },
        "processes": collected["processes"],
        "services": collected["services"],
        "network_connections": collected["network"],
        "startup": collected["startup"],
    }
