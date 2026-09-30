def sample_windows_evidence():
    return {
        "schema_version": "windows-read-only-v0.1",
        "device": {
            "platform": "Windows",
            "hostname": "SAMPLE-LAPTOP",
            "os_version": "Windows 11 24H2",
            "agent_version": "windows-read-only-simulator-v0.1",
        },
        "security": {
            "defender": {"available": True, "data": {"RealTimeProtectionEnabled": True, "AntivirusEnabled": True}},
            "firewall": {"available": True, "data": [
                {"Name": "Domain", "Enabled": True},
                {"Name": "Private", "Enabled": True},
                {"Name": "Public", "Enabled": False},
            ]},
        },
        "processes": {"available": True, "data": [
            {"Name": "powershell.exe", "CommandLine": "powershell.exe -NoProfile -EncodedCommand sample"},
        ]},
        "services": {"available": True, "data": [
            {"Name": "SampleUpdater", "State": "Running", "StartMode": "Auto", "PathName": "C:\\Program Files\\SampleUpdater\\updater.exe"},
        ]},
        "network_connections": {"available": True, "data": []},
        "startup": {"available": True, "data": [
            {"Name": "Sample Updater", "Command": "C:\\Program Files\\SampleUpdater\\updater.exe", "Location": "HKCU", "User": "SAMPLE"},
        ]},
    }
