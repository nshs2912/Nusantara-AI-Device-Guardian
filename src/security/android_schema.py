ANDROID_DOMAINS = (
    "Malware", "Spyware", "Network", "Persistence", "Phishing",
    "Privacy", "App Integrity", "Device Security", "Root/Tampering", "Behavior"
)

def validate_android_telemetry(telemetry):
    if not isinstance(telemetry, dict):
        raise ValueError("Android telemetry must be an object.")
    device = telemetry.get("device")
    if not isinstance(device, dict):
        raise ValueError("Android telemetry.device must be an object.")
    if str(device.get("platform", "")).lower() != "android":
        raise ValueError("Android telemetry.device.platform must be Android.")
    for key in ("os_version", "security_patch"):
        if key not in device:
            raise ValueError(f"Android device is missing {key}.")
    apps = telemetry.get("apps", [])
    if not isinstance(apps, list):
        raise ValueError("Android telemetry.apps must be a list.")
    for app in apps:
        if not isinstance(app, dict) or not app.get("package"):
            raise ValueError("Every Android app must contain a package.")
    return True
