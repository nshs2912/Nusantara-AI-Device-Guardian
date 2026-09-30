REQUIRED_DEVICE_FIELDS = {"platform", "hostname", "os_version", "agent_version"}

def validate_windows_telemetry(telemetry):
    if not isinstance(telemetry, dict):
        raise ValueError("Windows telemetry must be an object.")
    device = telemetry.get("device")
    if not isinstance(device, dict) or not REQUIRED_DEVICE_FIELDS.issubset(device):
        raise ValueError("Windows telemetry.device is missing required fields.")
    if str(device.get("platform", "")).lower() != "windows":
        raise ValueError("Telemetry platform must be Windows.")
    for key in ("processes", "services", "startup", "network_connections", "security"):
        value = telemetry.get(key, [])
        if not isinstance(value, (list, dict)):
            raise ValueError(f"Windows telemetry.{key} must be a list or object.")
    return True
