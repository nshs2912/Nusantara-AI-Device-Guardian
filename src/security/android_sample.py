def sample_android_evidence():
    return {
        "device": {
            "platform": "Android",
            "model": "Sample Android Device",
            "os_version": "15",
            "security_patch": "2026-08-01",
            "agent": "android-read-only-simulator-v0.1",
            "root_detected": False,
            "bootloader_unlocked": False,
        },
        "apps": [
            {
                "package": "com.example.notes",
                "label": "Sample Notes",
                "source": "Play Store",
                "accessibility_enabled": False,
                "notification_access": False,
                "camera": False,
                "microphone": False,
                "location": True,
            },
            {
                "package": "com.example.unknownhelper",
                "label": "Unknown Helper",
                "source": "Unknown source",
                "accessibility_enabled": True,
                "notification_access": True,
                "camera": True,
                "microphone": True,
                "location": True,
            },
        ],
        "network": [
            {"destination": "unclassified.example", "periodic": True, "dns_suspicious": True}
        ],
        "events": [
            {"type": "accessibility", "message": "unknown helper accessibility service enabled"},
            {"type": "network", "message": "periodic outbound connection to suspicious dns destination"},
        ],
    }
