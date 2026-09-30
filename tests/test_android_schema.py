import pytest
from src.security.android_schema import validate_android_telemetry
from src.security.android_sample import sample_android_evidence

def test_android_sample_is_valid():
    assert validate_android_telemetry(sample_android_evidence())

def test_non_android_device_rejected():
    data = sample_android_evidence()
    data["device"]["platform"] = "Windows"
    with pytest.raises(ValueError):
        validate_android_telemetry(data)
