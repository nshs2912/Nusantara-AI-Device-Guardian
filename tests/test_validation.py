import pytest
from src.security.validation import validate_evidence

def test_valid_evidence():
    assert validate_evidence({"device": {}, "indicators": []})

def test_invalid_indicator():
    with pytest.raises(ValueError):
        validate_evidence({"device": {}, "indicators": [{"severity": "UNKNOWN"}]})
