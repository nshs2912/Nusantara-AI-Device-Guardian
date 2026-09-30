ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
REQUIRED_INDICATOR_FIELDS = {"id", "title", "severity", "domain", "weight", "description", "evidence"}

def validate_evidence(evidence):
    if not isinstance(evidence, dict):
        raise ValueError("Evidence must be an object.")
    if not isinstance(evidence.get("device"), dict):
        raise ValueError("Evidence.device must be an object.")
    indicators = evidence.get("indicators", [])
    if not isinstance(indicators, list):
        raise ValueError("Evidence.indicators must be a list.")
    for item in indicators:
        if not isinstance(item, dict) or not REQUIRED_INDICATOR_FIELDS.issubset(item):
            raise ValueError("Each indicator is missing required fields.")
        if str(item["severity"]).upper() not in ALLOWED_SEVERITIES:
            raise ValueError("Unsupported severity.")
        if not isinstance(item["weight"], (int, float)) or item["weight"] < 0:
            raise ValueError("Indicator weight must be non-negative.")
    return True
