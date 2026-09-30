from src.intelligence.risk_engine import calculate_risk, risk_band

def test_risk_band_boundaries():
    assert risk_band(0) == "NORMAL"
    assert risk_band(20) == "LOW"
    assert risk_band(40) == "MEDIUM"
    assert risk_band(60) == "HIGH"
    assert risk_band(80) == "CRITICAL"

def test_calculate_risk():
    result = calculate_risk([{"domain": "Network", "weight": 18}, {"domain": "Persistence", "weight": 8}])
    assert result["score"] == 26
    assert result["band"] == "LOW"
