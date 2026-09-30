# Nusantara AI Device Guardian

AI-assisted device security assessment for suspicious malware, spyware, persistence, network, privacy, and phishing indicators.

## v0.1 Foundation

This release deliberately uses safe sample telemetry. It does not claim to scan or control the host device from Streamlit Cloud.

Included:
- Explainable risk engine
- Security findings and domain scores
- Safe sample evidence
- Streamlit security console
- Unit tests
- GitHub Actions CI

## Architecture

Streamlit is the security console. Future Windows/Android/macOS/Linux agents will collect local telemetry and submit minimized, validated evidence to the analysis layer.

Device Agent -> Evidence -> Detection -> Risk Engine -> AI Explanation -> Security Console

## Safety principles

- Evidence before conclusions
- No destructive actions by default
- No automatic file deletion
- No credential collection
- No malware execution
- User approval required for future remediation actions

## Run locally

python -m pip install -r requirements.txt
streamlit run app.py

Run tests:

python -m pytest -q

## Roadmap

1. Foundation and CI
2. Windows telemetry agent
3. Android security telemetry
4. Behavioral anomaly detection
5. Threat correlation and AI analyst
6. Safe remediation workflows
7. Production hardening
