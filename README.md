# Nusantara AI Device Guardian

AI-assisted device security assessment for suspicious malware, spyware, persistence, network, privacy, and phishing indicators.

## v0.2 Foundation

The Streamlit application is a security console, not a privileged endpoint scanner. The current release uses safe sample telemetry and heuristic detection. It does not execute malware, collect credentials, delete files, or remotely control a device.

### Included

- Evidence schema validation
- Malware heuristic indicators
- Spyware/privacy heuristic indicators
- Persistence indicators
- Network anomaly indicators
- Phishing-language indicators
- Explainable risk scoring
- Streamlit dashboard
- Unit tests
- GitHub Actions CI

### Architecture

Device Agent -> Evidence Validation -> Detection -> Risk Engine -> Analyst Explanation -> Security Console

Future device agents will collect minimized local telemetry on Windows and Android, with explicit user consent and no credential collection.

## Safety

A finding is an indicator, not proof of compromise. The application must preserve evidence and require user approval before any future remediation.

## Local run

python -m pip install -r requirements.txt
streamlit run app.py

Tests:

python -m pytest -q

## Roadmap

1. Foundation and CI
2. Windows read-only telemetry agent
3. Android security telemetry
4. Behavioral anomaly detection
5. Threat correlation and AI analyst
6. Safe remediation with explicit approval
7. Production security hardening
