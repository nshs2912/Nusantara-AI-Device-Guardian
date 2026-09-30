import os

import streamlit as st

from src.security.sample_data import sample_device_evidence
from src.security.android_sample import sample_android_evidence
from src.security.validation import validate_evidence
from src.security.android_schema import validate_android_telemetry
from src.security.windows_agent import collect_windows_telemetry
from src.security.windows_schema import validate_windows_telemetry
from src.intelligence.risk_engine import calculate_risk
from src.detection.detectors import run_detectors
from src.detection.android_detectors import run_android_detectors
from src.detection.windows_detectors import run_windows_detectors

st.set_page_config(page_title="Nusantara AI Device Guardian", page_icon="🛡️", layout="wide")
st.title("🛡️ Nusantara AI Device Guardian")
st.caption("AI-assisted device security assessment — evidence-based, explainable, and non-destructive.")

windows_available = os.name == "nt"
device_options = ["Android Sample", "Sample Device"]
if windows_available:
    device_options.insert(0, "This Windows Laptop")

with st.sidebar:
    st.header("Security Assessment")
    device_type = st.radio("Device", device_options, index=0)
    if device_type == "This Windows Laptop":
        st.warning("LOCAL READ-ONLY SCAN")
        st.write(
            "This mode inspects minimized Windows security telemetry on this machine only. "
            "It does not collect passwords, browser secrets, cookies, private documents, or credentials, "
            "and it performs no remediation."
        )
    else:
        st.write(
            "Simulation mode uses safe synthetic telemetry. A future Android agent can collect minimized "
            "read-only telemetry with explicit user consent."
        )
    show_evidence = st.checkbox("Show raw evidence", value=False)
    st.divider()
    st.caption("v0.4 Windows read-only agent")

if "scan" not in st.session_state:
    st.session_state.scan = None

if st.button("🔍 Run Security Assessment", type="primary"):
    try:
        if device_type == "This Windows Laptop":
            evidence = collect_windows_telemetry()
            validate_windows_telemetry(evidence)
            findings = run_windows_detectors(evidence)
            source = "LOCAL WINDOWS READ-ONLY"
        elif device_type == "Android Sample":
            evidence = sample_android_evidence()
            validate_android_telemetry(evidence)
            findings = run_android_detectors(evidence)
            source = "ANDROID SIMULATION"
        else:
            evidence = sample_device_evidence()
            validate_evidence(evidence)
            findings = run_detectors(evidence)
            source = "GENERIC SIMULATION"

        risk = calculate_risk(findings)
        st.session_state.scan = (evidence, findings, risk, device_type, source)
    except Exception as exc:
        st.error(f"Assessment could not be completed: {exc}")

if not st.session_state.scan:
    st.info("Pilih device lalu jalankan assessment untuk melihat telemetry keamanan.")
    st.markdown("### Available assessment modes")
    if windows_available:
        st.markdown("- **This Windows Laptop** — local, read-only Windows telemetry")
    st.markdown("- **Android Sample** — safe Android security simulation")
    st.markdown("- **Sample Device** — generic simulation")
else:
    evidence, findings, risk, scanned_type, source = st.session_state.scan
    st.success(f"Assessment source: {source}")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Overall Risk", f"{risk['score']}/100")
    c2.metric("Risk Band", risk["band"])
    c3.metric("Findings", len(findings))
    c4.metric(
        "Device",
        evidence["device"].get(
            "model",
            evidence["device"].get("hostname", evidence["device"].get("platform", scanned_type)),
        ),
    )

    st.subheader("Security Domains")
    domains = risk["domains"]
    cols = st.columns(min(5, max(1, len(domains))))
    for index, domain in enumerate(domains):
        cols[index % len(cols)].metric(domain["name"], f"{domain['score']}/100")

    st.subheader("Findings")
    if not findings:
        st.success("No suspicious indicators were found in the supplied evidence.")
    else:
        for finding in findings:
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(
                finding["severity"], "ℹ️"
            )
            with st.expander(f"{icon} {finding['title']} — {finding['severity']}"):
                st.write(finding["description"])
                st.caption(f"Domain: {finding['domain']} • Weight: {finding['weight']}")
                st.code(finding["evidence"])

    st.subheader("Security Analyst Summary")
    st.info(risk["summary"])
    st.caption("A finding is an indicator, not proof of compromise. Verify context before remediation.")

    if show_evidence:
        st.subheader("Evidence")
        st.json(evidence)
