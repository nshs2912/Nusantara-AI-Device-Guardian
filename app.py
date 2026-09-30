import streamlit as st
from src.security.sample_data import sample_device_evidence
from src.security.android_sample import sample_android_evidence
from src.security.validation import validate_evidence
from src.security.android_schema import validate_android_telemetry
from src.intelligence.risk_engine import calculate_risk
from src.detection.detectors import run_detectors
from src.detection.android_detectors import run_android_detectors

st.set_page_config(page_title="Nusantara AI Device Guardian", page_icon="🛡️", layout="wide")
st.title("🛡️ Nusantara AI Device Guardian")
st.caption("AI-assisted device security assessment — evidence-based, explainable, and non-destructive.")

with st.sidebar:
    st.header("Security Assessment")
    device_type = st.radio("Device", ["Android", "Sample Device"], index=0)
    st.write("The current MVP uses safe simulated telemetry. A future Android agent will collect minimized read-only telemetry with explicit user consent.")
    show_evidence = st.checkbox("Show raw evidence", value=False)
    st.divider()
    st.caption("v0.3 Android security foundation")

if "scan" not in st.session_state:
    st.session_state.scan = None

if st.button("🔍 Run Security Assessment", type="primary"):
    if device_type == "Android":
        evidence = sample_android_evidence()
        validate_android_telemetry(evidence)
        findings = run_android_detectors(evidence)
    else:
        evidence = sample_device_evidence()
        validate_evidence(evidence)
        findings = run_detectors(evidence)
    risk = calculate_risk(findings)
    st.session_state.scan = (evidence, findings, risk, device_type)

if not st.session_state.scan:
    st.info("Pilih device lalu jalankan assessment untuk melihat telemetry keamanan.")
    st.markdown("### Android detection coverage")
    st.markdown("- Malware / Spyware / Privacy / Network")
    st.markdown("- Persistence / Phishing / App Integrity")
    st.markdown("- Device Security / Root-Tampering / Behavior")
else:
    evidence, findings, risk, scanned_type = st.session_state.scan
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Overall Risk", f"{risk['score']}/100")
    c2.metric("Risk Band", risk["band"])
    c3.metric("Findings", len(findings))
    c4.metric("Device", evidence["device"].get("model", evidence["device"].get("platform", scanned_type)))

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
            icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵"}.get(finding["severity"], "ℹ️")
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
