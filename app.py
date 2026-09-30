import streamlit as st
from src.security.sample_data import sample_device_evidence
from src.intelligence.risk_engine import calculate_risk
from src.detection.detectors import run_detectors

st.set_page_config(page_title="Nusantara AI Device Guardian", page_icon="🛡️", layout="wide")
st.title("🛡️ Nusantara AI Device Guardian")
st.caption("AI-assisted device security assessment — evidence-based, explainable, and non-destructive.")

if "scan" not in st.session_state:
    st.session_state.scan = None

if st.button("🔍 Run Security Assessment", type="primary"):
    evidence = sample_device_evidence()
    findings = run_detectors(evidence)
    risk = calculate_risk(findings)
    st.session_state.scan = (evidence, findings, risk)

if st.session_state.scan:
    evidence, findings, risk = st.session_state.scan
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Overall Risk", f"{risk['score']}/100")
    c2.metric("Risk Band", risk["band"])
    c3.metric("Findings", len(findings))
    c4.metric("Device", evidence["device"]["platform"])
    st.subheader("Security Domains")
    cols = st.columns(4)
    for col, domain in zip(cols, risk["domains"][:4]):
        col.metric(domain["name"], f"{domain['score']}/100")
    st.subheader("Findings")
    if not findings:
        st.success("No suspicious indicators were found in the supplied evidence.")
    else:
        for finding in findings:
            level = finding["severity"]
            icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵"}.get(level, "ℹ️")
            with st.expander(f"{icon} {finding['title']} — {level}"):
                st.write(finding["description"])
                st.caption(f"Evidence: {finding['evidence']}")
    st.subheader("AI Security Summary")
    st.info(risk["summary"])
else:
    st.info("Run an assessment to inspect the included safe sample telemetry.")
    st.markdown("""
    **Current foundation**
    - Evidence-based risk scoring
    - Malware/persistence/network/permission indicators
    - Explainable findings
    - Safe sample telemetry
    - Automated tests and CI
    """)
