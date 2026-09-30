import streamlit as st
from src.security.sample_data import sample_device_evidence
from src.security.validation import validate_evidence
from src.intelligence.risk_engine import calculate_risk
from src.detection.detectors import run_detectors

st.set_page_config(page_title="Nusantara AI Device Guardian", page_icon="🛡️", layout="wide")
st.title("🛡️ Nusantara AI Device Guardian")
st.caption("AI-assisted device security assessment — evidence-based, explainable, and non-destructive.")

with st.sidebar:
    st.header("Security Assessment")
    st.write("This MVP analyzes supplied evidence. Streamlit Cloud cannot directly inspect your personal laptop or phone.")
    show_evidence = st.checkbox("Show raw evidence", value=False)
    st.divider()
    st.caption("v0.2 foundation • safe simulation")

if "scan" not in st.session_state:
    st.session_state.scan = None

if st.button("🔍 Run Security Assessment", type="primary"):
    evidence = sample_device_evidence()
    validate_evidence(evidence)
    findings = run_detectors(evidence)
    risk = calculate_risk(findings)
    st.session_state.scan = (evidence, findings, risk)

if not st.session_state.scan:
    st.info("Run an assessment to inspect the included safe sample telemetry.")
    st.markdown("### Current capabilities")
    st.markdown("- Heuristic malware, spyware, persistence, network and phishing indicators\n- Evidence validation\n- Explainable risk score\n- Safe sample telemetry\n- Automated tests and CI")
else:
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
            icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵"}.get(finding["severity"], "ℹ️")
            with st.expander(f"{icon} {finding['title']} — {finding['severity']}"):
                st.write(finding["description"])
                st.caption(f"Domain: {finding['domain']} • Weight: {finding['weight']}")
                st.code(finding["evidence"])

    st.subheader("Security Analyst Summary")
    st.info(risk["summary"])
    if show_evidence:
        st.subheader("Evidence")
        st.json(evidence)
