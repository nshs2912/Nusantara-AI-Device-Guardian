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
device_options = [
    "🖥️ This Windows Laptop",
    "📱 Android Device",
    "🧪 Sample Device",
]

with st.sidebar:
    st.header("Security Assessment")
    show_evidence = st.checkbox("Show raw evidence", value=False)
    st.divider()
    st.caption("v0.5 Windows read-only agent")
    st.caption("Assessment controls are available on the dashboard.")

if "scan" not in st.session_state:
    st.session_state.scan = None
if "selected_device" not in st.session_state:
    st.session_state.selected_device = device_options[0]

st.subheader("Security Assessment")
control_col, action_col = st.columns([3, 1])

with control_col:
    st.session_state.selected_device = st.selectbox(
        "Device",
        device_options,
        index=device_options.index(st.session_state.selected_device),
        label_visibility="collapsed",
    )

with action_col:
    run_assessment = st.button(
        "🔍 Run Security Assessment",
        type="primary",
        use_container_width=True,
    )

device_type = st.session_state.selected_device

if device_type == "🖥️ This Windows Laptop":
    if windows_available:
        st.success(
            "LOCAL READ-ONLY SCAN — Windows telemetry will be collected from this machine only."
        )
    else:
        st.info(
            "Windows local scanning is available when this application runs on Windows. "
            "In Streamlit Cloud/Linux, this option cannot access your laptop."
        )
elif device_type == "📱 Android Device":
    st.info(
        "ANDROID DEVICE — currently represented by safe Android telemetry simulation. "
        "A future Android agent can provide minimized read-only telemetry with explicit consent."
    )
else:
    st.info("SAMPLE DEVICE — safe synthetic telemetry for demonstration and testing.")

if run_assessment:
    try:
        if device_type == "🖥️ This Windows Laptop":
            if not windows_available:
                raise RuntimeError(
                    "Local Windows scanning requires the application to run on a Windows device. "
                    "Streamlit Cloud cannot directly scan your Windows laptop."
                )
            evidence = collect_windows_telemetry()
            validate_windows_telemetry(evidence)
            findings = run_windows_detectors(evidence)
            source = "LOCAL WINDOWS READ-ONLY"
        elif device_type == "📱 Android Device":
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
    st.markdown("- **🖥️ This Windows Laptop** — local, read-only Windows telemetry")
    st.markdown("- **📱 Android Device** — Android security telemetry mode")
    st.markdown("- **🧪 Sample Device** — safe generic simulation")
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
            evidence["device"].get(
                "hostname",
                evidence["device"].get("platform", scanned_type),
            ),
        ),
    )

    if source == "LOCAL WINDOWS READ-ONLY":
        st.subheader("Windows Security Posture")
        security = evidence.get("security", {})
        posture = st.columns(5)

        defender = security.get("defender", {}).get("data", {})
        posture[0].metric(
            "Defender",
            "ON" if defender.get("RealTimeProtectionEnabled") else "OFF",
        )

        firewall_items = security.get("firewall", {}).get("data", [])
        if isinstance(firewall_items, dict):
            firewall_items = [firewall_items]
        firewall_ok = bool(firewall_items) and all(
            item.get("Enabled") is True
            for item in firewall_items
            if isinstance(item, dict)
        )
        posture[1].metric("Firewall", "ON" if firewall_ok else "CHECK")

        secure_boot = security.get("secure_boot", {}).get("data", {})
        secure_boot_state = (
            "ON"
            if secure_boot.get("Enabled") is True
            else "OFF"
            if secure_boot.get("Supported") is True
            else "N/A"
        )
        posture[2].metric("Secure Boot", secure_boot_state)

        tpm = security.get("tpm", {}).get("data", {})
        posture[3].metric("TPM", "READY" if tpm.get("TpmReady") else "CHECK")

        uac = security.get("uac", {}).get("data", {})
        posture[4].metric("UAC", "ON" if uac.get("EnableLUA") else "CHECK")

        st.caption(
            "Posture indicators describe security configuration. They are not proof that a device is compromised."
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
            icon = {
                "CRITICAL": "🔴",
                "HIGH": "🟠",
                "MEDIUM": "🟡",
                "LOW": "🔵",
            }.get(finding["severity"], "ℹ️")
            with st.expander(f"{icon} {finding['title']} — {finding['severity']}"):
                st.write(finding["description"])
                st.caption(
                    f"Domain: {finding['domain']} • Weight: {finding['weight']}"
                )
                st.code(finding["evidence"])

    st.subheader("Security Analyst Summary")
    st.info(risk["summary"])
    st.caption(
        "A finding is an indicator, not proof of compromise. Verify context before remediation."
    )

    if show_evidence:
        st.subheader("Evidence")
        st.json(evidence)
