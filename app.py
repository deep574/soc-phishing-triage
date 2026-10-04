import os
import streamlit as st
import json
from scripts.triage_phish import analyze_email, defang

st.set_page_config(
    page_title="SOC Phishing Email Triage Lab",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ SOC Phishing Email Triage & Threat Hunting Engine")
st.markdown("Automated RFC 822 Email Header Analysis, SPF/DKIM/DMARC Validation, and IoC Extractor")

# Sidebar
st.sidebar.header("📁 Ingest Suspicious Email")
sample_path = "samples/urgent_payroll_phish.eml"

load_sample = st.sidebar.button("⚡ Load Incident Sample (INC-2024-0891)")
uploaded_file = st.sidebar.file_uploader("Upload .eml file", type=["eml", "txt"])

target_file = None
if load_sample and os.path.exists(sample_path):
    target_file = sample_path
elif uploaded_file:
    temp_path = "temp_uploaded.eml"
    with open(temp_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    target_file = temp_path
elif os.path.exists(sample_path):
    target_file = sample_path

if target_file:
    result = analyze_email(target_file)
    meta = result["analysis_metadata"]
    hdr = result["email_headers"]
    net = result["network_telemetry"]
    iocs = result["indicators_of_compromise"]

    # Top metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Triage Verdict", meta["verdict"].split()[0])
    with col2:
        st.metric("Risk Score", f"{meta['risk_score']} / 100")
    with col3:
        st.metric("Severity", meta["severity"])
    with col4:
        st.metric("Originating IP", net["defanged_origin_ip"])

    st.markdown("---")

    # Layout columns
    left_col, right_col = st.columns([1, 1])

    with left_col:
        st.subheader("📬 RFC 822 Header Breakdown")
        st.code(f"""From:       {hdr['From']}
Reply-To:   {hdr['Reply-To']}
To:         {hdr['To']}
Subject:    {hdr['Subject']}
Date:       {hdr['Date']}
Mailer:     {hdr.get('X-Mailer', 'N/A')}
Origin IP:  {net['defanged_origin_ip']}""", language="yaml")

        st.subheader("🔐 Email Authentication Alignment")
        auth_col1, auth_col2, auth_col3 = st.columns(3)
        with auth_col1:
            st.metric("SPF", net["authentication"]["spf"])
        with auth_col2:
            st.metric("DKIM", net["authentication"]["dkim"])
        with auth_col3:
            st.metric("DMARC", net["authentication"]["dmarc"])

        st.subheader("🚨 Threat Triggers & Anomalies")
        for trig in meta["triggers"]:
            st.error(trig)

    with right_col:
        st.subheader("🔗 Defanged Indicators of Compromise (IoCs)")
        st.markdown("**Suspicious URLs:**")
        for u in iocs["defanged_urls"]:
            st.code(u, language="text")

        st.markdown("**Attachments & Cryptographic Checksums:**")
        for att in iocs["attachments"]:
            st.markdown(f"**File:** `{att['filename']}` ({att['size_bytes']} bytes)")
            st.code(f"SHA256: {att['hashes']['sha256']}\nMD5:    {att['hashes']['md5']}")

        st.subheader("🛡️ Recommended SOC Containment Actions")
        for act in result["recommended_soc_actions"]:
            st.checkbox(act, value=True, key=act)

        st.markdown("---")
        st.download_button(
            label="📥 Download JSON IoC Report",
            data=json.dumps(result, indent=2),
            file_name="triage_report.json",
            mime="application/json"
        )
else:
    st.info("Please upload an .eml file or click 'Load Incident Sample' in the sidebar to begin triage.")
