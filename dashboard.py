import json

import streamlit as st

from main import analyze

st.set_page_config(page_title="HONEYNET SENTINEL", page_icon="🛡️", layout="wide")
st.title("HONEYNET SENTINEL")
st.caption("Cowrie honeypot telemetry review — offline export only")

uploaded_file = st.file_uploader(
    "Upload Cowrie JSON or JSONL export",
    type=["json", "jsonl", "log"],
)

if uploaded_file:
    report = analyze(uploaded_file.getvalue().decode("utf-8", errors="replace"))

    events_col, sessions_col, failed_col, success_col = st.columns(4)
    events_col.metric("Events", report["events_parsed"])
    sessions_col.metric("Sessions", report["unique_sessions"])
    failed_col.metric("Failed logins", report["failed_logins"])
    success_col.metric("Successful logins", report["successful_logins"])

    st.subheader("Top source IPs")
    st.dataframe(
        [{"source_ip": ip, "events": count} for ip, count in report["top_source_ips"]],
        use_container_width=True,
    )

    st.subheader("Event types")
    st.json(report["event_counts"])

    st.subheader("Observed command strings (untrusted; never execute)")
    st.dataframe(
        [{"command": command, "count": count} for command, count in report["top_commands"]],
        use_container_width=True,
    )

    st.download_button(
        "Download JSON report",
        json.dumps(report, indent=2),
        file_name="honeynet-report.json",
        mime="application/json",
    )
else:
    st.info(
        "Upload an authorized Cowrie log export to generate the report. "
        "This dashboard does not collect live honeypot traffic."
    )
