
import os
import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="SENTINEL WAF",
    page_icon="🛡️",
    layout="wide"
)

LOG_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "waf_logs.csv"
)

st.title("🛡️ SENTINEL WAF")
st.subheader("Web Application Firewall — Security Dashboard")
st.caption("Monitor requests, detect threats, and review security events.")

if not os.path.exists(LOG_FILE):
    st.warning("No log file found. Start the WAF and generate requests first.")
    st.stop()

try:
    df = pd.read_csv(LOG_FILE)
except pd.errors.EmptyDataError:
    st.info("The log file is empty. Generate some requests first.")
    st.stop()

if df.empty:
    st.info("No security events recorded yet.")
    st.stop()

df["status"] = df["status"].fillna("UNKNOWN")
df["attack_type"] = df["attack_type"].fillna("None")

total_requests = len(df)
allowed = int((df["status"] == "ALLOWED").sum())
blocked = int((df["status"] == "BLOCKED").sum())

st.markdown("### Security Overview")

col1, col2, col3 = st.columns(3)
col1.metric("Total Requests", total_requests)
col2.metric("Allowed Requests", allowed)
col3.metric("Blocked Requests", blocked)

st.divider()

st.markdown("### Attack Analysis")

attacks = df[df["status"] == "BLOCKED"]

if attacks.empty:
    st.info("No blocked attacks recorded yet.")
else:
    attack_counts = attacks["attack_type"].value_counts()
    left, right = st.columns(2)

    with left:
        st.markdown("**Attacks by Type**")
        st.bar_chart(attack_counts)

    with right:
        st.markdown("**Blocked Attack Details**")
        st.dataframe(
            attacks[["timestamp", "path", "attack_type", "action"]],
            use_container_width=True,
            hide_index=True
        )

st.divider()

st.markdown("### Request Activity")
status_counts = df["status"].value_counts()
st.bar_chart(status_counts)

st.markdown("### Recent Security Events")
st.dataframe(
    df.tail(20).iloc[::-1],
    use_container_width=True,
    hide_index=True
)

st.caption("SENTINEL WAF | Local security monitoring prototype")
