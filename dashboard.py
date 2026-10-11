
import os
import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="SENTINEL WAF | Security Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "waf_logs.csv")

# ---------- NAVY BLUE + ORANGE THEME ----------
st.markdown("""
<style>
:root {
    --navy: #08152E;
    --navy-light: #10264A;
    --orange: #FF8A24;
    --orange-light: #FFB15C;
    --white: #F5F7FC;
    --muted: #AAB8D0;
}

.stApp {
    background: linear-gradient(135deg, #071326 0%, #10264A 100%);
    color: var(--white);
}

[data-testid="stHeader"] {
    background: rgba(8, 21, 46, 0.95);
}

[data-testid="stSidebar"] {
    background: #061126;
    border-right: 1px solid #243A5D;
}

[data-testid="stSidebar"] * {
    color: #F5F7FC;
}

.block-container {
    padding-top: 2rem;
    padding-bottom: 3rem;
    max-width: 1450px;
}

.hero {
    background: linear-gradient(110deg, #10264A, #173761);
    border: 1px solid #29496F;
    border-left: 5px solid #FF8A24;
    border-radius: 18px;
    padding: 27px 30px;
    margin-bottom: 25px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.20);
}

.hero h1 {
    color: #FFFFFF;
    font-size: 36px;
    margin: 0;
    letter-spacing: 1px;
}

.hero p {
    color: #C0CDE0;
    font-size: 15px;
    margin: 8px 0 0 0;
}

.orange {
    color: #FF8A24;
}

.section-title {
    color: #FFFFFF;
    font-size: 22px;
    font-weight: 700;
    margin: 25px 0 15px 0;
    padding-bottom: 9px;
    border-bottom: 2px solid #FF8A24;
}

div[data-testid="stMetric"] {
    background: linear-gradient(145deg, #10264A, #142E53);
    border: 1px solid #2A456B;
    border-radius: 15px;
    padding: 20px 22px;
    box-shadow: 0 7px 18px rgba(0,0,0,0.18);
}

div[data-testid="stMetricLabel"] {
    color: #C0CDE0;
}

div[data-testid="stMetricValue"] {
    color: #FFFFFF;
    font-weight: 800;
}

div[data-testid="stMetricDelta"] {
    color: #FFB15C;
}

div[data-testid="stDataFrame"] {
    border: 1px solid #2A456B;
    border-radius: 12px;
    overflow: hidden;
}

.stButton > button {
    background: #FF8A24;
    color: #08152E;
    border: none;
    border-radius: 9px;
    font-weight: 700;
}

.stButton > button:hover {
    background: #FFB15C;
    color: #08152E;
    border: none;
}

div[data-testid="stAlert"] {
    border-radius: 12px;
}

.footer {
    text-align: center;
    color: #91A4C2;
    border-top: 1px solid #29405F;
    margin-top: 40px;
    padding-top: 20px;
    font-size: 13px;
}

div[data-testid="stPlotlyChart"],
div[data-testid="stVegaLiteChart"] {
    background: #10264A;
    border-radius: 12px;
}

</style>
""", unsafe_allow_html=True)

# ---------- SIDEBAR ----------
with st.sidebar:
    st.markdown(
        "<h1 style='color:#FF8A24;'>🛡️ SENTINEL</h1>",
        unsafe_allow_html=True
    )
    st.caption("WEB APPLICATION FIREWALL")
    st.markdown("---")
    st.markdown("### Navigation")
    page = st.radio(
        "Choose a section",
        ["Overview", "Attack Analysis", "Security Logs"],
        label_visibility="collapsed"
    )
    st.markdown("---")
    st.markdown("**Protection Engine**")
    st.markdown("🟠 Pattern-based detection")
    st.markdown("🔵 SQL Injection monitoring")
    st.markdown("🟠 XSS detection")
    st.markdown("---")
    st.caption("Local security monitoring prototype")

# ---------- HEADER ----------
st.markdown("""
<div class="hero">
    <h1>🛡️ SENTINEL <span class="orange">WAF</span></h1>
    <p>SECURITY OPERATIONS CENTER &nbsp; / &nbsp;
    Web traffic monitoring, threat detection and incident visibility</p>
</div>
""", unsafe_allow_html=True)

# ---------- LOAD LOGS ----------
if not os.path.exists(LOG_FILE):
    st.warning("No security log file found. Start the WAF and generate requests.")
    st.stop()

try:
    df = pd.read_csv(LOG_FILE)
except pd.errors.EmptyDataError:
    st.info("Your security log file is empty.")
    st.stop()

if df.empty:
    st.info("No requests have been recorded yet.")
    st.stop()

required = [
    "timestamp", "method", "path", "ip",
    "status", "attack_type", "action"
]

missing = [column for column in required if column not in df.columns]
if missing:
    st.error("The log file is missing columns: " + ", ".join(missing))
    st.stop()

df["status"] = df["status"].fillna("UNKNOWN")
df["attack_type"] = df["attack_type"].fillna("None")
df["path"] = df["path"].fillna("/")
df["timestamp"] = df["timestamp"].fillna("Unknown")

total = len(df)
allowed = int((df["status"] == "ALLOWED").sum())
blocked = int((df["status"] == "BLOCKED").sum())
attack_df = df[df["status"] == "BLOCKED"].copy()

# ---------- OVERVIEW ----------
if page == "Overview":
    st.markdown(
        '<div class="section-title">📊 Security Overview</div>',
        unsafe_allow_html=True
    )

    c1, c2, c3 = st.columns(3)
    c1.metric("TOTAL REQUESTS", f"{total:,}", "Traffic inspected")
    c2.metric("ALLOWED REQUESTS", f"{allowed:,}", "Passed inspection")
    c3.metric("BLOCKED THREATS", f"{blocked:,}", "Requests blocked")

    st.markdown(
        '<div class="section-title">📈 Traffic Intelligence</div>',
        unsafe_allow_html=True
    )

    left, right = st.columns(2)

    with left:
        st.markdown("**Request Status Distribution**")
        status_counts = pd.Series({
            "Allowed": allowed,
            "Blocked": blocked
        })
        st.bar_chart(status_counts, color="#FF8A24")

    with right:
        st.markdown("**Detected Attack Categories**")
        if attack_df.empty:
            st.info("No blocked attacks recorded yet.")
        else:
            attack_counts = attack_df["attack_type"].value_counts()
            st.bar_chart(attack_counts, color="#FF8A24")

    st.markdown(
        '<div class="section-title">🚨 Latest Security Events</div>',
        unsafe_allow_html=True
    )

    recent = df.tail(8).iloc[::-1]
    st.dataframe(recent, use_container_width=True, hide_index=True)

elif page == "Attack Analysis":
    st.markdown(
        '<div class="section-title">🎯 Threat Intelligence</div>',
        unsafe_allow_html=True
    )

    if attack_df.empty:
        st.success("No blocked attacks have been recorded.")
    else:
        c1, c2 = st.columns(2)
        c1.metric("Detected Incidents", len(attack_df))
        c2.metric(
            "Attack Categories",
            attack_df["attack_type"].nunique()
        )

        st.markdown("**Attack Frequency**")
        st.bar_chart(
            attack_df["attack_type"].value_counts(),
            color="#FF8A24"
        )

        st.markdown("**Incident Details**")
        st.dataframe(
            attack_df[
                ["timestamp", "method", "path", "ip",
                 "attack_type", "status", "action"]
            ].iloc[::-1],
            use_container_width=True,
            hide_index=True
        )

        report = attack_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            "⬇️ Download Incident Report",
            data=report,
            file_name="incident_report.csv",
            mime="text/csv"
        )

elif page == "Security Logs":
    st.markdown(
        '<div class="section-title">📋 Security Event Logs</div>',
        unsafe_allow_html=True
    )

    statuses = ["All"] + sorted(df["status"].unique().tolist())
    selected_status = st.selectbox("Filter by request status", statuses)

    filtered = df.copy()
    if selected_status != "All":
        filtered = filtered[filtered["status"] == selected_status]

    st.caption(f"Showing {len(filtered)} of {total} recorded requests.")
    st.dataframe(
        filtered.iloc[::-1],
        use_container_width=True,
        hide_index=True
    )

    st.download_button(
        "⬇️ Download Filtered Logs",
        data=filtered.to_csv(index=False).encode("utf-8"),
        file_name="waf_logs_export.csv",
        mime="text/csv"
    )

# ---------- FOOTER ----------
st.markdown("""
<div class="footer">
    <b style="color:#FF8A24;">SENTINEL WAF</b>
    &nbsp; • &nbsp; Security Monitoring Prototype
    <br>Built with Python, Flask, Streamlit and Pandas
</div>
""", unsafe_allow_html=True)
