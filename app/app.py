import streamlit as st
import pandas as pd
from utils import get_processes, analyze_process
from streamlit_autorefresh import st_autorefresh

# -------------------------------
# Page setup
# -------------------------------
st.set_page_config(page_title="SOC Dashboard", layout="wide")

# -------------------------------
# hacker-style UI
# -------------------------------
st.markdown("""
    <style>
    body {
        background-color: #0b0f1a;
        color: #00ffcc;
    }
    .stApp {
        background-color: #0b0f1a;
    }
    h1, h2, h3 {
        color: #00ffcc;
    }
    .stMetric {
        background-color: #111827;
        padding: 10px;
        border-radius: 10px;
    }
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ SOC Memory Forensics Dashboard")
st.caption("Real-time RAM threat analysis")

# -------------------------------
# Sidebar
# -------------------------------
refresh_rate = st.sidebar.slider("🔄 Refresh Rate (seconds)", 2, 10, 5)
st_autorefresh(interval=refresh_rate * 1000, key="refresh")

# -------------------------------
# Loading Spinner
# -------------------------------
with st.spinner("Analyzing system memory..."):
    processes = get_processes()

search = st.text_input("🔍 Search process")

# -------------------------------
# Detect suspicious processes
# -------------------------------
threats = []

for p in processes:
    reasons = analyze_process(p)
    if reasons:
        threats.append((p, reasons))

# Sort by severity (memory)
threats = sorted(threats, key=lambda x: x[0]["memory"], reverse=True)

# -------------------------------
# 🚨 TOP 3 THREATS (SOC STYLE)
# -------------------------------
st.subheader("🚨 Top Threats")

top_threats = threats[:3]

cols = st.columns(3)

for i, (p, reasons) in enumerate(top_threats):
    with cols[i]:
        st.error(f"{p['name']}")
        st.metric("PID", p["pid"])
        st.metric("Memory (MB)", round(p["memory"] / (1024 * 1024), 2))
        st.write("⚠️ " + ", ".join(reasons))

# -------------------------------
# 📊 Memory Chart
# -------------------------------
st.subheader("📊 Top Memory Consumers")

top_processes = sorted(processes, key=lambda x: x["memory"], reverse=True)[:10]

df = pd.DataFrame([
    {"Process": p["name"], "Memory (MB)": p["memory"] / (1024 * 1024)}
    for p in top_processes
])

st.bar_chart(df.set_index("Process"))

# -------------------------------
# 🚨 Suspicious Processes
# -------------------------------
st.subheader("🚨 Suspicious Processes")

for p, reasons in threats:
    if search and search.lower() not in p["name"].lower():
        continue

    st.error(f"⚠️ {p['name']} (PID: {p['pid']})")
    st.write(f"Reasons: {', '.join(reasons)}")

    for conn in p["connections"][:3]:
        try:
            st.write(f"🌐 {conn.laddr} → {conn.raddr}")
        except:
            pass

    st.write("---")

# -------------------------------
# 📁 All Processes
# -------------------------------
st.subheader("📁 All Processes")

for p in processes:
    if search and search.lower() not in p["name"].lower():
        continue

    with st.expander(f"{p['name']} (PID: {p['pid']})"):
        st.write(f"👤 User: {p['user']}")
        st.write(f"💾 Memory: {round(p['memory'] / (1024 * 1024), 2)} MB")
        st.write(f"🌐 Connections: {len(p['connections'])}")