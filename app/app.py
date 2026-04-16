import streamlit as st
import pandas as pd
from utils import get_processes, analyze_process
from streamlit_autorefresh import st_autorefresh

st.set_page_config(page_title="RAM Forensics Analyzer", layout="wide")

st.title("🧠 RAM Memory Forensics Dashboard")
st.caption("Live RAM analysis — updates automatically")

# Control how often the data refreshes
refresh_rate = st.sidebar.slider("🔄 Refresh Rate (seconds)", 2, 10, 5)
st_autorefresh(interval=refresh_rate * 1000, key="refresh")

# Fetch current system processes
processes = get_processes()

# Simple search to filter processes
search = st.text_input("🔍 Search process")

st.subheader("📊 Top Memory Consumers")

top_processes = sorted(processes, key=lambda x: x["memory"], reverse=True)[:10]

df = pd.DataFrame([
    {"Process": p["name"], "Memory (MB)": p["memory"] / (1024 * 1024)}
    for p in top_processes
])

st.bar_chart(df.set_index("Process"))

st.subheader("🚨 Suspicious Processes")

for p in processes:
    if search and search.lower() not in p["name"].lower():
        continue

    reasons = analyze_process(p)

    if reasons:
        st.error(f"⚠️ {p['name']} (PID: {p['pid']})")
        st.write(f"Reasons: {', '.join(reasons)}")

        for conn in p["connections"][:3]:
            try:
                st.write(f"🌐 {conn.laddr} → {conn.raddr}")
            except:
                pass

        st.write("---")

st.subheader("📁 All Processes")

for p in processes:
    if search and search.lower() not in p["name"].lower():
        continue

    with st.expander(f"{p['name']} (PID: {p['pid']})"):
        st.write(f"👤 User: {p['user']}")
        st.write(f"💾 Memory: {round(p['memory'] / (1024 * 1024), 2)} MB")
        st.write(f"🌐 Connections: {len(p['connections'])}")