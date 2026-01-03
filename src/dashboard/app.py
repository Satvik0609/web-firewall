import streamlit as st
import requests
import pandas as pd
import time
import plotly.express as px
import random

# Configuration
API_URL = "http://127.0.0.1:8000"
API_KEY = "naval-academy-secret-key-2024"
HEADERS = {"X-API-Key": API_KEY}

st.set_page_config(
    page_title="WAF ML Anomaly Detection",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.title("🛡️ ML-Enabled WAF Anomaly Detection Module")

# Sidebar for controls
st.sidebar.header("Control Panel")
simulation_speed = st.sidebar.slider("Simulation Speed (requests/sec)", 1, 10, 2)
run_simulation = st.sidebar.checkbox("Run Traffic Simulation")

enable_shadow_mode = st.sidebar.checkbox("Enable Shadow Mode (All Traffic)")

st.sidebar.markdown("---")
st.sidebar.subheader("Model Training")
model_type = st.sidebar.selectbox("Model Type", ["isolation_forest", "autoencoder"])

if st.sidebar.button("Retrain Model"):
    try:
        res = requests.post(f"{API_URL}/retrain", params={"model_type": model_type}, headers=HEADERS).json()
        st.sidebar.success(res['status'])
    except:
        st.sidebar.error("Failed to retrain")

st.sidebar.markdown("---")
st.sidebar.subheader("Alert Configuration")
webhook_url = st.sidebar.text_input("Webhook URL", placeholder="https://hooks.slack.com/...")
if st.sidebar.button("Update Alert Config"):
    try:
        res = requests.post(f"{API_URL}/config/alerts", json={"webhook_url": webhook_url}, headers=HEADERS).json()
        if res.get('enabled'):
            st.sidebar.success("Alerts Enabled")
        else:
            st.sidebar.info("Alerts Disabled")
    except:
        st.sidebar.error("Failed to update config")

# Stats Section
st.header("System Status")
col1, col2, col3, col4 = st.columns(4)

try:
    stats = requests.get(f"{API_URL}/stats", headers=HEADERS).json()
    col1.metric("Model Status", stats.get("model_status", "Unknown"))
    col2.metric("Total Analyzed", stats.get("total_analyzed", 0))
    col3.metric("Anomalies Detected", stats.get("anomalies_detected", 0))
    col4.metric("Active IPs", stats.get("active_ips", 0))
except:
    col1.metric("API Status", "Offline")
    st.error("Could not connect to API. Please ensure `uvicorn src.api.main:app` is running.")

# Real-time Monitor
st.header("Real-time Traffic Analysis")

# Placeholder for charts
chart_col1, chart_col2 = st.columns(2)
with chart_col1:
    scatter_placeholder = st.empty()
with chart_col2:
    pie_placeholder = st.empty()

log_placeholder = st.empty()

if "traffic_history" not in st.session_state:
    st.session_state.traffic_history = []

def generate_random_traffic():
    """Generate a single random traffic log."""
    is_attack = random.random() < 0.1
    # Random IP pool
    ips = [f"192.168.1.{i}" for i in range(1, 10)] + ["10.0.0.666"] # 666 is bot
    
    if is_attack:
        return {
            "source_ip": "10.0.0.666",
            "packet_size": random.randint(3000, 8000),
            "latency": random.uniform(100, 500),
            "url_length": random.randint(100, 300),
            "num_params": random.randint(5, 20),
            "method": random.choice(["POST", "PUT"]),
            "protocol": "HTTP/1.1"
        }
    else:
        return {
            "source_ip": random.choice(ips),
            "packet_size": random.randint(200, 1000),
            "latency": random.uniform(20, 100),
            "url_length": random.randint(10, 50),
            "num_params": random.randint(0, 5),
            "method": random.choice(["GET", "POST"]),
            "protocol": "HTTP/2"
        }

def render_dashboard(df):
    if df.empty:
        return

    # Chart 1: Scatter Plot (Latency vs Packet Size)
    fig_scatter = px.scatter(
        df, 
        x="latency", 
        y="packet_size", 
        color="is_anomaly",
        title="Traffic Clusters (Latency vs Packet Size)",
        color_discrete_map={True: "red", False: "blue"},
        hover_data=['explanation', 'source_ip']
    )
    scatter_placeholder.plotly_chart(fig_scatter, use_container_width=True)
    
    # Chart 2: Anomaly Distribution
    anomaly_counts = df['is_anomaly'].value_counts().reset_index()
    anomaly_counts.columns = ['is_anomaly', 'count']
    anomaly_counts['label'] = anomaly_counts['is_anomaly'].map({True: 'Anomaly', False: 'Normal'})
    
    fig_pie = px.pie(
        anomaly_counts, 
        values='count', 
        names='label', 
        title="Traffic Distribution",
        color='label',
        color_discrete_map={'Anomaly': 'red', 'Normal': 'blue'}
    )
    pie_placeholder.plotly_chart(fig_pie, use_container_width=True)
    
    # Update Log Table (Show last 10)
    cols = ['timestamp', 'source_ip', 'method', 'latency', 'packet_size', 'is_anomaly', 'recommendation']
    # Filter cols that exist
    cols = [c for c in cols if c in df.columns]
    
    log_placeholder.dataframe(
        df.tail(10)[cols]
        .style.applymap(lambda x: 'background-color: #ffcdd2' if x else '', subset=['is_anomaly'])
    )

if run_simulation:
    while True:
        traffic_data = generate_random_traffic()
        
        try:
            response = requests.post(f"{API_URL}/analyze", json=traffic_data, headers=HEADERS)
            if response.status_code == 200:
                result = response.json()
                traffic_data['is_anomaly'] = result['is_anomaly']
                traffic_data['score'] = result['anomaly_score']
                traffic_data['recommendation'] = result['recommendation']
                traffic_data['explanation'] = result['explanation']
                traffic_data['timestamp'] = time.time() # Client side timestamp
                
                # Add to history
                st.session_state.traffic_history.append(traffic_data)
                if len(st.session_state.traffic_history) > 100:
                    st.session_state.traffic_history.pop(0)
                
                # Update Chart
                df = pd.DataFrame(st.session_state.traffic_history)
                render_dashboard(df)
                
            else:
                st.error(f"API Error: {response.status_code}")
        except Exception as e:
            st.error(f"Connection Error: {e}")
            break
            
        time.sleep(1/simulation_speed)
else:
    if st.session_state.traffic_history:
        df = pd.DataFrame(st.session_state.traffic_history)
        render_dashboard(df)

# Feedback Section
st.header("Anomaly Feedback Loop")
st.write("Review detected anomalies and provide feedback to improve the model.")

if st.session_state.traffic_history:
    df_hist = pd.DataFrame(st.session_state.traffic_history)
    anomalies = df_hist[df_hist['is_anomaly'] == True]
    
    if not anomalies.empty:
        # Select an anomaly to review
        selected_idx = st.selectbox("Select Anomaly to Review", anomalies.index.tolist(), format_func=lambda x: f"Log #{x} - {anomalies.loc[x]['explanation']}")
        
        row = anomalies.loc[selected_idx]
        st.json(row.to_dict())
        
        col_f1, col_f2 = st.columns(2)
        with col_f1:
            if st.button("Confirm Anomaly"):
                # Send feedback
                payload = {"timestamp": row['timestamp'], "feedback": "anomaly"}
                requests.post(f"{API_URL}/feedback", json=payload, headers=HEADERS)
                st.success("Feedback recorded: Confirmed Anomaly")
                
        with col_f2:
            if st.button("Mark as False Positive"):
                payload = {"timestamp": row['timestamp'], "feedback": "normal"}
                requests.post(f"{API_URL}/feedback", json=payload, headers=HEADERS)
                st.info("Feedback recorded: False Positive")
    else:
        st.info("No anomalies detected in current session history.")

# Manual Test
st.header("Manual Inspection")
with st.form("manual_test"):
    src_ip = st.text_input("Source IP", "192.168.1.5")
    p_size = st.number_input("Packet Size", 0, 10000, 500)
    lat = st.number_input("Latency (ms)", 0.0, 1000.0, 50.0)
    url_len = st.number_input("URL Length", 1, 1000, 30)
    method = st.selectbox("Method", ["GET", "POST", "PUT", "DELETE"])
    shadow_mode_manual = st.checkbox("Shadow Mode", value=False)
    
    submitted = st.form_submit_button("Analyze")
    
    if submitted:
        data = {
            "source_ip": src_ip,
            "packet_size": p_size,
            "latency": lat,
            "url_length": url_len,
            "num_params": 0,
            "method": method,
            "protocol": "HTTP/1.1",
            "shadow_mode": shadow_mode_manual
        }
        try:
            res = requests.post(f"{API_URL}/analyze", json=data, headers=HEADERS).json()
            if res['is_anomaly']:
                st.error(f"Anomaly Detected!")
                st.write(f"**Explanation:** {res['explanation']}")
                st.write(f"**Recommendation:** {res['recommendation']}")
            else:
                st.success(f"Traffic Normal.")
        except:
            st.error("API Error")
