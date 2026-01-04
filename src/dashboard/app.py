import streamlit as st
import requests
import pandas as pd
import time
import plotly.express as px
import random
import plotly.graph_objects as go

# Configuration
API_URL = "http://127.0.0.1:8000"

st.set_page_config(
    page_title="WAF ML Anomaly Detection",
    layout="wide",
    initial_sidebar_state="expanded",
    page_icon="🛡️"
)

# Login System
if 'token' not in st.session_state:
    st.title("🔐 WAF Dashboard Login")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")
        
        if submitted:
            try:
                res = requests.post(f"{API_URL}/token", data={"username": username, "password": password})
                if res.status_code == 200:
                    token_data = res.json()
                    st.session_state['token'] = token_data['access_token']
                    st.session_state['username'] = username
                    st.rerun()
                else:
                    st.error(f"Invalid credentials ({res.status_code}): {res.text}")
            except Exception as e:
                st.error(f"Connection failed: {e}")
    st.stop()

# Authenticated Session
HEADERS = {"Authorization": f"Bearer {st.session_state['token']}"}

# Logout
st.sidebar.write(f"Logged in as: **{st.session_state['username']}**")
if st.sidebar.button("Logout"):
    del st.session_state['token']
    st.rerun()

# --- CSS for "Pro" Look ---
st.markdown("""
<style>
    .metric-card {
        background-color: #1e1e1e;
        border: 1px solid #333;
        padding: 20px;
        border-radius: 10px;
        text-align: center;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 24px;
    }
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        white-space: pre-wrap;
        background-color: #0e1117;
        border-radius: 4px 4px 0px 0px;
        gap: 1px;
        padding-top: 10px;
        padding-bottom: 10px;
    }
    h1 {
        text-align: center;
        color: #4CAF50;
    }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ ML-Enabled WAF | Security Command Center")

# Sidebar for controls
st.sidebar.header("Control Panel")
simulation_speed = st.sidebar.slider("Simulation Speed (requests/sec)", 1, 10, 2)
run_simulation = st.sidebar.checkbox("Run Traffic Simulation")

enable_shadow_mode = st.sidebar.checkbox("Enable Shadow Mode (Global)")
rate_limit_threshold = st.sidebar.number_input("Rate Limit Threshold (req/min)", min_value=1, max_value=10000, value=100)
if st.sidebar.button("Apply Security Controls"):
    try:
        requests.post(f"{API_URL}/config/shadow_mode", json={"enable": enable_shadow_mode}, headers=HEADERS)
        requests.post(f"{API_URL}/config/rate_limit", json={"threshold": int(rate_limit_threshold)}, headers=HEADERS)
        st.sidebar.success("Security controls applied")
    except:
        st.sidebar.error("Failed to apply controls")

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
        
st.sidebar.markdown("---")
st.sidebar.subheader("Blocklist")
try:
    bl = requests.get(f"{API_URL}/blocklist", headers=HEADERS).json().get("blocked_ips", [])
    st.sidebar.write(f"Blocked IPs: {len(bl)}")
    for ip in bl[:10]:
        cols = st.sidebar.columns([2,1])
        cols[0].write(ip)
        if cols[1].button("Unblock", key=f"unblock-{ip}"):
            try:
                requests.post(f"{API_URL}/blocklist/remove", params={"ip": ip}, headers=HEADERS)
                st.sidebar.success(f"Unblocked {ip}")
            except:
                st.sidebar.error("Failed")
    new_ip = st.sidebar.text_input("Add IP to blocklist", "")
    if st.sidebar.button("Block IP"):
        try:
            requests.post(f"{API_URL}/blocklist/add", params={"ip": new_ip}, headers=HEADERS)
            st.sidebar.success(f"Blocked {new_ip}")
        except:
            st.sidebar.error("Failed to block")
except:
    st.sidebar.info("Blocklist unavailable")

# --- TOP METRICS (Industry Standard Placement) ---
st.markdown("### System Status")
col1, col2, col3, col4 = st.columns(4)

try:
    stats = requests.get(f"{API_URL}/stats", headers=HEADERS).json()
    col1.metric("Model Status", stats.get("model_status", "Unknown"), delta="Active", delta_color="normal")
    col2.metric("Total Analyzed", stats.get("total_analyzed", 0))
    col3.metric("Anomalies Detected", stats.get("anomalies_detected", 0), delta_color="inverse")
    col4.metric("Active IPs", stats.get("active_ips", 0))
except:
    col1.metric("API Status", "Offline", delta="Down", delta_color="inverse")
    st.error("Could not connect to API. Please ensure `uvicorn src.api.main:app` is running.")


# --- MAIN TABS ---
tab_monitor, tab_forensics, tab_test = st.tabs(["📊 Live Monitor", "🔍 Forensics & Feedback", "🛠️ Manual Test"])

# --- TAB 1: LIVE MONITOR ---
with tab_monitor:
    st.subheader("Real-time Threat Intelligence")
    
    # Placeholders
    col_map, col_pie = st.columns([2, 1])
    with col_map:
        map_placeholder = st.empty()
    with col_pie:
        pie_placeholder = st.empty()

    st.markdown("### Recent Traffic Logs")
    log_placeholder = st.empty()
    st.markdown("### Anomaly Trend")
    trend_placeholder = st.empty()

# --- HELPER FUNCTIONS ---
if "traffic_history" not in st.session_state:
    st.session_state.traffic_history = []

def generate_random_traffic():
    """Generate a single random traffic log."""
    is_attack = random.random() < 0.1
    # Random IP pool (Simulated Geo)
    ips = [f"192.168.1.{i}" for i in range(1, 10)] + ["10.0.0.666"] # 666 is bot
    
    if is_attack:
        return {
            "source_ip": "10.0.0.666",
            "packet_size": random.randint(3000, 8000),
            "latency": random.uniform(100, 500),
            "url_length": random.randint(100, 300),
            "num_params": random.randint(5, 20),
            "method": random.choice(["POST", "PUT"]),
            "protocol": "HTTP/1.1",
            "lat": random.uniform(-90, 90), # Sim Geo
            "lon": random.uniform(-180, 180) # Sim Geo
        }
    else:
        return {
            "source_ip": random.choice(ips),
            "packet_size": random.randint(200, 1000),
            "latency": random.uniform(20, 100),
            "url_length": random.randint(10, 50),
            "num_params": random.randint(0, 5),
            "method": random.choice(["GET", "POST"]),
            "protocol": "HTTP/2",
            "lat": random.uniform(20, 50), # Sim Geo (US/Europe)
            "lon": random.uniform(-100, 20)
        }

def render_dashboard(df):
    if df.empty:
        map_placeholder.info("Waiting for traffic data... Start simulation in sidebar.")
        return

    # Chart 1: Threat Map (Scatter Geo)
    # Simulating a "Threat Map" - usually requires real IP geolocation
    fig_map = px.scatter_geo(
        df,
        lat="lat",
        lon="lon",
        color="is_anomaly",
        hover_name="source_ip",
        size="packet_size",
        projection="natural earth",
        title="Live Threat Map (Source IPs)",
        color_discrete_map={True: "red", False: "#00CC96"},
        template="plotly_dark"
    )
    fig_map.update_layout(margin={"r":0,"t":30,"l":0,"b":0})
    map_placeholder.plotly_chart(fig_map, use_container_width=True)
    
    # Chart 2: Attack Classification (Pie)
    # Extract "Reason" from explanation for classification
    def get_reason(row):
        if not row['is_anomaly']: return "Normal"
        exp = row['explanation']
        if "Packet Size" in exp: return "DoS Attempt"
        if "Latency" in exp: return "Slowloris"
        if "URL" in exp: return "Injection"
        if "Bot" in exp or "Rate" in exp: return "Botnet"
        return "Unknown Anomaly"

    df['attack_type'] = df.apply(get_reason, axis=1)
    
    attack_counts = df['attack_type'].value_counts().reset_index()
    attack_counts.columns = ['type', 'count']
    
    fig_pie = px.pie(
        attack_counts, 
        values='count', 
        names='type', 
        title="Traffic Classification",
        color='type',
        color_discrete_map={
            'Normal': '#00CC96', 
            'DoS Attempt': '#EF553B', 
            'Botnet': '#AB63FA',
            'Injection': '#FFA15A',
            'Slowloris': '#19D3F3'
        },
        hole=0.4,
        template="plotly_dark"
    )
    pie_placeholder.plotly_chart(fig_pie, use_container_width=True)
    
    # Trend: anomalies over time (session)
    try:
        trend_df = df.copy()
        trend_df['count'] = trend_df['is_anomaly'].apply(lambda x: 1 if x else 0)
        trend_df['t'] = trend_df['timestamp']
        fig_trend = px.line(trend_df, x='t', y='count', title="Anomaly Trend", template="plotly_dark")
        trend_placeholder.plotly_chart(fig_trend, use_container_width=True)
    except:
        pass
    
    # Update Log Table (Show last 10)
    cols = ['timestamp', 'source_ip', 'method', 'attack_type', 'recommendation']
    # Filter cols that exist
    cols = [c for c in cols if c in df.columns]
    
    log_placeholder.dataframe(
        df.tail(10)[cols].sort_index(ascending=False),
        use_container_width=True
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
                traffic_data['timestamp'] = time.strftime("%H:%M:%S")
                
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
    else:
        render_dashboard(pd.DataFrame())
        
# Export data
st.markdown("---")
st.markdown("#### Data Export")
col_e1, col_e2 = st.columns(2)
with col_e1:
    if st.button("Download Logs (CSV)"):
        try:
            res = requests.get(f"{API_URL}/export/logs", params={"format": "csv", "limit": 1000}, headers=HEADERS)
            if res.status_code == 200:
                st.download_button("Save CSV", data=res.text, file_name="traffic_logs.csv")
        except:
            st.error("CSV export failed")
with col_e2:
    if st.button("Download Logs (JSON)"):
        try:
            res = requests.get(f"{API_URL}/export/logs", params={"format": "json", "limit": 1000}, headers=HEADERS)
            if res.status_code == 200:
                st.download_button("Save JSON", data=str(res.json()), file_name="traffic_logs.json")
        except:
            st.error("JSON export failed")

# --- TAB 2: FORENSICS ---
with tab_forensics:
    st.subheader("Anomaly Feedback Loop")
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
                    # Use current time as mock timestamp since we store formatted string
                    payload = {"timestamp": time.time(), "feedback": "anomaly"}
                    requests.post(f"{API_URL}/feedback", json=payload, headers=HEADERS)
                    st.success("Feedback recorded: Confirmed Anomaly")
                    
            with col_f2:
                if st.button("Mark as False Positive"):
                    payload = {"timestamp": time.time(), "feedback": "normal"}
                    requests.post(f"{API_URL}/feedback", json=payload, headers=HEADERS)
                    st.info("Feedback recorded: False Positive")
        else:
            st.info("No anomalies detected in current session history.")
    else:
        st.info("No data available.")

# --- TAB 3: MANUAL TEST ---
with tab_test:
    st.subheader("Manual Inspection")
    with st.form("manual_test"):
        col_m1, col_m2 = st.columns(2)
        with col_m1:
            src_ip = st.text_input("Source IP", "192.168.1.5")
            p_size = st.number_input("Packet Size", 0, 10000, 500)
            lat = st.number_input("Latency (ms)", 0.0, 1000.0, 50.0)
        with col_m2:
            url_len = st.number_input("URL Length", 1, 1000, 30)
            method = st.selectbox("Method", ["GET", "POST", "PUT", "DELETE"])
            shadow_mode_manual = st.checkbox("Shadow Mode", value=False)
        
        submitted = st.form_submit_button("Analyze Request")
        
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
                    st.error(f"❌ Anomaly Detected!")
                    st.markdown(f"**Explanation:** `{res['explanation']}`")
                    st.markdown(f"**Recommendation:** `{res['recommendation']}`")
                else:
                    st.success(f"✅ Traffic Normal")
            except:
                st.error("API Error")
