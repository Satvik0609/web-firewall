import streamlit as st
import requests
import pandas as pd
import time
import plotly.express as px
import plotly.graph_objects as go
import numpy as np
from datetime import datetime, timedelta
import random

# Configuration
API_URL = "http://127.0.0.1:8000"

st.set_page_config(
    page_title="WAF ML Dashboard",
    layout="wide",
    initial_sidebar_state="expanded",
    page_icon="🛡️",
    menu_items={
        'Get Help': 'https://github.com/your-repo',
        'Report a bug': "https://github.com/your-repo/issues",
        'About': "# WAF ML Anomaly Detection Dashboard"
    }
)

# --- Custom CSS for Modern UI ---
st.markdown("""
<style>
    .main {
        background-color: #0E1117;
        color: #FAFAFA;
    }
    
    .css-1d391kg, [data-testid="stSidebarContent"] {
        background-color: #1E1E2E !important;
        border-right: 1px solid #2D3748;
    }
    
    .metric-card {
        background: linear-gradient(145deg, #1E1E2E, #2D2B42);
        border-radius: 16px;
        padding: 1.5rem;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);
        transition: all 0.3s ease;
        border: 1px solid #2D3748;
    }
    
    .metric-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 8px 25px rgba(0, 0, 0, 0.3);
    }
    
    .stButton>button {
        border-radius: 12px;
        padding: 0.5rem 1.5rem;
        font-weight: 600;
        transition: all 0.3s;
        background: linear-gradient(90deg, #4F46E5, #7C3AED);
        border: none;
    }
    
    .stButton>button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(79, 70, 229, 0.3);
    }
    
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    
    .stTabs [data-baseweb="tab"] {
        padding: 8px 16px;
        border-radius: 12px;
        transition: all 0.3s;
    }
    
    .stTabs [aria-selected="true"] {
        background-color: #4F46E5;
        color: white !important;
    }
    
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(20px); }
        to { opacity: 1; transform: translateY(0); }
    }
    
    .fade-in {
        animation: fadeIn 0.5s ease-out forwards;
    }
    
    .login-container {
        background: linear-gradient(145deg, #1E1E2E, #2D2B42);
        border-radius: 20px;
        padding: 3rem 2rem;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
        max-width: 500px;
        margin: 2rem auto;
        border: 1px solid #2D3748;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if "traffic_history" not in st.session_state:
    st.session_state.traffic_history = []

# --- LOGIN SYSTEM ---
def show_login():
    col = st.columns([1, 2, 1])[1]
    with col:
        st.markdown("""
        <div style="text-align: center; margin-bottom: 2rem;">
            <h1 style="color: #4F46E5; font-size: 2.5rem; margin-bottom: 0.5rem;">🛡️ WAF ML Dashboard</h1>
            <p style="color: #A0AEC0; margin-bottom: 2rem;">Advanced Anomaly Detection System</p>
        </div>
        """, unsafe_allow_html=True)
        
        with st.form("login_form"):
            username = st.text_input("👤 Username", placeholder="Enter your username")
            password = st.text_input("🔑 Password", type="password", placeholder="Enter your password")
            submitted = st.form_submit_button("Login", use_container_width=True)
            
            if submitted:
                with st.spinner("Authenticating..."):
                    try:
                        res = requests.post(
                            f"{API_URL}/token",
                            data={"username": username, "password": password}
                        )
                        if res.status_code == 200:
                            token_data = res.json()
                            st.session_state['token'] = token_data['access_token']
                            st.session_state['username'] = username
                            st.rerun()
                        else:
                            st.error("Invalid credentials. Please try again.")
                    except Exception as e:
                        st.error(f"Connection error: {str(e)}")

# --- HELPER FUNCTIONS ---
def generate_random_traffic():
    """Generate a single random traffic log."""
    is_attack = random.random() < 0.1
    ips = [f"192.168.1.{i}" for i in range(1, 10)] + ["10.0.0.666"]
    
    if is_attack:
        return {
            "source_ip": "10.0.0.666",
            "packet_size": random.randint(3000, 8000),
            "latency": random.uniform(100, 500),
            "url_length": random.randint(100, 300),
            "num_params": random.randint(5, 20),
            "method": random.choice(["POST", "PUT"]),
            "protocol": "HTTP/1.1",
            "lat": random.uniform(-90, 90),
            "lon": random.uniform(-180, 180)
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
            "lat": random.uniform(20, 50),
            "lon": random.uniform(-100, 20)
        }

def get_attack_reason(row):
    """Extract attack reason from explanation."""
    if not row.get('is_anomaly'): 
        return "Normal"
    exp = row.get('explanation', '')
    if "Packet Size" in exp: 
        return "DoS Attempt"
    if "Latency" in exp: 
        return "Slowloris"
    if "URL" in exp: 
        return "Injection"
    if "Bot" in exp or "Rate" in exp: 
        return "Botnet"
    return "Unknown Anomaly"

def render_dashboard(df, headers):
    """Render dashboard charts and tables."""
    if df.empty:
        st.info("Waiting for traffic data... Start simulation in sidebar.")
        return

    col1, col2 = st.columns([2, 1])
    
    # Chart 1: Threat Map
    with col1:
        st.markdown("### 🗺️ Live Threat Map")
        fig_map = px.scatter_geo(
            df,
            lat="lat",
            lon="lon",
            color="is_anomaly",
            hover_name="source_ip",
            size="packet_size",
            projection="natural earth",
            color_discrete_map={True: "#EF4444", False: "#10B981"},
            template="plotly_dark"
        )
        fig_map.update_layout(
            margin={"r":0,"t":30,"l":0,"b":0},
            height=400,
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)'
        )
        st.plotly_chart(fig_map, use_container_width=True)
    
    # Chart 2: Attack Classification
    with col2:
        st.markdown("### 📊 Traffic Classification")
        df['attack_type'] = df.apply(get_attack_reason, axis=1)
        attack_counts = df['attack_type'].value_counts().reset_index()
        attack_counts.columns = ['type', 'count']
        
        fig_pie = px.pie(
            attack_counts, 
            values='count', 
            names='type',
            color_discrete_map={
                'Normal': '#10B981', 
                'DoS Attempt': '#EF4444', 
                'Botnet': '#AB63FA',
                'Injection': '#FFA15A',
                'Slowloris': '#19D3F3'
            },
            hole=0.4
        )
        fig_pie.update_layout(
            height=400,
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='#E2E8F0'),
            margin=dict(l=20, r=20, t=30, b=20)
        )
        st.plotly_chart(fig_pie, use_container_width=True)
    
    # Anomaly Trend
    st.markdown("### 📈 Anomaly Trend")
    try:
        trend_df = df.copy()
        trend_df['count'] = trend_df['is_anomaly'].apply(lambda x: 1 if x else 0)
        trend_df['t'] = trend_df['timestamp']
        
        fig_trend = go.Figure()
        fig_trend.add_trace(go.Scatter(
            x=trend_df['t'],
            y=trend_df['count'],
            fill='tozeroy',
            line=dict(color='#EF4444', width=3),
            fillcolor='rgba(239, 68, 68, 0.1)',
            name='Anomalies'
        ))
        fig_trend.update_layout(
            height=300,
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='#E2E8F0'),
            xaxis=dict(gridcolor='#2D3748'),
            yaxis=dict(gridcolor='#2D3748'),
            margin=dict(l=20, r=20, t=30, b=20)
        )
        st.plotly_chart(fig_trend, use_container_width=True)
    except:
        pass
    
    # Recent Logs Table
    st.markdown("### 📋 Recent Traffic Logs")
    cols = ['timestamp', 'source_ip', 'method', 'attack_type', 'recommendation']
    cols = [c for c in cols if c in df.columns]
    
    st.dataframe(
        df.tail(10)[cols].sort_index(ascending=False),
        use_container_width=True,
        height=300
    )

def main_dashboard():
    """Main dashboard after login."""
    
    # Sidebar
    with st.sidebar:
        st.markdown("""
        <div style="text-align: center; margin-bottom: 2rem;">
            <h2 style="color: #4F46E5;">WAF ML Dashboard</h2>
            <p style="color: #A0AEC0; font-size: 0.9rem;">v1.0.0</p>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        # User info
        st.markdown(f"""
        <div style="margin-bottom: 1.5rem; padding: 1rem; background: rgba(79, 70, 229, 0.1); border-radius: 12px;">
            <p style="margin: 0; font-size: 0.9rem; color: #A0AEC0;">Logged in as</p>
            <p style="margin: 0; font-weight: 600; color: #4F46E5;">{st.session_state.get('username', '')}</p>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("---")
        st.subheader("⚙️ Control Panel")
        
        # Simulation Controls
        st.markdown("**Traffic Simulation**")
        simulation_speed = st.slider("Speed (req/sec)", 1, 10, 2)
        run_simulation = st.checkbox("Run Simulation", value=False)
        
        st.markdown("---")
        
        # Security Controls
        st.markdown("**Security Controls**")
        enable_shadow_mode = st.checkbox("Enable Shadow Mode")
        rate_limit_threshold = st.number_input("Rate Limit (req/min)", min_value=1, max_value=10000, value=100)
        
        if st.button("Apply Controls", use_container_width=True):
            headers = {"Authorization": f"Bearer {st.session_state['token']}"}
            try:
                requests.post(f"{API_URL}/config/shadow_mode", json={"enable": enable_shadow_mode}, headers=headers)
                requests.post(f"{API_URL}/config/rate_limit", json={"threshold": int(rate_limit_threshold)}, headers=headers)
                st.success("Controls applied")
            except:
                st.error("Failed to apply")
        
        st.markdown("---")
        
        # Model Training
        st.markdown("**Model Training**")
        model_type = st.selectbox("Model Type", ["isolation_forest", "autoencoder"])
        
        if st.button("Retrain Model", use_container_width=True):
            headers = {"Authorization": f"Bearer {st.session_state['token']}"}
            try:
                res = requests.post(f"{API_URL}/retrain", params={"model_type": model_type}, headers=headers).json()
                st.success(res.get('status', 'Retraining started'))
            except:
                st.error("Failed to retrain")
        
        st.markdown("---")
        
        # Alerts Configuration
        st.markdown("**Alert Configuration**")
        webhook_url = st.text_input("Webhook URL", placeholder="https://hooks.slack.com/...")
        
        if st.button("Update Alerts", use_container_width=True):
            headers = {"Authorization": f"Bearer {st.session_state['token']}"}
            try:
                res = requests.post(f"{API_URL}/config/alerts", json={"webhook_url": webhook_url}, headers=headers).json()
                st.success("Alerts configured")
            except:
                st.error("Failed to update")
        
        st.markdown("---")
        
        # Logout
        if st.button("🚪 Logout", use_container_width=True):
            del st.session_state['token']
            st.rerun()
    
    # Main Content
    headers = {"Authorization": f"Bearer {st.session_state['token']}"}
    
    st.title("🛡️ ML-Enabled WAF | Security Command Center")
    
    # Top Metrics
    st.markdown("### System Status")
    col1, col2, col3, col4 = st.columns(4)
    
    try:
        stats = requests.get(f"{API_URL}/stats", headers=headers).json()
        col1.metric("Model Status", stats.get("model_status", "Unknown"), delta="Active", delta_color="normal")
        col2.metric("Total Analyzed", stats.get("total_analyzed", 0))
        col3.metric("Anomalies Detected", stats.get("anomalies_detected", 0), delta_color="inverse")
        col4.metric("Active IPs", stats.get("active_ips", 0))
    except:
        col1.metric("API Status", "Offline", delta="Down", delta_color="inverse")
        st.error("Could not connect to API. Ensure `uvicorn src.api.main:app` is running.")
    
    st.markdown("---")
    
    # Tabs
    tab_monitor, tab_forensics, tab_test = st.tabs(["📊 Live Monitor", "🔍 Forensics", "🛠️ Manual Test"])
    
    # TAB 1: LIVE MONITOR
    with tab_monitor:
        st.subheader("Real-time Threat Intelligence")
        
        if run_simulation:
            while True:
                traffic_data = generate_random_traffic()
                
                try:
                    response = requests.post(f"{API_URL}/analyze", json=traffic_data, headers=headers)
                    if response.status_code == 200:
                        result = response.json()
                        traffic_data['is_anomaly'] = result['is_anomaly']
                        traffic_data['score'] = result['anomaly_score']
                        traffic_data['recommendation'] = result['recommendation']
                        traffic_data['explanation'] = result['explanation']
                        traffic_data['timestamp'] = time.strftime("%H:%M:%S")
                        
                        st.session_state.traffic_history.append(traffic_data)
                        if len(st.session_state.traffic_history) > 100:
                            st.session_state.traffic_history.pop(0)
                        
                        df = pd.DataFrame(st.session_state.traffic_history)
                        render_dashboard(df, headers)
                    else:
                        st.error(f"API Error: {response.status_code}")
                except Exception as e:
                    st.error(f"Connection Error: {e}")
                    break
                
                time.sleep(1/simulation_speed)
        else:
            if st.session_state.traffic_history:
                df = pd.DataFrame(st.session_state.traffic_history)
                render_dashboard(df, headers)
            else:
                render_dashboard(pd.DataFrame(), headers)
        
        # Data Export
        st.markdown("---")
        st.markdown("#### 📥 Data Export")
        col_e1, col_e2 = st.columns(2)
        
        with col_e1:
            if st.button("Download Logs (CSV)", use_container_width=True):
                try:
                    res = requests.get(f"{API_URL}/export/logs", params={"format": "csv", "limit": 1000}, headers=headers)
                    if res.status_code == 200:
                        st.download_button("Save CSV", data=res.text, file_name="traffic_logs.csv", use_container_width=True)
                except:
                    st.error("CSV export failed")
        
        with col_e2:
            if st.button("Download Logs (JSON)", use_container_width=True):
                try:
                    res = requests.get(f"{API_URL}/export/logs", params={"format": "json", "limit": 1000}, headers=headers)
                    if res.status_code == 200:
                        st.download_button("Save JSON", data=str(res.json()), file_name="traffic_logs.json", use_container_width=True)
                except:
                    st.error("JSON export failed")
    
    # TAB 2: FORENSICS
    with tab_forensics:
        st.subheader("Anomaly Feedback Loop")
        st.write("Review detected anomalies and provide feedback to improve the model.")
        
        if st.session_state.traffic_history:
            df_hist = pd.DataFrame(st.session_state.traffic_history)
            anomalies = df_hist[df_hist.get('is_anomaly', False) == True]
            
            if not anomalies.empty:
                selected_idx = st.selectbox("Select Anomaly to Review", anomalies.index.tolist(), 
                                           format_func=lambda x: f"Log #{x} - {anomalies.loc[x].get('explanation', 'N/A')}")
                
                row = anomalies.loc[selected_idx]
                st.json(row.to_dict())
                
                col_f1, col_f2 = st.columns(2)
                with col_f1:
                    if st.button("Confirm Anomaly", use_container_width=True):
                        payload = {"timestamp": time.time(), "feedback": "anomaly"}
                        requests.post(f"{API_URL}/feedback", json=payload, headers=headers)
                        st.success("Feedback recorded: Confirmed Anomaly")
                
                with col_f2:
                    if st.button("Mark as False Positive", use_container_width=True):
                        payload = {"timestamp": time.time(), "feedback": "normal"}
                        requests.post(f"{API_URL}/feedback", json=payload, headers=headers)
                        st.info("Feedback recorded: False Positive")
            else:
                st.info("No anomalies detected in current session history.")
        else:
            st.info("No data available.")
    
    # TAB 3: MANUAL TEST
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
            
            submitted = st.form_submit_button("Analyze Request", use_container_width=True)
            
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
                    res = requests.post(f"{API_URL}/analyze", json=data, headers=headers).json()
                    if res['is_anomaly']:
                        st.error(f"❌ Anomaly Detected!")
                        st.markdown(f"**Explanation:** `{res['explanation']}`")
                        st.markdown(f"**Recommendation:** `{res['recommendation']}`")
                    else:
                        st.success(f"✅ Traffic Normal")
                except:
                    st.error("API Error")

# Main App Entry Point
def main():
    if 'token' not in st.session_state:
        show_login()
    else:
        main_dashboard()

if __name__ == "__main__":
    main()