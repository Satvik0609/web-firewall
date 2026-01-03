from fastapi import FastAPI, HTTPException, Security, Depends
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
import pandas as pd
import numpy as np
import os
import joblib
from contextlib import asynccontextmanager
from typing import Optional
from src.ml_engine.model import AnomalyDetector
from src.ml_engine.preprocessor import TrafficPreprocessor
from src.utils.data_generator import generate_traffic_data
from src.utils.data_manager import DataManager
from src.utils.state_tracker import TrafficStateTracker
from src.utils.alerter import AlertManager

# Security
API_KEY_NAME = "X-API-Key"
API_KEY = "naval-academy-secret-key-2024" # In production, use os.getenv("API_KEY")
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)

async def get_api_key(api_key_header: str = Security(api_key_header)):
    if api_key_header == API_KEY:
        return api_key_header
    raise HTTPException(status_code=403, detail="Could not validate credentials")

# Global instances
model = AnomalyDetector()
preprocessor = TrafficPreprocessor()
data_manager = DataManager()
state_tracker = TrafficStateTracker(window_size=60)

# Baseline stats for explainability (simple mean/std)
baseline_stats = {}

def update_baseline(df):
    """Update baseline statistics for explainability."""
    global baseline_stats
    numeric_cols = ['packet_size', 'latency', 'url_length', 'num_params', 'request_rate_1min']
    baseline_stats = df[numeric_cols].mean().to_dict()
    baseline_stats.update({f"{c}_std": df[c].std() for c in numeric_cols})

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup logic
    global model, preprocessor
    
    # Check if model exists
    if os.path.exists(MODEL_PATH) and os.path.exists(PREPROCESSOR_PATH):
        print("Loading existing model...")
        model.load(MODEL_PATH)
        preprocessor.load(PREPROCESSOR_PATH)
        
        # Load data to update baseline
        df = data_manager.load_data()
        if df.empty:
             df = generate_traffic_data(n_samples=500)
        
        # Ensure 'request_rate_1min' is in df if loaded from old CSV
        if 'request_rate_1min' not in df.columns:
             # Default fallback for legacy data
             df['request_rate_1min'] = 10 
             
        update_baseline(df)
    else:
        print("Training new model on synthetic data...")
        df = generate_traffic_data(n_samples=2000)
        update_baseline(df)
        
        # Train preprocessor
        preprocessor.fit(df)
        X = preprocessor.transform(df)
        
        # Train model
        model.train(X)
        
        # Save
        model.save(MODEL_PATH)
        preprocessor.save(PREPROCESSOR_PATH)
        print("Model trained and saved.")
    
    yield
    # Shutdown logic (if any)

app = FastAPI(title="WAF ML Anomaly Detection Module", lifespan=lifespan)

# Paths
MODEL_PATH = "data/processed/model.joblib"
PREPROCESSOR_PATH = "data/processed/preprocessor.joblib"

class TrafficLog(BaseModel):
    source_ip: str # Added Source IP
    packet_size: int
    latency: float
    url_length: int
    num_params: int
    method: str
    protocol: str
    shadow_mode: bool = False # If True, result will always be 'normal' but anomaly score logged

class Feedback(BaseModel):
    timestamp: float
    feedback: str  # 'normal' or 'anomaly'

class AlertConfig(BaseModel):
    webhook_url: str

def explain_anomaly(log_dict):
    """
    Generate a human-readable explanation for the anomaly.
    Compares current values to baseline.
    """
    reasons = []
    
    # Check numeric deviations (Z-score like heuristic)
    if baseline_stats:
        if log_dict['packet_size'] > baseline_stats.get('packet_size', 0) + 2 * baseline_stats.get('packet_size_std', 1):
            reasons.append(f"Packet Size ({log_dict['packet_size']}) is unusually high")
        
        if log_dict['latency'] > baseline_stats.get('latency', 0) + 2 * baseline_stats.get('latency_std', 1):
            reasons.append(f"Latency ({log_dict['latency']}ms) is unusually high")
            
        if log_dict['url_length'] > baseline_stats.get('url_length', 0) + 2 * baseline_stats.get('url_length_std', 1):
            reasons.append(f"URL Length ({log_dict['url_length']}) is suspicious")

        if log_dict['request_rate_1min'] > baseline_stats.get('request_rate_1min', 0) + 2 * baseline_stats.get('request_rate_1min_std', 1):
            reasons.append(f"Request Rate ({log_dict['request_rate_1min']}/min) indicates Bot activity")
    
    # Fallback
    if not reasons:
        reasons.append("Unusual combination of parameters")
        
    return "; ".join(reasons)

@app.post("/analyze")
def analyze_traffic(log: TrafficLog, api_key: str = Depends(get_api_key)):
    """
    Analyze a traffic log for anomalies.
    """
    # 1. Update State & Get Rate Features
    state_features = state_tracker.update_and_get_features(log.source_ip)
    
    # 2. Combine Log Data + State Features
    log_dict = log.model_dump()
    log_dict.update(state_features)
    
    # Convert to DataFrame
    data = pd.DataFrame([log_dict])
    
    # Preprocess
    try:
        X = preprocessor.transform(data)
    except Exception as e:
        # Handle case where model expects features not present (e.g. model mismatch)
        raise HTTPException(status_code=500, detail=f"Preprocessing error: {str(e)}")
    
    # Predict
    # Isolation Forest: -1 is anomaly, 1 is normal
    prediction = model.predict(X)[0]
    score = model.score_samples(X)[0]
    
    is_anomaly = prediction == -1
    
    # Shadow Mode Logic: If enabled, suppress the anomaly alert to the client
    # but still log it as an anomaly internally if we wanted (or log as 'Shadow Block')
    # Here, we will just set is_anomaly to False in the response if shadow_mode is active,
    # but keep the original detection for logging purposes?
    # Usually Shadow Mode means: "Would have blocked, but allowed".
    
    recommendation = "None"
    explanation = "Normal traffic"
    
    if is_anomaly:
        explanation = explain_anomaly(log_dict)
        if "Packet Size" in explanation:
            recommendation = "Block IP: Potential DoS/Exfiltration"
        elif "Latency" in explanation:
            recommendation = "Rate Limit: Potential Slowloris/Timeout"
        elif "URL" in explanation:
            recommendation = "Block Request: Potential Injection/Overflow"
        elif "Bot" in explanation or "Rate" in explanation:
            recommendation = "CAPTCHA / Block IP: Bot Activity Detected"
        else:
            recommendation = "Flag for Manual Review"

    # Handle Shadow Mode
    if log.shadow_mode and is_anomaly:
        recommendation = f"[SHADOW MODE] Would have blocked: {recommendation}"
        # We don't change is_anomaly boolean so dashboard still sees it as anomaly,
        # but the recommendation tells the WAF (client) not to act yet.
        # OR, we return is_anomaly=False to the WAF so it doesn't block?
        # Let's return is_anomaly=True but recommendation clearly states Shadow Mode.

    result = {
        "is_anomaly": bool(is_anomaly),
        "anomaly_score": float(score),
        "recommendation": recommendation,
        "explanation": explanation,
        "source_ip": log.source_ip
    }
    
    # Log to persistent storage
    data_manager.log_traffic(log_dict, result)
    
    # Send alert if anomaly
    if is_anomaly:
        alerter.send_alert(log_dict, result)
    
    return result

@app.post("/config/alerts")
def configure_alerts(config: AlertConfig, api_key: str = Depends(get_api_key)):
    """
    Configure the webhook URL for alerts.
    """
    alerter.set_webhook(config.webhook_url)
    return {"status": "Alert configuration updated", "enabled": alerter.enabled}

@app.post("/feedback")
def submit_feedback(feedback: Feedback, api_key: str = Depends(get_api_key)):
    """
    Submit user feedback for a log entry.
    """
    success = data_manager.add_feedback(feedback.timestamp, feedback.feedback)
    if not success:
        raise HTTPException(status_code=404, detail="Log entry not found")
    return {"status": "Feedback recorded"}

@app.get("/stats")
def get_stats(api_key: str = Depends(get_api_key)):
    df = data_manager.load_data()
    total = len(df)
    anomalies = len(df[df['is_anomaly'] == True]) if total > 0 else 0
    
    return {
        "model_status": "Active",
        "last_trained": "Today",
        "total_analyzed": total,
        "anomalies_detected": anomalies,
        "active_ips": len(state_tracker.get_active_ips())
    }

@app.post("/retrain")
def retrain_model(model_type: str = "isolation_forest", api_key: str = Depends(get_api_key)):
    """
    Retrain the model using historical data + feedback + synthetic data.
    model_type: 'isolation_forest' or 'autoencoder'
    """
    # Load historical data
    real_data = data_manager.load_data(limit=5000)
    
    # Generate fresh synthetic data to maintain baseline knowledge
    synthetic_data = generate_traffic_data(n_samples=1000)
    
    if not real_data.empty:
        # Handle missing columns if upgrading
        if 'request_rate_1min' not in real_data.columns:
            real_data['request_rate_1min'] = 10
            
        combined_data = pd.concat([synthetic_data, real_data[real_data['user_feedback'] != 'anomaly']], ignore_index=True)
    else:
        combined_data = synthetic_data
        
    # Retrain
    global model, preprocessor
    
    # Initialize new model if type changed or just to be fresh
    if model.model_type != model_type:
        print(f"Switching model to {model_type}")
        model = AnomalyDetector(model_type=model_type)
    
    # Drop non-feature columns
    features = ['packet_size', 'latency', 'url_length', 'num_params', 'method', 'protocol', 'request_rate_1min']
    train_df = combined_data[features]
    
    preprocessor.fit(train_df)
    X = preprocessor.transform(train_df)
    model.train(X)
    
    model.save(MODEL_PATH)
    preprocessor.save(PREPROCESSOR_PATH)
    
    update_baseline(train_df)
    
    return {"status": "Model retrained successfully with new data"}
