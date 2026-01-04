# ML-Enabled Network Anomaly Detection Module

## Overview
This project is a Machine Learning Enabled Network Anomaly Detection Module designed for integration with Web Application Firewalls (WAF). It acts as an intelligent layer that inspects traffic, detects zero-day attacks and bots using unsupervised learning, and allows for safe testing via Shadow Mode.

## Key Features
1.  **Dual ML Engines**:
    *   **Isolation Forest**: Efficient anomaly detection for general outliers.
    *   **Autoencoder**: Deep learning model for detecting complex non-linear attack patterns.
2.  **Shadow Mode**: Safely test the system in production. It flags what *would* have been blocked without actually blocking traffic.
3.  **Real-Time Alerting**: Integrated webhook support (Slack/Discord) for high-severity anomaly notifications.
4.  **Stateful Bot Detection**: Tracks IP request rates in real-time to identify high-frequency bot attacks.
5.  **Database Agnostic**: Built with SQLAlchemy. Uses **SQLite** by default (zero setup) but is ready for **PostgreSQL** in production.
6.  **Interactive Dashboard**: Streamlit GUI for monitoring, simulation, retraining, and configuration.

## external APIs & Cost
*   **Is it free?** **YES**. This project uses 100% open-source libraries (`scikit-learn`, `fastapi`, `streamlit`, `sqlite`). It runs entirely on your local machine or server. You do not need to pay for any API tokens or cloud services.
*   **External APIs Used**: None for the core logic.
    *   *Optional*: You can configure an external **Webhook URL** (e.g., Slack Incoming Webhook) for alerts, but this is not required for the system to function.

## Setup & Running

### Prerequisites
*   Python 3.9+
*   pip

### Option 1: Quick Start (Local)
1.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```
2.  **Start the API Server** (Terminal 1):
    ```bash
    uvicorn src.api.main:app --reload
    ```
    *   The API will run at `http://127.0.0.1:8000`
3.  **Start the Dashboard** (Terminal 2):
    ```bash
    streamlit run src/dashboard/app.py
    ```
    *   The Dashboard will open in your browser at `http://localhost:8501`

### Option 2: Docker
1.  **Build the image**:
    ```bash
    docker build -t waf-ml-module .
    ```
2.  **Run the container**:
    ```bash
    docker run -p 8000:8000 -p 8501:8501 waf-ml-module
    ```

## Usage Guide

### 1. Dashboard Control Panel
*   **Traffic Simulation**: Toggle "Run Traffic Simulation" in the sidebar to see the system analyze generated traffic.
*   **Shadow Mode**: Enable "Shadow Mode" to see recommendations without "blocking" actions.
*   **Model Selection**: Choose between `isolation_forest` (fast) or `autoencoder` (deep) and click "Retrain Model".
*   **Alerts**: Paste a Slack/Discord Webhook URL to receive notifications.

### 2. API Integration
The API is protected by an API Key.
*   **Header**: `X-API-Key: naval-academy-secret-key-2024`
*   **Endpoints**:
    *   `POST /analyze`: Analyze a single request log.
    *   `POST /retrain`: Trigger model retraining.
    *   `POST /feedback`: Submit feedback (False Positive/Confirmed Anomaly).

## Architecture
-   **ML Engine**: `src/ml_engine` - Scikit-learn & Neural Network models.
-   **API**: `src/api` - FastAPI with Pydantic validation.
-   **Data Layer**: `src/database.py` & `src/models.py` - SQLAlchemy ORM.
-   **Utils**: `src/utils/alerter.py` (Async alerts), `state_tracker.py` (Bot detection).

## Testing
Run the full integration test suite:
```bash
pytest tests/test_integration.py
```
