# ML-Enabled Network Anomaly Detection Module

## Overview
This project is a Machine Learning Enabled Network Anomaly Detection Module designed for integration with Web Application Firewalls (WAF). It aims to detect anomalies, discover new attacks, and autonomously recommend security policies by combining traditional rule-based filtering with intelligent ML-driven analysis.

## Key Features
1.  **ML-Module**: Inspects HTTP(S) traffic, performs network baselining, behavioral analysis, and anomaly detection.
2.  **Adaptive Anomaly Detection**: Supports supervised and unsupervised learning to identify malicious behavior.
3.  **Stateful Bot Detection**: Tracks IP request rates to identify high-frequency bot attacks.
4.  **Automated Security Rule Recommendation**: Converts ML insights into human-readable security rules.
5.  **Dashboard**: A user-friendly GUI for administrators to view reports, approve recommendations, and manage feedback.
6.  **Continuous Learning**: Feedback loop to refine model accuracy over time.

## Architecture
-   **ML Engine**: `src/ml_engine` - Isolation Forest model with stateful feature engineering.
-   **API Service**: `src/api` - FastAPI application for WAF integration.
-   **Dashboard**: `src/dashboard` - Streamlit application.
-   **State Tracker**: `src/utils/state_tracker.py` - In-memory request rate tracking.

## Setup & Running

### Option 1: Local Python Environment
1.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
2.  Run the API (Terminal 1):
    ```bash
    uvicorn src.api.main:app --reload
    ```
3.  Run the Dashboard (Terminal 2):
    ```bash
    streamlit run src/dashboard/app.py
    ```

### Option 2: Docker
1.  Build the image:
    ```bash
    docker build -t waf-ml-module .
    ```
2.  Run the container:
    ```bash
    docker run -p 8000:8000 -p 8501:8501 waf-ml-module
    ```
    -   API: `http://localhost:8000`
    -   Dashboard: `http://localhost:8501`

## Usage Guide
1.  **Dashboard**: Open the dashboard to view real-time traffic simulation.
2.  **Simulation**: Enable "Run Traffic Simulation" to see normal vs. anomalous traffic (including Bots).
3.  **Feedback**: Use the "Anomaly Feedback Loop" section to confirm or reject anomalies, then click "Retrain Model" to update the system.
4.  **API Integration**: Send POST requests to `/analyze` with traffic metadata.

## Security
The API is protected by an API Key.
-   **Default Key**: `naval-academy-secret-key-2024`
-   **Header**: `X-API-Key: naval-academy-secret-key-2024`

## Testing
Run integration tests:
```bash
python tests/test_integration.py
```
