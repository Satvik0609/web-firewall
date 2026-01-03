#!/bin/bash

# Start the API in the background
echo "Starting API..."
uvicorn src.api.main:app --host 0.0.0.0 --port 8000 &

# Start the Dashboard
echo "Starting Dashboard..."
streamlit run src/dashboard/app.py --server.port 8501 --server.address 0.0.0.0
