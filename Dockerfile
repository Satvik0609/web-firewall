# Use official Python runtime as a parent image
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies (needed for some python packages like numpy/scikit-learn on slim)
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Create directory for data
RUN mkdir -p data/processed data/raw

# Expose ports for API (8000) and Dashboard (8501)
EXPOSE 8000
EXPOSE 8501

# Copy a script to run both services
COPY start.sh .
RUN chmod +x start.sh

# Default command
CMD ["./start.sh"]
