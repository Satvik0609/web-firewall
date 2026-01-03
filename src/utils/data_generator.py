import pandas as pd
import numpy as np
import random

def generate_traffic_data(n_samples=1000, anomaly_ratio=0.05):
    """
    Generate synthetic network traffic data.
    Now includes source_ip and request patterns.
    """
    data = []
    
    methods = ['GET', 'POST', 'PUT', 'DELETE']
    protocols = ['HTTP/1.1', 'HTTP/2', 'HTTPS']
    
    # Simulate a set of IPs
    normal_ips = [f"192.168.1.{i}" for i in range(1, 20)]
    bot_ips = [f"10.0.0.{i}" for i in range(1, 5)]
    
    for _ in range(n_samples):
        is_anomaly = random.random() < anomaly_ratio
        
        if is_anomaly:
            # Anomaly Type 1: High Latency/Packet (DoS or Exfiltration)
            # Anomaly Type 2: High Rate (Bot)
            anomaly_type = random.choice(['volume', 'bot'])
            
            if anomaly_type == 'bot':
                source_ip = random.choice(bot_ips)
                # Bot traffic might look normal per request but high rate (handled by state tracker)
                # But to simulate training data which is a snapshot, we need to inject the 'rate' feature directly
                # assuming the state tracker would have seen it.
                request_rate_1min = int(np.random.normal(100, 20)) # High rate
                packet_size = int(np.random.normal(500, 200)) # Normal size
                latency = np.random.normal(50, 20)
                method = 'POST'
                url_length = int(np.random.normal(30, 10))
                num_params = int(np.random.normal(2, 1))
                
            else: # Volume
                source_ip = random.choice(normal_ips) # Compromised host?
                packet_size = int(np.random.normal(5000, 2000))
                latency = np.random.normal(500, 100) 
                request_rate_1min = int(np.random.normal(10, 5)) # Normal rate
                url_length = int(np.random.normal(200, 50))
                num_params = int(np.random.normal(10, 5))
                method = random.choice(['POST', 'PUT'])
        else:
            # Normal
            source_ip = random.choice(normal_ips)
            packet_size = int(np.random.normal(500, 200))
            latency = np.random.normal(50, 20)
            request_rate_1min = int(np.random.normal(5, 2)) # Low rate
            url_length = int(np.random.normal(30, 10))
            num_params = int(np.random.normal(2, 1))
            method = random.choice(['GET', 'POST'])
            
        # Ensure non-negative
        packet_size = max(0, packet_size)
        latency = max(0, latency)
        url_length = max(1, url_length)
        num_params = max(0, num_params)
        request_rate_1min = max(0, request_rate_1min)
        
        data.append({
            'source_ip': source_ip,
            'packet_size': packet_size,
            'latency': latency,
            'url_length': url_length,
            'num_params': num_params,
            'method': method,
            'protocol': random.choice(protocols),
            'request_rate_1min': request_rate_1min,
            'label': 1 if is_anomaly else 0
        })
        
    return pd.DataFrame(data)
