import requests
import time
import sys

API_URL = "http://127.0.0.1:8000"

def test_features():
    print("Testing Advanced Features...")
    
    # 1. Login
    print("[1] Testing Login (JWT)...")
    try:
        res = requests.post(f"{API_URL}/token", data={"username": "admin", "password": "admin123"})
        if res.status_code != 200:
            print(f"FAILED: Login failed. Status: {res.status_code}, Body: {res.text}")
            return
        token = res.json()["access_token"]
        print("PASSED: Got Access Token")
    except Exception as e:
        print(f"FAILED: Connection error: {e}")
        return

    headers = {"Authorization": f"Bearer {token}"}

    # 2. RBAC / Config
    print("[2] Testing RBAC (Admin Config)...")
    try:
        res = requests.post(f"{API_URL}/config/shadow_mode", json={"enable": True}, headers=headers)
        if res.status_code == 200 and res.json()["enabled"] == True:
            print("PASSED: Admin can configure shadow mode")
        else:
            print(f"FAILED: Admin config failed. Status: {res.status_code}")
    except Exception as e:
        print(f"FAILED: {e}")

    # 3. Metrics
    print("[3] Testing Prometheus Metrics...")
    try:
        res = requests.get(f"{API_URL}/metrics")
        if res.status_code == 200 and "waf_http_requests_total" in res.text:
            print("PASSED: Metrics endpoint active")
        else:
            print(f"FAILED: Metrics endpoint missing or empty. Status: {res.status_code}")
    except Exception as e:
        print(f"FAILED: {e}")

if __name__ == "__main__":
    # Wait for API to start if running in parallel
    time.sleep(5) 
    test_features()
