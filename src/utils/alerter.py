import requests
import json
import logging
import threading
from datetime import datetime

logger = logging.getLogger(__name__)

class AlertManager:
    def __init__(self, webhook_url=None):
        self.webhook_url = webhook_url
        self.enabled = False
        if webhook_url:
            self.enabled = True
        self._last_sent = {}
        self.cooldown_seconds = 60

    def set_webhook(self, url):
        self.webhook_url = url
        self.enabled = bool(url)
    
    def set_cooldown(self, seconds):
        self.cooldown_seconds = max(0, int(seconds))

    def send_alert(self, log_data, result):
        """
        Send an alert if the anomaly is severe.
        Runs asynchronously to not block the API.
        """
        if not self.enabled:
            return
        
        # Cooldown dedupe per IP
        ip = log_data.get('source_ip')
        now = datetime.now().timestamp()
        last = self._last_sent.get(ip, 0)
        if now - last < self.cooldown_seconds:
            return
        self._last_sent[ip] = now

        # Simple severity logic
        severity = "LOW"
        recommendation = result.get('recommendation', '') or ''
        score = result.get('anomaly_score', 0)
        if "Block" in recommendation or score < -0.8:
            severity = "HIGH"
        elif "Rate Limit" in recommendation or score < -0.5:
            severity = "MEDIUM"
        
        # For Autoencoder (positive scores usually), we'll need to adjust, but let's assume generic logic for now
        # or pass severity from outside.
        
        # Construct payload
        payload = {
            "text": f"🚨 **WAF Anomaly Detected** 🚨\n\n"
                    f"**Severity:** {severity}\n"
                    f"**IP:** {log_data.get('source_ip')}\n"
                    f"**Reason:** {result.get('explanation')}\n"
                    f"**Action:** {result.get('recommendation')}\n"
                    f"**Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        }

        # Send in background thread
        thread = threading.Thread(target=self._post_to_webhook, args=(payload,))
        thread.start()

    def _post_to_webhook(self, payload):
        try:
            response = requests.post(
                self.webhook_url, 
                data=json.dumps(payload),
                headers={'Content-Type': 'application/json'},
                timeout=5
            )
            if response.status_code != 200:
                logger.error(f"Failed to send alert: {response.status_code} {response.text}")
        except Exception as e:
            logger.error(f"Alert system error: {e}")
