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

    def set_webhook(self, url):
        self.webhook_url = url
        self.enabled = bool(url)

    def send_alert(self, log_data, result):
        """
        Send an alert if the anomaly is severe.
        Runs asynchronously to not block the API.
        """
        if not self.enabled:
            return

        # Simple severity logic
        severity = "MEDIUM"
        if result['anomaly_score'] < -0.8: # IsolationForest scores are negative, lower is more anomalous
            severity = "HIGH"
        
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
