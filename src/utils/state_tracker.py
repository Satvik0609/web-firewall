from collections import defaultdict
import time

class TrafficStateTracker:
    def __init__(self, window_size=60):
        """
        Tracks traffic state per IP.
        window_size: Time window in seconds to calculate rates.
        """
        self.window_size = window_size
        self.ip_history = defaultdict(list)
        self.blocked_ips = set()

    def update_and_get_features(self, source_ip, current_time=None):
        """
        Updates history for an IP and returns current rate features.
        """
        if current_time is None:
            current_time = time.time()
            
        # Add current request timestamp
        self.ip_history[source_ip].append(current_time)
        
        # Cleanup old requests outside window
        cutoff = current_time - self.window_size
        
        # Filter (keeping only recent)
        # Optimization: In high throughput, use a ring buffer or Redis. 
        # For this challenge/demo, list filtering is fine.
        self.ip_history[source_ip] = [t for t in self.ip_history[source_ip] if t > cutoff]
        
        request_count = len(self.ip_history[source_ip])
        
        # Calculate rate (requests per second roughly, or just count in window)
        # We'll use count in last 60s as a feature
        return {
            "request_rate_1min": request_count
        }

    def get_active_ips(self):
        return list(self.ip_history.keys())
