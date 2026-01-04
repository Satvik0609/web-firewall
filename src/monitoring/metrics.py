from prometheus_client import Counter, Histogram, Gauge

# Request Metrics
REQUEST_COUNT = Counter(
    "waf_http_requests_total",
    "Total number of HTTP requests processed",
    ["method", "endpoint", "status"]
)

REQUEST_LATENCY = Histogram(
    "waf_request_processing_seconds",
    "Time spent processing request",
    ["endpoint"]
)

# ML Metrics
ANOMALY_SCORE = Histogram(
    "waf_anomaly_score",
    "Distribution of anomaly scores"
)

ANOMALIES_DETECTED = Counter(
    "waf_anomalies_detected_total",
    "Total number of anomalies detected",
    ["type"]
)

MODEL_PREDICTION_LATENCY = Histogram(
    "waf_model_prediction_seconds",
    "Time spent on model inference"
)

# System Metrics
BLOCKED_IPS_COUNT = Gauge(
    "waf_blocked_ips_total",
    "Current number of blocked IPs"
)
