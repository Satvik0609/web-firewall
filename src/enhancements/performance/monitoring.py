import time
from fastapi import Request, Response
from fastapi.routing import APIRoute
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from starlette.middleware.base import BaseHTTPMiddleware
from typing import Callable, Awaitable

# Metrics
REQUEST_COUNT = Counter(
    'http_requests_total',
    'Total HTTP Requests',
    ['method', 'endpoint', 'http_status']
)

REQUEST_LATENCY = Histogram(
    'http_request_duration_seconds',
    'HTTP Request latency',
    ['method', 'endpoint']
)

class PrometheusMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        method = request.method
        endpoint = request.url.path
        
        start_time = time.time()
        
        try:
            response = await call_next(request)
            status_code = response.status_code
        except Exception as e:
            status_code = 500
            raise e
        finally:
            process_time = time.time() - start_time
            
            REQUEST_COUNT.labels(
                method=method,
                endpoint=endpoint,
                http_status=status_code
            ).inc()
            
            REQUEST_LATENCY.labels(
                method=method,
                endpoint=endpoint
            ).observe(process_time)
        
        return response

def setup_metrics(app: FastAPI):
    app.add_middleware(PrometheusMiddleware)
    
    @app.get("/metrics")
    async def metrics():
        return Response(
            content=generate_latest(),
            media_type=CONTENT_TYPE_LATEST
        )
