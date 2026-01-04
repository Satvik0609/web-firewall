from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.security import APIKeyHeader
from .rate_limiter import limiter, rate_limit_middleware
from .config import security_config
from typing import Optional

api_key_header = APIKeyHeader(name=security_config.API_KEY_HEADER, auto_error=True)

async def verify_api_key(api_key: str = Depends(api_key_header)):
    if api_key not in security_config.API_KEYS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API Key"
        )
    return api_key

def secure_application(app: FastAPI) -> FastAPI:
    # Add security middleware
    app.middleware("http")(rate_limit_middleware)
    
    # Add security dependencies to all routes
    app.dependency_overrides[verify_api_key] = verify_api_key
    
    # Add security headers
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        return response
    
    return app
