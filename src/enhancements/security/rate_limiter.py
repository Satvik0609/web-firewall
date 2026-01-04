from fastapi import Request, HTTPException, status
from fastapi.middleware import Middleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)

async def rate_limit_middleware(request: Request, call_next):
    try:
        response = await limiter.check(request)
    except RateLimitExceeded as exc:
        return await _rate_limit_exceeded_handler(request, exc)
    return await call_next(request)

def get_security_middleware():
    return [
        Middleware(
            TrustedHostMiddleware,
            allowed_hosts=["*"],  # In production, replace with actual hosts
        )
    ]
