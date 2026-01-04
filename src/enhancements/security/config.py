from pydantic import BaseSettings

class SecurityConfig(BaseSettings):
    # API Security
    API_KEY_HEADER: str = "X-API-Key"
    API_KEYS: list = ["naval-academy-secret-key-2024"]  # In production, use environment variables
    
    # Rate Limiting
    RATE_LIMIT: str = "100/minute"
    
    # CORS
    ALLOWED_ORIGINS: list = ["*"]  # Restrict in production
    
    # Request Validation
    MAX_REQUEST_SIZE: int = 1024 * 1024  # 1MB
    
    class Config:
        env_file = ".env"

security_config = SecurityConfig()
