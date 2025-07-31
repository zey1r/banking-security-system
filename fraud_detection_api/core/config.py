"""
Core configuration settings for the fraud detection system.
"""

from typing import Any, Dict, List, Optional, Union
from decimal import Decimal
import os
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings with validation and type checking."""
    
    # API Settings
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "Banking Fraud Detection AI"
    VERSION: str = "1.0.0"
    DESCRIPTION: str = "Enterprise-grade fraud detection system"
    
    # Server Settings
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = False
    RELOAD: bool = False
    
    # Security
    SECRET_KEY: str = Field(default="default-secret-key-32-chars-long", min_length=32)
    JWT_SECRET_KEY: str = Field(default="default-jwt-secret-key-32-chars", min_length=32)
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days
    
    # Database
    DATABASE_URL: str = Field(default="sqlite:///./fraud_detection.db")
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 20
    DATABASE_POOL_TIMEOUT: int = 30
    
    # Redis Cache
    REDIS_URL: str = "redis://localhost:6379"
    REDIS_EXPIRE_SECONDS: int = 3600
    
    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "https://localhost:3000"]
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: List[str] = ["*"]
    CORS_ALLOW_HEADERS: List[str] = ["*"]
    
    # Rate Limiting
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW: int = 60  # seconds
    
    # Machine Learning
    MODEL_PATH: str = "./models"
    MODEL_VERSION: str = "1.0.0"
    FEATURE_STORE_PATH: str = "./features"
    RETRAIN_INTERVAL_HOURS: int = 24
    MODEL_DRIFT_THRESHOLD: float = 0.05
    
    # Fraud Detection Thresholds
    FRAUD_THRESHOLD_LOW: float = 0.3
    FRAUD_THRESHOLD_MEDIUM: float = 0.6
    FRAUD_THRESHOLD_HIGH: float = 0.8
    FRAUD_THRESHOLD_CRITICAL: float = 0.9
    
    # Transaction Limits
    MAX_TRANSACTION_AMOUNT: Decimal = Decimal("100000.00")
    DAILY_TRANSACTION_LIMIT: Decimal = Decimal("50000.00")
    SUSPICIOUS_AMOUNT_THRESHOLD: Decimal = Decimal("10000.00")
    
    # Monitoring & Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"
    ENABLE_METRICS: bool = True
    METRICS_PATH: str = "/metrics"
    HEALTH_CHECK_PATH: str = "/health"
    
    # External Services
    NOTIFICATION_SERVICE_URL: Optional[str] = None
    WEBHOOK_SECRET: Optional[str] = None
    
    # Compliance & Audit
    AUDIT_LOG_RETENTION_DAYS: int = 2555  # 7 years
    DATA_RETENTION_DAYS: int = 2555
    ENABLE_AUDIT_TRAIL: bool = True
    
    # Performance
    MAX_BATCH_SIZE: int = 1000
    ASYNC_POOL_SIZE: int = 10
    REQUEST_TIMEOUT_SECONDS: int = 30
    
    # Feature Engineering
    ENABLE_BEHAVIORAL_FEATURES: bool = True
    ENABLE_TEMPORAL_FEATURES: bool = True
    ENABLE_GEOLOCATION_FEATURES: bool = True
    ENABLE_DEVICE_FINGERPRINTING: bool = True
    
    # Model Ensemble Configuration
    ENSEMBLE_MODELS: List[str] = ["xgboost", "lightgbm", "random_forest"]
    ENSEMBLE_WEIGHTS: Dict[str, float] = {
        "xgboost": 0.4,
        "lightgbm": 0.3,
        "random_forest": 0.3
    }
    
    @field_validator("FRAUD_THRESHOLD_LOW")
    @classmethod
    def validate_low_threshold(cls, v):
        if not 0 <= v <= 1:
            raise ValueError("Fraud threshold must be between 0 and 1")
        return v
    
    @field_validator("FRAUD_THRESHOLD_MEDIUM")
    @classmethod
    def validate_medium_threshold(cls, v, info):
        if not 0 <= v <= 1:
            raise ValueError("Fraud threshold must be between 0 and 1")
        # Note: In Pydantic v2, cross-field validation requires model_validator
        return v
    
    @field_validator("FRAUD_THRESHOLD_HIGH")
    @classmethod
    def validate_high_threshold(cls, v, info):
        if not 0 <= v <= 1:
            raise ValueError("Fraud threshold must be between 0 and 1")
        # Note: In Pydantic v2, cross-field validation requires model_validator
        return v
    
    @field_validator("FRAUD_THRESHOLD_CRITICAL")
    @classmethod
    def validate_critical_threshold(cls, v, info):
        if not 0 <= v <= 1:
            raise ValueError("Fraud threshold must be between 0 and 1")
        # Note: In Pydantic v2, cross-field validation requires model_validator
        return v
    
    @field_validator("ENSEMBLE_WEIGHTS")
    @classmethod
    def validate_ensemble_weights(cls, v):
        total_weight = sum(v.values())
        if abs(total_weight - 1.0) > 0.001:
            raise ValueError("Ensemble weights must sum to 1.0")
        return v
    
    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "allow"


class DevelopmentSettings(Settings):
    """Development environment settings."""
    DEBUG: bool = True
    RELOAD: bool = True
    LOG_LEVEL: str = "DEBUG"
    
    # Override required fields with development defaults
    SECRET_KEY: str = "development-secret-key-32-chars-long"
    JWT_SECRET_KEY: str = "development-jwt-secret-key-32-chars"
    DATABASE_URL: str = "sqlite:///./fraud_detection.db"
    

class ProductionSettings(Settings):
    """Production environment settings."""
    DEBUG: bool = False
    RELOAD: bool = False
    LOG_LEVEL: str = "WARNING"
    
    # Production requires environment variables for security
    SECRET_KEY: str = Field(..., min_length=32, description="Set via FRAUD_SECRET_KEY env var")
    JWT_SECRET_KEY: str = Field(..., min_length=32, description="Set via FRAUD_JWT_SECRET_KEY env var")
    DATABASE_URL: str = Field(..., pattern=r"^postgresql://.*", description="Set via FRAUD_DATABASE_URL env var")
    

class TestingSettings(Settings):
    """Testing environment settings."""
    DATABASE_URL: str = "postgresql://test_user:test_pass@localhost:5432/test_fraud_db"
    REDIS_URL: str = "redis://localhost:6379/1"
    SECRET_KEY: str = "test-secret-key-for-testing-only-32-chars"
    JWT_SECRET_KEY: str = "test-jwt-secret-key-for-testing-only-32"


def get_settings() -> Settings:
    """Get settings based on environment."""
    env = os.getenv("ENVIRONMENT", "development").lower()
    
    if env == "production":
        return ProductionSettings()
    elif env == "testing":
        return TestingSettings()
    else:
        return DevelopmentSettings()


# Global settings instance
settings = get_settings()
