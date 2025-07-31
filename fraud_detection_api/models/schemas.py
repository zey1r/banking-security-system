"""
Pydantic schemas for request/response validation.
"""

from typing import List, Optional, Dict, Any, Union
from datetime import datetime
from decimal import Decimal
from enum import Enum

from pydantic import BaseModel, Field, validator


class TransactionType(str, Enum):
    """Transaction types."""
    PURCHASE = "purchase"
    WITHDRAWAL = "withdrawal"
    TRANSFER = "transfer"
    DEPOSIT = "deposit"
    PAYMENT = "payment"
    REFUND = "refund"


class PaymentMethod(str, Enum):
    """Payment method types."""
    CREDIT_CARD = "credit_card"
    DEBIT_CARD = "debit_card"
    BANK_TRANSFER = "bank_transfer"
    DIGITAL_WALLET = "digital_wallet"
    CASH = "cash"
    CHECK = "check"


class RiskLevel(str, Enum):
    """Risk levels for fraud scoring."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TransactionBase(BaseModel):
    """Base transaction schema."""
    transaction_id: str = Field(..., min_length=1, max_length=100)
    user_id: str = Field(..., min_length=1, max_length=100)
    amount: Decimal = Field(..., gt=0, decimal_places=2)
    currency: str = Field(..., min_length=3, max_length=3)
    transaction_type: TransactionType
    payment_method: PaymentMethod
    merchant_id: Optional[str] = Field(None, max_length=100)
    merchant_category: Optional[str] = Field(None, max_length=10)
    location: Optional[str] = Field(None, max_length=200)
    device_fingerprint: Optional[str] = Field(None, max_length=500)
    ip_address: Optional[str] = Field(None, max_length=45)
    user_agent: Optional[str] = Field(None, max_length=500)
    timestamp: Optional[datetime] = None
    
    @validator('currency')
    def validate_currency(cls, v):
        """Validate currency code."""
        if not v.isupper() or len(v) != 3:
            raise ValueError('Currency must be a 3-letter uppercase code')
        return v
    
    @validator('merchant_category')
    def validate_merchant_category(cls, v):
        """Validate merchant category code."""
        if v and not v.isdigit():
            raise ValueError('Merchant category must be numeric')
        return v


class TransactionCreate(TransactionBase):
    """Schema for creating transactions."""
    pass


class TransactionResponse(TransactionBase):
    """Schema for transaction responses."""
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class FraudDetectionRequest(BaseModel):
    """Schema for fraud detection requests."""
    transaction: TransactionCreate
    include_explanation: bool = Field(default=False)
    model_version: Optional[str] = None


class FraudPrediction(BaseModel):
    """Schema for fraud prediction results."""
    is_fraud: bool
    fraud_probability: float = Field(..., ge=0, le=1)
    risk_level: RiskLevel
    confidence_score: float = Field(..., ge=0, le=1)
    explanation: Optional[Dict[str, Any]] = None
    model_version: str
    prediction_timestamp: datetime


class FraudDetectionResponse(BaseModel):
    """Schema for fraud detection responses."""
    transaction_id: str
    prediction: FraudPrediction
    processing_time_ms: float
    request_id: str


class BatchFraudDetectionRequest(BaseModel):
    """Schema for batch fraud detection requests."""
    transactions: List[TransactionCreate] = Field(..., max_items=1000)
    include_explanation: bool = Field(default=False)
    model_version: Optional[str] = None


class BatchFraudDetectionResponse(BaseModel):
    """Schema for batch fraud detection responses."""
    predictions: List[FraudDetectionResponse]
    total_transactions: int
    processing_time_ms: float
    request_id: str


class UserBase(BaseModel):
    """Base user schema."""
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., max_length=255)
    full_name: Optional[str] = Field(None, max_length=100)
    is_active: bool = True


class UserCreate(UserBase):
    """Schema for creating users."""
    password: str = Field(..., min_length=8, max_length=100)


class UserResponse(UserBase):
    """Schema for user responses."""
    id: int
    created_at: datetime
    last_login: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class UserLogin(BaseModel):
    """Schema for user login."""
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=100)


class Token(BaseModel):
    """Schema for authentication tokens."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenData(BaseModel):
    """Schema for token data."""
    username: Optional[str] = None
    user_id: Optional[int] = None
    permissions: List[str] = []


class HealthCheck(BaseModel):
    """Schema for health check responses."""
    status: str
    timestamp: datetime
    version: str
    database_status: str
    redis_status: str
    model_status: str


class ModelMetrics(BaseModel):
    """Schema for model performance metrics."""
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    auc_roc: float
    false_positive_rate: float
    true_positive_rate: float
    last_updated: datetime


class SystemMetrics(BaseModel):
    """Schema for system metrics."""
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    active_connections: int
    requests_per_minute: float
    average_response_time_ms: float
    error_rate: float


class AuditLog(BaseModel):
    """Schema for audit log entries."""
    user_id: Optional[int]
    action: str
    resource: str
    resource_id: Optional[str]
    ip_address: Optional[str]
    user_agent: Optional[str]
    timestamp: datetime
    details: Optional[Dict[str, Any]] = None


class ModelTrainingRequest(BaseModel):
    """Schema for model training requests."""
    data_source: str
    model_type: str
    hyperparameters: Optional[Dict[str, Any]] = None
    validation_split: float = Field(default=0.2, ge=0.1, le=0.4)


class ModelTrainingResponse(BaseModel):
    """Schema for model training responses."""
    training_id: str
    status: str
    metrics: Optional[ModelMetrics] = None
    started_at: datetime
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None


class FeatureImportance(BaseModel):
    """Schema for feature importance data."""
    feature_name: str
    importance_score: float
    rank: int


class ModelExplanation(BaseModel):
    """Schema for model explanation data."""
    feature_contributions: List[FeatureImportance]
    decision_path: Optional[List[str]] = None
    confidence_factors: Optional[Dict[str, float]] = None
