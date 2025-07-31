"""
Banking Fraud Detection API - Simplified Version
Production-ready fraud detection system for financial institutions
"""

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import logging
import asyncio
import uvicorn
from decimal import Decimal
import secrets
import hashlib
import json

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Banking Fraud Detection API",
    description="Enterprise-grade fraud detection system for financial institutions",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS configuration for production (Render + GitHub Pages)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://zey1r.github.io",  # GitHub Pages frontend
        "http://localhost:3000",    # Local development
        "http://localhost:8080",    # Local development  
        "https://*.onrender.com",   # Render deployment URLs
        "*"  # Allow all for development (remove in strict production)
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

security = HTTPBearer()

# Simple token storage (in production, use Redis or database)
VALID_TOKENS = {
    "demo_token_123": {
        "user_id": "demo_user",
        "permissions": ["fraud_detection", "admin"],
        "created_at": datetime.now()
    }
}

# Pydantic models
class TransactionData(BaseModel):
    """Transaction data model for fraud detection"""
    transaction_id: str = Field(..., description="Unique transaction identifier")
    account_id: str = Field(..., description="Account identifier")
    amount: Decimal = Field(..., description="Transaction amount")
    currency: str = Field(default="TRY", description="Currency code (ISO 4217)")
    merchant_id: Optional[str] = Field(None, description="Merchant identifier")
    merchant_category: Optional[str] = Field(None, description="Merchant category code")
    location: Optional[str] = Field(None, description="Transaction location")
    device_id: Optional[str] = Field(None, description="Device identifier")
    ip_address: Optional[str] = Field(None, description="Client IP address")
    timestamp: Optional[datetime] = Field(default_factory=datetime.now, description="Transaction timestamp")
    channel: str = Field(default="online", description="Transaction channel")

class FraudResult(BaseModel):
    """Fraud detection result model"""
    transaction_id: str
    is_fraud: bool
    risk_score: float = Field(..., ge=0, le=1, description="Risk score between 0 and 1")
    risk_level: str = Field(..., description="Risk level: LOW, MEDIUM, HIGH, CRITICAL")
    reasons: List[str] = Field(default=[], description="Fraud indicators")
    recommended_action: str = Field(..., description="Recommended action")
    confidence: float = Field(..., ge=0, le=1, description="Model confidence")
    processing_time_ms: float = Field(..., description="Processing time in milliseconds")

class HealthStatus(BaseModel):
    """Health check response model"""
    status: str
    timestamp: datetime
    version: str
    uptime_seconds: float

# Simple authentication
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Simple token validation"""
    token = credentials.credentials
    
    if token not in VALID_TOKENS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_data = VALID_TOKENS[token]
    
    # Check token expiry (24 hours)
    if datetime.now() - user_data["created_at"] > timedelta(hours=24):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return user_data

# Simple fraud detection algorithm
class SimpleFraudDetector:
    """Simple but effective fraud detection algorithm"""
    
    def __init__(self):
        self.transaction_history = {}
        self.risk_thresholds = {
            "amount_medium": 5000,       # 5K TL
            "amount_large": 25000,       # 25K TL  
            "amount_very_large": 100000, # 100K TL
            "amount_extreme": 500000,    # 500K TL
            "amount_suspicious": 1000000, # 1M TL
            "velocity_limit": 5,
            "foreign_country_risk": 0.3
        }
        
        # High-risk categories
        self.high_risk_categories = ["casino", "lottery", "gambling", "crypto"]
        self.medium_risk_categories = ["luxury", "jewelry", "electronics"]
        self.low_risk_categories = ["grocery", "restaurant", "pharmacy", "gas"]
        
        # High-risk countries/locations
        self.high_risk_locations = ["dubai", "macau", "panama", "cayman", "malta", "cyprus"]
        self.foreign_locations = ["dubai", "london", "paris", "new york", "singapore", "hong kong"]
    
    async def analyze_transaction(self, transaction: TransactionData) -> FraudResult:
        """Enhanced fraud analysis with multiple risk factors"""
        start_time = datetime.now()
        
        risk_score = 0.0
        reasons = []
        
        # Enhanced amount-based risk scoring
        amount = float(transaction.amount)
        if amount >= self.risk_thresholds["amount_suspicious"]:  # 1M+
            risk_score += 0.6
            reasons.append("Extremely large transaction amount (1M+ TL)")
        elif amount >= self.risk_thresholds["amount_extreme"]:   # 500K+
            risk_score += 0.5
            reasons.append("Suspicious transaction amount (500K+ TL)")
        elif amount >= self.risk_thresholds["amount_very_large"]: # 100K+
            risk_score += 0.3
            reasons.append("Very large transaction amount (100K+ TL)")
        elif amount >= self.risk_thresholds["amount_large"]:     # 25K+
            risk_score += 0.2
            reasons.append("Large transaction amount (25K+ TL)")
        elif amount >= self.risk_thresholds["amount_medium"]:    # 5K+
            risk_score += 0.1
            reasons.append("Medium transaction amount (5K+ TL)")
        
        # Enhanced merchant category risk
        category = transaction.merchant_category.lower() if transaction.merchant_category else ""
        if category in self.high_risk_categories:
            risk_score += 0.4
            reasons.append(f"High-risk merchant category: {category}")
        elif category in self.medium_risk_categories:
            risk_score += 0.2
            reasons.append(f"Medium-risk merchant category: {category}")
        elif category in self.low_risk_categories:
            risk_score += 0.0  # No additional risk for low-risk categories
        else:
            risk_score += 0.1  # Unknown category gets some risk
            reasons.append("Unknown merchant category")
        
        # Enhanced location-based risk
        location = transaction.location.lower() if transaction.location else ""
        if any(risky_loc in location for risky_loc in self.high_risk_locations):
            risk_score += 0.3
            reasons.append(f"High-risk location: {transaction.location}")
        elif any(foreign_loc in location for foreign_loc in self.foreign_locations):
            risk_score += 0.15
            reasons.append(f"Foreign location: {transaction.location}")
        elif location not in ["istanbul", "ankara", "izmir", "bursa", "adana"]:
            risk_score += 0.05
            reasons.append("Non-major Turkish city")
        
        # Currency risk
        if transaction.currency != "TRY":
            risk_score += 0.15
            reasons.append(f"Foreign currency transaction: {transaction.currency}")
        
        # Combination risk bonuses (multiplicative effects)
        if category in self.high_risk_categories and amount >= self.risk_thresholds["amount_large"]:
            risk_score += 0.2
            reasons.append("High-risk category + Large amount combination")
        
        if any(risky_loc in location for risky_loc in self.high_risk_locations) and category in self.high_risk_categories:
            risk_score += 0.3
            reasons.append("High-risk location + High-risk category combination")
        
        if amount >= self.risk_thresholds["amount_extreme"] and transaction.currency != "TRY":
            risk_score += 0.25
            reasons.append("Extreme amount + Foreign currency combination")
        
        # Channel-based risk
        if transaction.channel == "online" and amount >= self.risk_thresholds["amount_large"]:
            risk_score += 0.1
            reasons.append("Large online transaction")
        elif transaction.channel == "atm" and amount >= self.risk_thresholds["amount_very_large"]:
            risk_score += 0.15
            reasons.append("Very large ATM transaction")
        
        # Velocity check (same as before)
        account_id = transaction.account_id
        current_hour = datetime.now().hour
        
        if account_id not in self.transaction_history:
            self.transaction_history[account_id] = {}
        
        if current_hour not in self.transaction_history[account_id]:
            self.transaction_history[account_id][current_hour] = 0
        
        self.transaction_history[account_id][current_hour] += 1
        
        if self.transaction_history[account_id][current_hour] > self.risk_thresholds["velocity_limit"]:
            risk_score += 0.2
            reasons.append("High transaction velocity")
        
        # Time-based risk
        if transaction.timestamp and (transaction.timestamp.hour < 6 or transaction.timestamp.hour > 22):
            risk_score += 0.1
            reasons.append("Off-hours transaction")
        
        # IP-based risk
        if transaction.ip_address and transaction.ip_address.startswith("10."):
            risk_score += 0.0  # Internal IP, no additional risk
        elif transaction.ip_address:
            risk_score += 0.05  # External IP, small risk
            reasons.append("External IP address")
        
        # Account risk patterns
        if transaction.account_id.startswith("ACC99"):  # Suspicious account pattern
            risk_score += 0.2
            reasons.append("Suspicious account pattern")
        
        # Ensure risk score is between 0 and 1
        risk_score = min(risk_score, 1.0)
        
        # Determine risk level and action
        if risk_score >= 0.8:
            risk_level = "CRITICAL"
            recommended_action = "BLOCK_TRANSACTION"
        elif risk_score >= 0.6:
            risk_level = "HIGH"
            recommended_action = "REQUIRE_ADDITIONAL_AUTH"
        elif risk_score >= 0.3:
            risk_level = "MEDIUM"
            recommended_action = "REVIEW_MANUALLY"
        else:
            risk_level = "LOW"
            recommended_action = "APPROVE"
        
        is_fraud = risk_score >= 0.6
        confidence = 0.85 + (0.15 * (1 - abs(0.5 - risk_score)))
        
        processing_time = (datetime.now() - start_time).total_seconds() * 1000
        
        return FraudResult(
            transaction_id=transaction.transaction_id,
            is_fraud=is_fraud,
            risk_score=risk_score,
            risk_level=risk_level,
            reasons=reasons,
            recommended_action=recommended_action,
            confidence=confidence,
            processing_time_ms=processing_time
        )

# Initialize fraud detector
fraud_detector = SimpleFraudDetector()

# Application startup time
app_start_time = datetime.now()

@app.get("/", response_model=Dict[str, Any])
async def root():
    """Root endpoint - API information"""
    return {
        "message": "Banking Fraud Detection API",
        "version": "1.0.0",
        "status": "operational",
        "documentation": "/docs",
        "health_check": "/health"
    }

@app.get("/health", response_model=HealthStatus)
async def health_check():
    """Health check endpoint"""
    uptime = (datetime.now() - app_start_time).total_seconds()
    
    return HealthStatus(
        status="healthy",
        timestamp=datetime.now(),
        version="1.0.0",
        uptime_seconds=uptime
    )

@app.post("/fraud-detection/analyze", response_model=FraudResult)
async def analyze_fraud(
    transaction: TransactionData,
    current_user: Dict = Depends(get_current_user)
):
    """
    Analyze transaction for fraud indicators
    
    This endpoint performs real-time fraud detection on transaction data.
    Returns risk assessment and recommended actions.
    """
    try:
        # Log transaction analysis request
        logger.info(f"Fraud analysis requested for transaction {transaction.transaction_id} by user {current_user['user_id']}")
        
        # Perform fraud analysis
        result = await fraud_detector.analyze_transaction(transaction)
        
        # Log result
        logger.info(f"Transaction {transaction.transaction_id}: risk_score={result.risk_score}, is_fraud={result.is_fraud}")
        
        return result
        
    except Exception as e:
        logger.error(f"Error analyzing transaction {transaction.transaction_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during fraud analysis"
        )

@app.post("/fraud-detection/batch", response_model=List[FraudResult])
async def analyze_fraud_batch(
    transactions: List[TransactionData],
    current_user: Dict = Depends(get_current_user)
):
    """
    Batch fraud analysis for multiple transactions
    
    Process multiple transactions simultaneously for fraud detection.
    Maximum 100 transactions per batch.
    """
    if len(transactions) > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum 100 transactions per batch"
        )
    
    try:
        logger.info(f"Batch fraud analysis requested for {len(transactions)} transactions by user {current_user['user_id']}")
        
        # Process transactions concurrently
        tasks = [fraud_detector.analyze_transaction(transaction) for transaction in transactions]
        results = await asyncio.gather(*tasks)
        
        logger.info(f"Batch analysis completed for {len(transactions)} transactions")
        
        return results
        
    except Exception as e:
        logger.error(f"Error in batch fraud analysis: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during batch fraud analysis"
        )

@app.get("/fraud-detection/stats", response_model=Dict[str, Any])
async def get_fraud_stats(current_user: Dict = Depends(get_current_user)):
    """Get fraud detection statistics"""
    
    total_accounts = len(fraud_detector.transaction_history)
    total_transactions = sum(
        sum(hourly_counts.values()) 
        for hourly_counts in fraud_detector.transaction_history.values()
    )
    
    return {
        "total_accounts_monitored": total_accounts,
        "total_transactions_processed": total_transactions,
        "api_uptime_seconds": (datetime.now() - app_start_time).total_seconds(),
        "fraud_detection_engine": "SimpleFraudDetector v1.0",
        "last_updated": datetime.now()
    }

@app.get("/auth/demo-token")
async def get_demo_token():
    """Get a demo authentication token for testing"""
    return {
        "token": "demo_token_123",
        "token_type": "bearer",
        "expires_in": 86400,
        "note": "This is a demo token for testing purposes"
    }

if __name__ == "__main__":
    uvicorn.run(
        "main_simple:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
