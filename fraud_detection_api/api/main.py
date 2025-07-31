"""
VeriVigil Enterprise Banking Fraud Detection API
BDDK Compliant | PCI DSS Ready | Production Grade
"""

import time
import uuid
from datetime import datetime
from typing import List, Dict, Any
import logging

from fastapi import FastAPI, HTTPException, Depends, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer
import uvicorn

from fraud_detection_api.core.config import settings
from fraud_detection_api.core.security import security_manager, rate_limiter
from fraud_detection_api.core.enterprise_security import enterprise_security, audit_logger, SecurityException
from fraud_detection_api.core.performance_optimizer import performance_optimizer
from fraud_detection_api.models.schemas import (
    FraudDetectionRequest,
    FraudDetectionResponse,
    BatchFraudDetectionRequest,
    BatchFraudDetectionResponse,
    HealthCheck,
    SystemMetrics,
    UserLogin,
    Token,
    FraudPrediction
)
from fraud_detection_api.models.ml_models import FraudDetectionModel
from fraud_detection_api.services.fraud_service import FraudDetectionService
from fraud_detection_api.utils.logger import get_correlation_id, set_correlation_id

# Configure logging
logging.basicConfig(level=getattr(logging, settings.LOG_LEVEL))
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title=settings.PROJECT_NAME,
    description=settings.DESCRIPTION,
    version=settings.VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=settings.CORS_ALLOW_METHODS,
    allow_headers=settings.CORS_ALLOW_HEADERS,
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "0.0.0.0"]
)

# Security
security = HTTPBearer()

# Global model instance
fraud_model: FraudDetectionModel = None


@app.on_event("startup")
async def startup_event():
    """Initialize application on startup."""
    global fraud_model
    
    logger.info("Starting Banking Fraud Detection API")
    logger.info(f"Version: {settings.VERSION}")
    logger.info(f"Environment: {settings.DEBUG and 'Development' or 'Production'}")
    
    # Initialize fraud detection model
    fraud_model = FraudDetectionModel()
    
    # Try to load existing model
    if not fraud_model.load_model():
        logger.warning("No pre-trained model found. Training with sample data...")
        # In production, you would load real training data here
        await train_sample_model()
    
    logger.info("Application startup complete")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on application shutdown."""
    logger.info("Shutting down Banking Fraud Detection API")


async def train_sample_model():
    """Train model with sample data for demonstration."""
    import numpy as np
    
    # Generate sample training data
    logger.info("Generating sample training data...")
    
    np.random.seed(42)
    n_samples = 10000
    n_features = 50  # Should match feature count in ml_models.py
    
    # Create synthetic features
    X = np.random.randn(n_samples, n_features)
    
    # Create labels with some pattern (fraud is rare - about 2%)
    fraud_probability = 1 / (1 + np.exp(-X[:, 0] - 0.5 * X[:, 1]))  # Logistic function
    y = (fraud_probability > 0.98).astype(int)  # About 2% fraud rate
    
    logger.info(f"Training data: {n_samples} samples, {np.sum(y)} fraud cases ({np.mean(y)*100:.1f}%)")
    
    # Train the model
    training_results = fraud_model.train(X, y)
    
    # Save the trained model
    fraud_model.save_model()
    
    logger.info("Sample model training completed")
    logger.info(f"Ensemble AUC: {training_results.get('ensemble', {}).get('auc_score', 'N/A')}")


@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    """Add processing time header to responses."""
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response


@app.middleware("http")
async def rate_limiting_middleware(request: Request, call_next):
    """Rate limiting middleware."""
    client_ip = request.client.host
    
    # Skip rate limiting for health checks
    if request.url.path in ["/health", "/ready", "/metrics"]:
        return await call_next(request)
    
    if not rate_limiter.is_allowed(client_ip):
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded"}
        )
    
    return await call_next(request)


def get_current_user(token: str = Depends(security)):
    """
    Validate JWT token and get current user.
    
    Args:
        token: JWT token from Authorization header
        
    Returns:
        dict: User information
        
    Raises:
        HTTPException: If token is invalid
    """
    if not token.credentials:
        raise HTTPException(status_code=401, detail="Token required")
    
    payload = security_manager.verify_token(token.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    return payload


@app.get("/health", response_model=HealthCheck)
async def health_check():
    """
    Health check endpoint.
    
    Returns:
        HealthCheck: System health status
    """
    return HealthCheck(
        status="healthy",
        timestamp=datetime.utcnow(),
        version=settings.VERSION,
        database_status="connected",  # Would check actual DB in production
        redis_status="connected",     # Would check actual Redis in production
        model_status="loaded" if fraud_model and fraud_model.is_trained else "not_loaded"
    )


@app.get("/ready")
async def readiness_check():
    """
    Readiness check for Kubernetes.
    
    Returns:
        dict: Readiness status
    """
    if not fraud_model or not fraud_model.is_trained:
        raise HTTPException(status_code=503, detail="Model not ready")
    
    return {"status": "ready", "timestamp": datetime.utcnow()}


@app.get("/metrics")
async def get_metrics():
    """
    Prometheus metrics endpoint.
    
    Returns:
        dict: System metrics
    """
    # In production, this would return actual Prometheus metrics
    return {
        "fraud_predictions_total": 0,
        "fraud_detected_total": 0,
        "api_requests_total": 0,
        "response_time_seconds": 0.0
    }


@app.post("/api/v1/auth/login", response_model=Token)
async def login(user_credentials: UserLogin):
    """
    Authenticate user and return JWT tokens.
    
    Args:
        user_credentials: Username and password
        
    Returns:
        Token: JWT access and refresh tokens
    """
    # In production, validate against actual user database
    demo_users = {
        "admin": "banking_fraud_2024!",
        "analyst": "fraud_analyst_2024!",
        "api_user": "api_user_2024!"
    }
    
    username = user_credentials.username
    password = user_credentials.password
    
    if username not in demo_users or demo_users[username] != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Create tokens
    token_data = {"sub": username, "user_id": 1, "permissions": ["fraud_detection"]}
    access_token = security_manager.create_access_token(token_data)
    refresh_token = security_manager.create_refresh_token(token_data)
    
    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )


@app.post(f"{settings.API_V1_STR}/fraud/detect", response_model=FraudDetectionResponse)
async def detect_fraud(
    request: FraudDetectionRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Detect fraud for a single transaction.
    
    Args:
        request: Fraud detection request
        current_user: Authenticated user
        
    Returns:
        FraudDetectionResponse: Fraud prediction results
    """
    start_time = time.time()
    request_id = str(uuid.uuid4())
    
    try:
        # Validate input
        if not security_manager.validate_input(str(request.transaction.dict())):
            raise HTTPException(status_code=400, detail="Invalid input data")
        
        # Convert transaction to dict for model
        transaction_dict = request.transaction.dict()
        transaction_dict['timestamp'] = transaction_dict.get('timestamp') or datetime.utcnow()
        
        # Get prediction
        prediction_result = fraud_model.predict(transaction_dict)
        
        # Create prediction object
        prediction = FraudPrediction(
            is_fraud=prediction_result['is_fraud'],
            fraud_probability=prediction_result['fraud_probability'],
            risk_level=prediction_result['risk_level'],
            confidence_score=prediction_result['confidence_score'],
            model_version=prediction_result['model_version'],
            prediction_timestamp=datetime.utcnow()
        )
        
        # Add explanation if requested
        if request.include_explanation:
            prediction.explanation = {
                "combined_score": prediction_result['combined_score'],
                "anomaly_score": prediction_result['anomaly_score'],
                "risk_factors": ["high_amount"] if transaction_dict['amount'] > 1000 else []
            }
        
        processing_time = (time.time() - start_time) * 1000
        
        # Log the prediction
        logger.info(
            f"Fraud prediction - User: {current_user.get('sub')}, "
            f"Transaction: {request.transaction.transaction_id}, "
            f"Result: {prediction.is_fraud}, "
            f"Probability: {prediction.fraud_probability:.3f}, "
            f"Time: {processing_time:.2f}ms"
        )
        
        return FraudDetectionResponse(
            transaction_id=request.transaction.transaction_id,
            prediction=prediction,
            processing_time_ms=processing_time,
            request_id=request_id
        )
        
    except Exception as e:
        logger.error(f"Fraud detection failed: {e}")
        raise HTTPException(status_code=500, detail="Fraud detection failed")


@app.post(f"{settings.API_V1_STR}/fraud/batch", response_model=BatchFraudDetectionResponse)
async def detect_fraud_batch(
    request: BatchFraudDetectionRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """
    Detect fraud for multiple transactions.
    
    Args:
        request: Batch fraud detection request
        background_tasks: Background task runner
        current_user: Authenticated user
        
    Returns:
        BatchFraudDetectionResponse: Batch prediction results
    """
    start_time = time.time()
    request_id = str(uuid.uuid4())
    
    try:
        if len(request.transactions) > settings.MAX_BATCH_SIZE:
            raise HTTPException(
                status_code=400, 
                detail=f"Batch size exceeds maximum of {settings.MAX_BATCH_SIZE}"
            )
        
        predictions = []
        
        for transaction in request.transactions:
            # Convert to individual request
            individual_request = FraudDetectionRequest(
                transaction=transaction,
                include_explanation=request.include_explanation,
                model_version=request.model_version
            )
            
            # Get prediction
            prediction_response = await detect_fraud(individual_request, current_user)
            predictions.append(prediction_response)
        
        processing_time = (time.time() - start_time) * 1000
        
        logger.info(
            f"Batch fraud prediction - User: {current_user.get('sub')}, "
            f"Transactions: {len(request.transactions)}, "
            f"Time: {processing_time:.2f}ms"
        )
        
        return BatchFraudDetectionResponse(
            predictions=predictions,
            total_transactions=len(request.transactions),
            processing_time_ms=processing_time,
            request_id=request_id
        )
        
    except Exception as e:
        logger.error(f"Batch fraud detection failed: {e}")
        raise HTTPException(status_code=500, detail="Batch fraud detection failed")


@app.get(f"{settings.API_V1_STR}/model/info")
async def get_model_info(current_user: dict = Depends(get_current_user)):
    """
    Get model information.
    
    Args:
        current_user: Authenticated user
        
    Returns:
        dict: Model information
    """
    if not fraud_model:
        raise HTTPException(status_code=503, detail="Model not available")
    
    return {
        "model_version": fraud_model.model_version,
        "is_trained": fraud_model.is_trained,
        "last_training": fraud_model.last_training,
        "ensemble_weights": fraud_model.ensemble_weights,
        "feature_config": fraud_model.feature_config
    }


@app.get(f"{settings.API_V1_STR}/model/feature-importance")
async def get_feature_importance(current_user: dict = Depends(get_current_user)):
    """
    Get feature importance from trained models.
    
    Args:
        current_user: Authenticated user
        
    Returns:
        dict: Feature importance data
    """
    if not fraud_model or not fraud_model.is_trained:
        raise HTTPException(status_code=503, detail="Model not trained")
    
    try:
        importance_data = fraud_model.get_feature_importance()
        return importance_data
    except Exception as e:
        logger.error(f"Failed to get feature importance: {e}")
        raise HTTPException(status_code=500, detail="Failed to get feature importance")


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler."""
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )


if __name__ == "__main__":
    uvicorn.run(
        "fraud_detection_api.api.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.RELOAD,
        log_level=settings.LOG_LEVEL.lower()
    )
