"""
Fraud Detection Service - Business logic for fraud detection operations.
"""

import logging
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional
from decimal import Decimal

from fraud_detection_api.core.config import settings
from fraud_detection_api.models.schemas import (
    FraudDetectionRequest,
    FraudDetectionResponse,
    FraudPrediction,
    TransactionCreate
)
from fraud_detection_api.models.ml_models import FraudDetectionModel
from fraud_detection_api.repositories.fraud_repository import FraudRepository

logger = logging.getLogger(__name__)


class FraudDetectionService:
    """Service class for fraud detection operations."""
    
    def __init__(self):
        """Initialize the fraud detection service."""
        self.ml_model = FraudDetectionModel()
        self.repository = FraudRepository()
        logger.info("FraudDetectionService initialized")
    
    async def detect_fraud(
        self, 
        request: FraudDetectionRequest,
        correlation_id: str
    ) -> FraudDetectionResponse:
        """
        Detect fraud for a single transaction.
        
        Args:
            request: Fraud detection request
            correlation_id: Correlation ID for traceability
            
        Returns:
            Fraud detection response
        """
        try:
            logger.info(
                f"Processing fraud detection request",
                extra={
                    "correlation_id": correlation_id,
                    "transaction_id": request.transaction_id,
                    "user_id": request.user_id
                }
            )
            
            # Prepare features for ML model
            features = self._extract_features(request.transaction_data)
            
            # Get fraud prediction from ML model
            prediction = await self.ml_model.predict(features)
            
            # Apply business rules
            final_prediction = self._apply_business_rules(request, prediction)
            
            # Create response
            response = FraudDetectionResponse(
                transaction_id=request.transaction_id,
                fraud_score=final_prediction.fraud_score,
                is_fraud=final_prediction.is_fraud,
                risk_level=final_prediction.risk_level,
                reasons=final_prediction.reasons,
                recommendations=final_prediction.recommendations,
                correlation_id=correlation_id,
                processing_time_ms=0  # Will be calculated by the API
            )
            
            # Save to repository for audit trail
            await self.repository.save_prediction(request, response, correlation_id)
            
            logger.info(
                f"Fraud detection completed",
                extra={
                    "correlation_id": correlation_id,
                    "transaction_id": request.transaction_id,
                    "fraud_score": response.fraud_score,
                    "is_fraud": response.is_fraud
                }
            )
            
            return response
            
        except Exception as e:
            logger.error(
                f"Error in fraud detection",
                extra={
                    "correlation_id": correlation_id,
                    "transaction_id": request.transaction_id,
                    "error": str(e)
                },
                exc_info=True
            )
            raise
    
    async def detect_fraud_batch(
        self, 
        transactions: List[FraudDetectionRequest],
        correlation_id: str
    ) -> List[FraudDetectionResponse]:
        """
        Detect fraud for multiple transactions.
        
        Args:
            transactions: List of fraud detection requests
            correlation_id: Correlation ID for traceability
            
        Returns:
            List of fraud detection responses
        """
        try:
            logger.info(
                f"Processing batch fraud detection",
                extra={
                    "correlation_id": correlation_id,
                    "batch_size": len(transactions)
                }
            )
            
            results = []
            for transaction in transactions:
                result = await self.detect_fraud(transaction, correlation_id)
                results.append(result)
            
            logger.info(
                f"Batch fraud detection completed",
                extra={
                    "correlation_id": correlation_id,
                    "batch_size": len(transactions),
                    "results_count": len(results)
                }
            )
            
            return results
            
        except Exception as e:
            logger.error(
                f"Error in batch fraud detection",
                extra={
                    "correlation_id": correlation_id,
                    "batch_size": len(transactions),
                    "error": str(e)
                },
                exc_info=True
            )
            raise
    
    def _extract_features(self, transaction_data: TransactionCreate) -> Dict[str, Any]:
        """
        Extract features from transaction data for ML model.
        
        Args:
            transaction_data: Transaction data
            
        Returns:
            Feature dictionary
        """
        features = {
            "amount": float(transaction_data.amount),
            "merchant_category": transaction_data.merchant_category,
            "transaction_type": transaction_data.transaction_type,
            "hour_of_day": transaction_data.timestamp.hour,
            "day_of_week": transaction_data.timestamp.weekday(),
            "is_weekend": transaction_data.timestamp.weekday() >= 5,
            "location_risk_score": self._calculate_location_risk(
                transaction_data.location
            ),
            "device_risk_score": self._calculate_device_risk(
                transaction_data.device_info
            ),
            "velocity_score": self._calculate_velocity_score(
                transaction_data.user_id, 
                transaction_data.timestamp
            )
        }
        
        return features
    
    def _apply_business_rules(
        self, 
        request: FraudDetectionRequest, 
        ml_prediction: FraudPrediction
    ) -> FraudPrediction:
        """
        Apply business rules to ML prediction.
        
        Args:
            request: Original request
            ml_prediction: ML model prediction
            
        Returns:
            Final prediction with business rules applied
        """
        fraud_score = ml_prediction.fraud_score
        is_fraud = ml_prediction.is_fraud
        risk_level = ml_prediction.risk_level
        reasons = list(ml_prediction.reasons)
        recommendations = list(ml_prediction.recommendations)
        
        # High amount rule
        if request.transaction_data.amount > Decimal(settings.HIGH_AMOUNT_THRESHOLD):
            fraud_score = min(fraud_score + 0.2, 1.0)
            reasons.append("High transaction amount")
            recommendations.append("Additional verification required")
        
        # International transaction rule
        if (hasattr(request.transaction_data, 'location') and 
            hasattr(request.transaction_data.location, 'country_code') and
            request.transaction_data.location.country_code != 'TR'):
            fraud_score = min(fraud_score + 0.15, 1.0)
            reasons.append("International transaction")
            recommendations.append("Verify customer location")
        
        # Late night transaction rule
        if request.transaction_data.timestamp.hour < 6 or request.transaction_data.timestamp.hour > 23:
            fraud_score = min(fraud_score + 0.1, 1.0)
            reasons.append("Unusual transaction time")
        
        # Update is_fraud and risk_level based on final score
        if fraud_score >= 0.8:
            is_fraud = True
            risk_level = "HIGH"
        elif fraud_score >= 0.6:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        return FraudPrediction(
            fraud_score=fraud_score,
            is_fraud=is_fraud,
            risk_level=risk_level,
            reasons=reasons,
            recommendations=recommendations
        )
    
    def _calculate_location_risk(self, location: Dict[str, Any]) -> float:
        """Calculate location-based risk score."""
        # Simplified location risk calculation
        if not location:
            return 0.5  # Unknown location has medium risk
        
        risk_score = 0.0
        
        # Add risk based on country
        high_risk_countries = ['CN', 'RU', 'KP']  # Example high-risk countries
        if location.get('country_code') in high_risk_countries:
            risk_score += 0.3
        
        # Add risk based on IP reputation (simplified)
        if location.get('is_proxy', False):
            risk_score += 0.4
        
        if location.get('is_vpn', False):
            risk_score += 0.3
        
        return min(risk_score, 1.0)
    
    def _calculate_device_risk(self, device_info: Dict[str, Any]) -> float:
        """Calculate device-based risk score."""
        if not device_info:
            return 0.5  # Unknown device has medium risk
        
        risk_score = 0.0
        
        # New device risk
        if device_info.get('is_new_device', False):
            risk_score += 0.2
        
        # Suspicious user agent
        if device_info.get('is_suspicious_user_agent', False):
            risk_score += 0.3
        
        # Rooted/jailbroken device
        if device_info.get('is_rooted', False):
            risk_score += 0.4
        
        return min(risk_score, 1.0)
    
    def _calculate_velocity_score(self, user_id: str, timestamp: datetime) -> float:
        """Calculate transaction velocity risk score."""
        # This would normally query recent transactions from database
        # For now, return a mock score
        return 0.1
    
    async def get_system_metrics(self) -> Dict[str, Any]:
        """Get system metrics for monitoring."""
        try:
            model_metrics = await self.ml_model.get_metrics()
            
            metrics = {
                "model_version": model_metrics.get("version", "1.0.0"),
                "model_accuracy": model_metrics.get("accuracy", 0.95),
                "predictions_today": await self.repository.get_daily_prediction_count(),
                "fraud_rate_today": await self.repository.get_daily_fraud_rate(),
                "system_status": "healthy",
                "last_model_update": model_metrics.get("last_update", datetime.utcnow().isoformat())
            }
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error getting system metrics: {str(e)}", exc_info=True)
            return {
                "system_status": "error",
                "error": str(e)
            }
