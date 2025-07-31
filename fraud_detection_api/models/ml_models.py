"""
Machine Learning models for fraud detection.
"""

import logging
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
from pathlib import Path
import json

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, roc_auc_score, precision_recall_curve
from sklearn.preprocessing import StandardScaler, LabelEncoder
import xgboost as xgb
import lightgbm as lgb

from fraud_detection_api.core.config import settings
from fraud_detection_api.models.schemas import RiskLevel

logger = logging.getLogger(__name__)


class FraudDetectionModel:
    """
    Advanced fraud detection model using ensemble methods.
    """
    
    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize fraud detection model.
        
        Args:
            model_path: Path to saved model files
        """
        self.model_path = model_path or settings.MODEL_PATH
        self.models = {}
        self.scalers = {}
        self.feature_names = []
        self.is_trained = False
        self.model_version = settings.MODEL_VERSION
        self.last_training = None
        
        # Model configurations
        self.model_configs = {
            'xgboost': {
                'n_estimators': 200,
                'max_depth': 8,
                'learning_rate': 0.1,
                'subsample': 0.8,
                'colsample_bytree': 0.8,
                'random_state': 42,
                'objective': 'binary:logistic',
                'eval_metric': 'auc'
            },
            'lightgbm': {
                'n_estimators': 200,
                'max_depth': 8,
                'learning_rate': 0.1,
                'subsample': 0.8,
                'colsample_bytree': 0.8,
                'random_state': 42,
                'objective': 'binary',
                'metric': 'auc',
                'verbose': -1
            },
            'random_forest': {
                'n_estimators': 100,
                'max_depth': 15,
                'min_samples_split': 5,
                'min_samples_leaf': 2,
                'random_state': 42,
                'n_jobs': -1
            }
        }
        
        # Ensemble weights
        self.ensemble_weights = settings.ENSEMBLE_WEIGHTS
        
        # Feature engineering configuration
        self.feature_config = {
            'behavioral_features': settings.ENABLE_BEHAVIORAL_FEATURES,
            'temporal_features': settings.ENABLE_TEMPORAL_FEATURES,
            'geolocation_features': settings.ENABLE_GEOLOCATION_FEATURES,
            'device_features': settings.ENABLE_DEVICE_FINGERPRINTING
        }
    
    def create_features(self, transaction_data: Dict[str, Any]) -> np.ndarray:
        """
        Create feature vector from transaction data.
        
        Args:
            transaction_data: Transaction information
            
        Returns:
            np.ndarray: Feature vector
        """
        features = []
        
        # Basic transaction features
        features.extend([
            float(transaction_data.get('amount', 0)),
            np.log1p(float(transaction_data.get('amount', 0))),  # Log-transformed amount
        ])
        
        # Time-based features if enabled
        if self.feature_config['temporal_features']:
            timestamp = transaction_data.get('timestamp')
            if timestamp:
                if isinstance(timestamp, str):
                    timestamp = pd.to_datetime(timestamp)
                elif isinstance(timestamp, datetime):
                    pass
                else:
                    timestamp = datetime.now()
                
                features.extend([
                    timestamp.hour,
                    timestamp.weekday(),
                    timestamp.day,
                    1 if timestamp.weekday() >= 5 else 0,  # Weekend flag
                    1 if 22 <= timestamp.hour or timestamp.hour <= 6 else 0  # Night flag
                ])
            else:
                features.extend([12, 1, 15, 0, 0])  # Default values
        
        # Payment method encoding
        payment_methods = ['credit_card', 'debit_card', 'bank_transfer', 'digital_wallet', 'cash', 'check']
        payment_method = transaction_data.get('payment_method', 'credit_card')
        payment_encoded = [1 if pm == payment_method else 0 for pm in payment_methods]
        features.extend(payment_encoded)
        
        # Transaction type encoding
        transaction_types = ['purchase', 'withdrawal', 'transfer', 'deposit', 'payment', 'refund']
        transaction_type = transaction_data.get('transaction_type', 'purchase')
        type_encoded = [1 if tt == transaction_type else 0 for tt in transaction_types]
        features.extend(type_encoded)
        
        # Currency encoding (top currencies)
        currencies = ['USD', 'EUR', 'GBP', 'JPY', 'CAD', 'AUD', 'CHF', 'CNY']
        currency = transaction_data.get('currency', 'USD')
        currency_encoded = [1 if c == currency else 0 for c in currencies]
        features.extend(currency_encoded)
        
        # Merchant category features
        merchant_category = transaction_data.get('merchant_category', '0000')
        try:
            merchant_cat_num = int(merchant_category)
            features.extend([
                merchant_cat_num,
                1 if 5000 <= merchant_cat_num <= 5999 else 0,  # Retail
                1 if 4000 <= merchant_cat_num <= 4999 else 0,  # Transportation
                1 if 7000 <= merchant_cat_num <= 7999 else 0,  # Services
            ])
        except (ValueError, TypeError):
            features.extend([0, 0, 0, 0])
        
        # Device and location features if enabled
        if self.feature_config['device_features']:
            device_fingerprint = transaction_data.get('device_fingerprint', '')
            features.extend([
                len(device_fingerprint),
                1 if device_fingerprint else 0
            ])
        
        if self.feature_config['geolocation_features']:
            location = transaction_data.get('location', '')
            features.extend([
                len(location.split(',')) if location else 0,
                1 if 'US' in location or 'United States' in location else 0,
                1 if any(city in location.lower() for city in ['new york', 'los angeles', 'chicago']) else 0
            ])
        
        # Risk indicators
        amount = float(transaction_data.get('amount', 0))
        features.extend([
            1 if amount > float(settings.SUSPICIOUS_AMOUNT_THRESHOLD) else 0,
            1 if amount > float(settings.MAX_TRANSACTION_AMOUNT) * 0.5 else 0,
            amount / float(settings.MAX_TRANSACTION_AMOUNT)  # Normalized amount
        ])
        
        return np.array(features, dtype=np.float32)
    
    def train(self, X: np.ndarray, y: np.ndarray) -> Dict[str, Any]:
        """
        Train the ensemble fraud detection model.
        
        Args:
            X: Feature matrix
            y: Target labels (0: legitimate, 1: fraud)
            
        Returns:
            Dict containing training metrics
        """
        logger.info("Starting fraud detection model training")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        self.scalers['main'] = scaler
        
        training_results = {}
        
        # Train individual models
        for model_name, config in self.model_configs.items():
            logger.info(f"Training {model_name} model")
            
            if model_name == 'xgboost':
                model = xgb.XGBClassifier(**config)
                model.fit(X_train_scaled, y_train)
            elif model_name == 'lightgbm':
                model = lgb.LGBMClassifier(**config)
                model.fit(X_train_scaled, y_train)
            elif model_name == 'random_forest':
                model = RandomForestClassifier(**config)
                model.fit(X_train_scaled, y_train)
            
            # Evaluate model
            y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]
            y_pred = (y_pred_proba >= 0.5).astype(int)
            
            auc_score = roc_auc_score(y_test, y_pred_proba)
            
            self.models[model_name] = model
            training_results[model_name] = {
                'auc_score': auc_score,
                'classification_report': classification_report(y_test, y_pred, output_dict=True)
            }
            
            logger.info(f"{model_name} AUC: {auc_score:.4f}")
        
        # Train anomaly detector
        isolation_forest = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_jobs=-1
        )
        
        # Train on legitimate transactions only
        legitimate_transactions = X_train_scaled[y_train == 0]
        isolation_forest.fit(legitimate_transactions)
        self.models['isolation_forest'] = isolation_forest
        
        # Calculate ensemble performance
        ensemble_predictions = self._predict_ensemble(X_test_scaled)
        ensemble_auc = roc_auc_score(y_test, ensemble_predictions)
        
        training_results['ensemble'] = {
            'auc_score': ensemble_auc,
            'classification_report': classification_report(
                y_test, (ensemble_predictions >= 0.5).astype(int), output_dict=True
            )
        }
        
        self.is_trained = True
        self.last_training = datetime.now()
        
        logger.info(f"Training completed. Ensemble AUC: {ensemble_auc:.4f}")
        
        return training_results
    
    def _predict_ensemble(self, X: np.ndarray) -> np.ndarray:
        """
        Get ensemble predictions from all models.
        
        Args:
            X: Feature matrix
            
        Returns:
            np.ndarray: Ensemble predictions
        """
        predictions = []
        
        for model_name in ['xgboost', 'lightgbm', 'random_forest']:
            if model_name in self.models:
                pred = self.models[model_name].predict_proba(X)[:, 1]
                weight = self.ensemble_weights.get(model_name, 0.33)
                predictions.append(pred * weight)
        
        if predictions:
            return np.sum(predictions, axis=0)
        else:
            return np.zeros(X.shape[0])
    
    def predict(self, transaction_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Predict fraud probability for a transaction.
        
        Args:
            transaction_data: Transaction information
            
        Returns:
            Dict containing prediction results
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        
        # Create features
        features = self.create_features(transaction_data)
        features_scaled = self.scalers['main'].transform(features.reshape(1, -1))
        
        # Get ensemble prediction
        fraud_probability = self._predict_ensemble(features_scaled)[0]
        
        # Get anomaly score
        anomaly_score = self.models['isolation_forest'].decision_function(features_scaled)[0]
        anomaly_score_normalized = max(0, min(1, (anomaly_score + 0.5) * 2))
        
        # Combine scores
        combined_score = 0.8 * fraud_probability + 0.2 * (1 - anomaly_score_normalized)
        
        # Determine risk level
        if combined_score >= settings.FRAUD_THRESHOLD_CRITICAL:
            risk_level = RiskLevel.CRITICAL
        elif combined_score >= settings.FRAUD_THRESHOLD_HIGH:
            risk_level = RiskLevel.HIGH
        elif combined_score >= settings.FRAUD_THRESHOLD_MEDIUM:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW
        
        # Determine if fraud
        is_fraud = combined_score >= settings.FRAUD_THRESHOLD_MEDIUM
        
        return {
            'is_fraud': is_fraud,
            'fraud_probability': float(fraud_probability),
            'combined_score': float(combined_score),
            'anomaly_score': float(1 - anomaly_score_normalized),
            'risk_level': risk_level,
            'confidence_score': float(abs(combined_score - 0.5) * 2),
            'model_version': self.model_version
        }
    
    def save_model(self, path: Optional[str] = None) -> str:
        """
        Save trained model to disk.
        
        Args:
            path: Save path
            
        Returns:
            str: Path where model was saved
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before saving")
        
        save_path = Path(path or self.model_path)
        save_path.mkdir(parents=True, exist_ok=True)
        
        # Save models
        model_data = {
            'models': self.models,
            'scalers': self.scalers,
            'feature_names': self.feature_names,
            'model_version': self.model_version,
            'last_training': self.last_training,
            'ensemble_weights': self.ensemble_weights,
            'feature_config': self.feature_config
        }
        
        model_file = save_path / f"fraud_model_v{self.model_version}.joblib"
        joblib.dump(model_data, model_file)
        
        # Save metadata
        metadata = {
            'version': self.model_version,
            'created_at': datetime.now().isoformat(),
            'model_type': 'ensemble_fraud_detector',
            'feature_count': len(self.feature_names) if self.feature_names else 0
        }
        
        metadata_file = save_path / "model_metadata.json"
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info(f"Model saved to {model_file}")
        return str(model_file)
    
    def load_model(self, path: Optional[str] = None) -> bool:
        """
        Load trained model from disk.
        
        Args:
            path: Load path
            
        Returns:
            bool: True if successful
        """
        load_path = Path(path or self.model_path)
        model_file = load_path / f"fraud_model_v{self.model_version}.joblib"
        
        if not model_file.exists():
            logger.error(f"Model file not found: {model_file}")
            return False
        
        try:
            model_data = joblib.load(model_file)
            
            self.models = model_data['models']
            self.scalers = model_data['scalers']
            self.feature_names = model_data.get('feature_names', [])
            self.last_training = model_data.get('last_training')
            self.ensemble_weights = model_data.get('ensemble_weights', self.ensemble_weights)
            self.feature_config = model_data.get('feature_config', self.feature_config)
            
            self.is_trained = True
            logger.info(f"Model loaded from {model_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False
    
    def get_feature_importance(self) -> Dict[str, List[float]]:
        """
        Get feature importance from trained models.
        
        Returns:
            Dict containing feature importance for each model
        """
        if not self.is_trained:
            raise ValueError("Model must be trained to get feature importance")
        
        importance_data = {}
        
        for model_name, model in self.models.items():
            if hasattr(model, 'feature_importances_'):
                importance_data[model_name] = model.feature_importances_.tolist()
        
        return importance_data
