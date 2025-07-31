"""
Helper utilities for fraud detection system.
"""

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from decimal import Decimal
import json


def calculate_risk_score(factors: Dict[str, float], weights: Dict[str, float]) -> float:
    """
    Calculate weighted risk score based on multiple factors.
    
    Args:
        factors: Dictionary of risk factors and their values (0-1)
        weights: Dictionary of weights for each factor
        
    Returns:
        Weighted risk score (0-1)
    """
    total_score = 0.0
    total_weight = 0.0
    
    for factor, value in factors.items():
        if factor in weights:
            weight = weights[factor]
            total_score += value * weight
            total_weight += weight
    
    if total_weight == 0:
        return 0.0
    
    return min(total_score / total_weight, 1.0)


def format_currency(amount: Decimal, currency_code: str = "TRY") -> str:
    """
    Format currency amount for display.
    
    Args:
        amount: Amount to format
        currency_code: Currency code
        
    Returns:
        Formatted currency string
    """
    currency_symbols = {
        'USD': '$',
        'EUR': '€',
        'GBP': '£',
        'TRY': '₺',
        'JPY': '¥'
    }
    
    symbol = currency_symbols.get(currency_code, currency_code)
    
    # Format with 2 decimal places for most currencies, 0 for JPY
    decimals = 0 if currency_code == 'JPY' else 2
    
    return f"{symbol}{amount:,.{decimals}f}"


def generate_transaction_id() -> str:
    """Generate a unique transaction ID."""
    timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    random_part = secrets.token_hex(8)
    return f"TXN_{timestamp}_{random_part.upper()}"


def generate_correlation_id() -> str:
    """Generate a unique correlation ID."""
    return secrets.token_hex(16)


def hash_sensitive_data(data: str, salt: Optional[str] = None) -> str:
    """
    Hash sensitive data for storage/comparison.
    
    Args:
        data: Data to hash
        salt: Optional salt (generated if not provided)
        
    Returns:
        Hashed data
    """
    if salt is None:
        salt = secrets.token_hex(16)
    
    return hashlib.pbkdf2_hex(data.encode(), salt.encode(), 100000)


def verify_hmac_signature(data: str, signature: str, secret: str) -> bool:
    """
    Verify HMAC signature for webhook/API security.
    
    Args:
        data: Original data
        signature: Provided signature
        secret: Secret key
        
    Returns:
        True if signature is valid
    """
    expected_signature = hmac.new(
        secret.encode(),
        data.encode(),
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(signature, expected_signature)


def calculate_time_velocity(transactions: List[Dict[str, Any]], window_minutes: int = 60) -> int:
    """
    Calculate transaction velocity (count) within a time window.
    
    Args:
        transactions: List of transactions with timestamps
        window_minutes: Time window in minutes
        
    Returns:
        Number of transactions in the window
    """
    if not transactions:
        return 0
    
    cutoff_time = datetime.utcnow() - timedelta(minutes=window_minutes)
    
    count = 0
    for txn in transactions:
        txn_time = datetime.fromisoformat(txn.get('timestamp', ''))
        if txn_time >= cutoff_time:
            count += 1
    
    return count


def calculate_amount_velocity(transactions: List[Dict[str, Any]], window_minutes: int = 60) -> Decimal:
    """
    Calculate transaction amount velocity within a time window.
    
    Args:
        transactions: List of transactions with amounts and timestamps
        window_minutes: Time window in minutes
        
    Returns:
        Total amount in the window
    """
    if not transactions:
        return Decimal('0')
    
    cutoff_time = datetime.utcnow() - timedelta(minutes=window_minutes)
    
    total_amount = Decimal('0')
    for txn in transactions:
        txn_time = datetime.fromisoformat(txn.get('timestamp', ''))
        if txn_time >= cutoff_time:
            amount = Decimal(str(txn.get('amount', 0)))
            total_amount += amount
    
    return total_amount


def get_time_of_day_risk(hour: int) -> float:
    """
    Calculate risk score based on time of day.
    
    Args:
        hour: Hour of the day (0-23)
        
    Returns:
        Risk score (0-1)
    """
    # Higher risk during late night/early morning hours
    if 2 <= hour <= 5:
        return 0.8  # Very high risk
    elif 23 <= hour <= 1 or 6 <= hour <= 7:
        return 0.5  # Medium risk
    elif 8 <= hour <= 22:
        return 0.1  # Low risk (normal business hours)
    else:
        return 0.3  # Default medium-low risk


def get_day_of_week_risk(weekday: int) -> float:
    """
    Calculate risk score based on day of week.
    
    Args:
        weekday: Day of week (0=Monday, 6=Sunday)
        
    Returns:
        Risk score (0-1)
    """
    # Slightly higher risk on weekends
    if weekday >= 5:  # Saturday, Sunday
        return 0.3
    else:  # Monday-Friday
        return 0.1


def anonymize_sensitive_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Anonymize sensitive data for logging/monitoring.
    
    Args:
        data: Data dictionary to anonymize
        
    Returns:
        Anonymized data dictionary
    """
    sensitive_fields = {
        'user_id', 'email', 'phone', 'card_number', 'account_number',
        'ip_address', 'device_id', 'ssn', 'tax_id'
    }
    
    anonymized = data.copy()
    
    for field in sensitive_fields:
        if field in anonymized:
            value = str(anonymized[field])
            if len(value) > 4:
                # Show first 2 and last 2 characters, mask the rest
                anonymized[field] = value[:2] + '*' * (len(value) - 4) + value[-2:]
            else:
                anonymized[field] = '*' * len(value)
    
    return anonymized


def calculate_geographic_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Calculate distance between two geographic coordinates (Haversine formula).
    
    Args:
        lat1, lon1: First coordinate
        lat2, lon2: Second coordinate
        
    Returns:
        Distance in kilometers
    """
    import math
    
    # Convert to radians
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
    
    # Haversine formula
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
    c = 2 * math.asin(math.sqrt(a))
    
    # Earth's radius in kilometers
    earth_radius = 6371
    
    return earth_radius * c


def is_business_hours(dt: datetime, timezone_offset: int = 3) -> bool:
    """
    Check if datetime is within business hours (9 AM - 6 PM local time).
    
    Args:
        dt: Datetime to check
        timezone_offset: Timezone offset from UTC (Turkey is UTC+3)
        
    Returns:
        True if within business hours
    """
    local_time = dt + timedelta(hours=timezone_offset)
    hour = local_time.hour
    weekday = local_time.weekday()
    
    # Monday-Friday, 9 AM - 6 PM
    return 0 <= weekday <= 4 and 9 <= hour <= 18


def create_audit_log_entry(
    action: str,
    user_id: str,
    details: Dict[str, Any],
    correlation_id: str
) -> Dict[str, Any]:
    """
    Create standardized audit log entry.
    
    Args:
        action: Action performed
        user_id: User who performed the action
        details: Additional details
        correlation_id: Correlation ID
        
    Returns:
        Audit log entry
    """
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "action": action,
        "user_id": user_id,
        "details": details,
        "correlation_id": correlation_id,
        "ip_address": details.get("ip_address"),
        "user_agent": details.get("user_agent")
    }
