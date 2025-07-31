"""
Validation utilities for fraud detection system.
"""

import re
from datetime import datetime
from typing import Dict, Any, List
from decimal import Decimal, InvalidOperation

from fraud_detection_api.models.schemas import TransactionCreate


def validate_transaction_data(transaction_data: TransactionCreate) -> List[str]:
    """
    Validate transaction data.
    
    Args:
        transaction_data: Transaction data to validate
        
    Returns:
        List of validation errors (empty if valid)
    """
    errors = []
    
    # Validate amount
    if transaction_data.amount <= 0:
        errors.append("Transaction amount must be positive")
    
    if transaction_data.amount > Decimal('1000000'):  # 1 million limit
        errors.append("Transaction amount exceeds maximum limit")
    
    # Validate merchant category
    valid_categories = [
        'retail', 'grocery', 'gas', 'restaurant', 'online', 
        'atm', 'transfer', 'payment', 'subscription'
    ]
    if transaction_data.merchant_category not in valid_categories:
        errors.append(f"Invalid merchant category: {transaction_data.merchant_category}")
    
    # Validate transaction type
    valid_types = ['purchase', 'withdrawal', 'transfer', 'payment', 'refund']
    if transaction_data.transaction_type not in valid_types:
        errors.append(f"Invalid transaction type: {transaction_data.transaction_type}")
    
    # Validate timestamp
    if transaction_data.timestamp > datetime.utcnow():
        errors.append("Transaction timestamp cannot be in the future")
    
    return errors


def validate_user_id(user_id: str) -> bool:
    """
    Validate user ID format.
    
    Args:
        user_id: User ID to validate
        
    Returns:
        True if valid
    """
    if not user_id:
        return False
    
    # User ID should be alphanumeric and between 3-50 characters
    pattern = r'^[a-zA-Z0-9_-]{3,50}$'
    return bool(re.match(pattern, user_id))


def validate_transaction_id(transaction_id: str) -> bool:
    """
    Validate transaction ID format.
    
    Args:
        transaction_id: Transaction ID to validate
        
    Returns:
        True if valid
    """
    if not transaction_id:
        return False
    
    # Transaction ID should be alphanumeric and between 10-100 characters
    pattern = r'^[a-zA-Z0-9_-]{10,100}$'
    return bool(re.match(pattern, transaction_id))


def validate_currency_code(currency_code: str) -> bool:
    """
    Validate ISO 4217 currency code.
    
    Args:
        currency_code: Currency code to validate
        
    Returns:
        True if valid
    """
    # Common currency codes (in production, use a complete list)
    valid_currencies = {
        'USD', 'EUR', 'GBP', 'JPY', 'CAD', 'AUD', 'CHF', 'CNY', 'SEK', 'NZD',
        'MXN', 'SGD', 'HKD', 'NOK', 'TRY', 'RUB', 'INR', 'BRL', 'ZAR', 'KRW'
    }
    
    return currency_code in valid_currencies


def validate_ip_address(ip_address: str) -> bool:
    """
    Validate IP address format.
    
    Args:
        ip_address: IP address to validate
        
    Returns:
        True if valid
    """
    if not ip_address:
        return False
    
    # IPv4 pattern
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    
    # IPv6 pattern (simplified)
    ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
    
    if re.match(ipv4_pattern, ip_address):
        # Validate IPv4 octets
        octets = ip_address.split('.')
        return all(0 <= int(octet) <= 255 for octet in octets)
    
    return bool(re.match(ipv6_pattern, ip_address))


def validate_email(email: str) -> bool:
    """
    Validate email format.
    
    Args:
        email: Email to validate
        
    Returns:
        True if valid
    """
    if not email:
        return False
    
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_phone_number(phone: str) -> bool:
    """
    Validate phone number format.
    
    Args:
        phone: Phone number to validate
        
    Returns:
        True if valid
    """
    if not phone:
        return False
    
    # Remove common formatting characters
    cleaned = re.sub(r'[\s\-\(\)\+]', '', phone)
    
    # Should be 10-15 digits
    pattern = r'^\d{10,15}$'
    return bool(re.match(pattern, cleaned))


def sanitize_input(input_str: str, max_length: int = 1000) -> str:
    """
    Sanitize input string to prevent injection attacks.
    
    Args:
        input_str: Input string to sanitize
        max_length: Maximum allowed length
        
    Returns:
        Sanitized string
    """
    if not input_str:
        return ""
    
    # Truncate to max length
    sanitized = input_str[:max_length]
    
    # Remove potentially dangerous characters
    dangerous_chars = ['<', '>', '"', "'", '&', ';', '(', ')', '|', '`', '$']
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, '')
    
    return sanitized.strip()


def validate_amount_format(amount_str: str) -> tuple[bool, Decimal]:
    """
    Validate and parse amount string.
    
    Args:
        amount_str: Amount string to validate
        
    Returns:
        Tuple of (is_valid, parsed_amount)
    """
    try:
        amount = Decimal(amount_str)
        if amount < 0:
            return False, Decimal('0')
        return True, amount
    except (InvalidOperation, ValueError):
        return False, Decimal('0')
