"""
Security utilities for authentication, authorization, and encryption.
"""

import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Any, Union, Optional
import logging

from passlib.context import CryptContext
from jose import JWTError, jwt
from cryptography.fernet import Fernet
import bcrypt

from fraud_detection_api.core.config import settings

logger = logging.getLogger(__name__)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Encryption instance
encryption_key = settings.SECRET_KEY.encode()[:32].ljust(32, b'0')
cipher_suite = Fernet(Fernet.generate_key())


class SecurityManager:
    """Centralized security management."""
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash.
        
        Args:
            plain_password: Plain text password
            hashed_password: Hashed password
            
        Returns:
            bool: True if password matches
        """
        try:
            return pwd_context.verify(plain_password, hashed_password)
        except Exception as e:
            logger.error(f"Password verification failed: {e}")
            return False
    
    @staticmethod
    def get_password_hash(password: str) -> str:
        """
        Hash a password.
        
        Args:
            password: Plain text password
            
        Returns:
            str: Hashed password
        """
        return pwd_context.hash(password)
    
    @staticmethod
    def create_access_token(
        data: dict, 
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Create JWT access token.
        
        Args:
            data: Data to encode in token
            expires_delta: Token expiration time
            
        Returns:
            str: JWT token
        """
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(
                minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
            )
        
        to_encode.update({"exp": expire, "type": "access"})
        
        try:
            encoded_jwt = jwt.encode(
                to_encode, 
                settings.JWT_SECRET_KEY, 
                algorithm=settings.JWT_ALGORITHM
            )
            return encoded_jwt
        except Exception as e:
            logger.error(f"Token creation failed: {e}")
            raise
    
    @staticmethod
    def create_refresh_token(data: dict) -> str:
        """
        Create JWT refresh token.
        
        Args:
            data: Data to encode in token
            
        Returns:
            str: JWT refresh token
        """
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(
            minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES
        )
        to_encode.update({"exp": expire, "type": "refresh"})
        
        try:
            encoded_jwt = jwt.encode(
                to_encode,
                settings.JWT_SECRET_KEY,
                algorithm=settings.JWT_ALGORITHM
            )
            return encoded_jwt
        except Exception as e:
            logger.error(f"Refresh token creation failed: {e}")
            raise
    
    @staticmethod
    def verify_token(token: str) -> Optional[dict]:
        """
        Verify and decode JWT token.
        
        Args:
            token: JWT token
            
        Returns:
            dict: Decoded token data or None if invalid
        """
        try:
            payload = jwt.decode(
                token,
                settings.JWT_SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM]
            )
            return payload
        except JWTError as e:
            logger.warning(f"Token verification failed: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected token verification error: {e}")
            return None
    
    @staticmethod
    def encrypt_sensitive_data(data: str) -> str:
        """
        Encrypt sensitive data.
        
        Args:
            data: Data to encrypt
            
        Returns:
            str: Encrypted data
        """
        try:
            encrypted_data = cipher_suite.encrypt(data.encode())
            return encrypted_data.decode()
        except Exception as e:
            logger.error(f"Data encryption failed: {e}")
            raise
    
    @staticmethod
    def decrypt_sensitive_data(encrypted_data: str) -> str:
        """
        Decrypt sensitive data.
        
        Args:
            encrypted_data: Encrypted data
            
        Returns:
            str: Decrypted data
        """
        try:
            decrypted_data = cipher_suite.decrypt(encrypted_data.encode())
            return decrypted_data.decode()
        except Exception as e:
            logger.error(f"Data decryption failed: {e}")
            raise
    
    @staticmethod
    def generate_api_key(length: int = 32) -> str:
        """
        Generate secure API key.
        
        Args:
            length: Key length
            
        Returns:
            str: Generated API key
        """
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def hash_api_key(api_key: str) -> str:
        """
        Hash API key for storage.
        
        Args:
            api_key: API key to hash
            
        Returns:
            str: Hashed API key
        """
        return hashlib.sha256(api_key.encode()).hexdigest()
    
    @staticmethod
    def generate_transaction_id() -> str:
        """
        Generate unique transaction ID.
        
        Returns:
            str: Transaction ID
        """
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        random_part = secrets.token_hex(8)
        return f"TXN_{timestamp}_{random_part}"
    
    @staticmethod
    def validate_input(data: Any, max_length: int = 1000) -> bool:
        """
        Basic input validation for security.
        
        Args:
            data: Data to validate
            max_length: Maximum allowed length
            
        Returns:
            bool: True if valid
        """
        if isinstance(data, str):
            # Check for common injection patterns
            suspicious_patterns = [
                "<script", "javascript:", "sql", "union", "select",
                "insert", "update", "delete", "drop", "exec"
            ]
            
            data_lower = data.lower()
            for pattern in suspicious_patterns:
                if pattern in data_lower:
                    logger.warning(f"Suspicious input detected: {pattern}")
                    return False
            
            # Check length
            if len(data) > max_length:
                logger.warning(f"Input too long: {len(data)} > {max_length}")
                return False
        
        return True


class RateLimiter:
    """Simple in-memory rate limiter."""
    
    def __init__(self):
        self._requests = {}
    
    def is_allowed(
        self, 
        identifier: str, 
        max_requests: int = None, 
        window_seconds: int = None
    ) -> bool:
        """
        Check if request is allowed under rate limit.
        
        Args:
            identifier: Unique identifier (user ID, IP, etc.)
            max_requests: Maximum requests allowed
            window_seconds: Time window in seconds
            
        Returns:
            bool: True if request is allowed
        """
        max_requests = max_requests or settings.RATE_LIMIT_REQUESTS
        window_seconds = window_seconds or settings.RATE_LIMIT_WINDOW
        
        now = datetime.utcnow()
        window_start = now - timedelta(seconds=window_seconds)
        
        # Clean old entries
        if identifier in self._requests:
            self._requests[identifier] = [
                req_time for req_time in self._requests[identifier]
                if req_time > window_start
            ]
        else:
            self._requests[identifier] = []
        
        # Check limit
        if len(self._requests[identifier]) >= max_requests:
            logger.warning(f"Rate limit exceeded for {identifier}")
            return False
        
        # Add current request
        self._requests[identifier].append(now)
        return True


# Global instances
security_manager = SecurityManager()
rate_limiter = RateLimiter()
