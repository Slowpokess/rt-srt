"""
User model and authentication utilities
"""

from datetime import datetime, timedelta
from typing import Optional
import hashlib
import secrets
from passlib.context import CryptContext
import jwt

from .log_model import User
from ..config import settings

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class UserManager:
    """User management utilities"""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password"""
        return pwd_context.hash(password)
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a password against a hash"""
        return pwd_context.verify(plain_password, hashed_password)
    
    @staticmethod
    def generate_api_token() -> str:
        """Generate a secure API token"""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def create_access_token(user_id: int, expires_delta: Optional[timedelta] = None) -> str:
        """Create a JWT access token"""
        expire = datetime.utcnow() + (expires_delta or timedelta(hours=settings.jwt_expiration_hours))
        payload = {
            "sub": str(user_id),
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "access"
        }
        return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)
    
    @staticmethod
    def verify_access_token(token: str) -> Optional[int]:
        """Verify and decode a JWT access token"""
        try:
            payload = jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
            if payload.get("type") != "access":
                return None
            user_id = payload.get("sub")
            return int(user_id) if user_id else None
        except (jwt.ExpiredSignatureError, jwt.JWTError, ValueError):
            return None
    
    @staticmethod
    def create_telegram_auth_token(telegram_user_id: int) -> str:
        """Create a token for Telegram authentication"""
        payload = {
            "telegram_id": telegram_user_id,
            "exp": datetime.utcnow() + timedelta(minutes=5),
            "type": "telegram_auth"
        }
        return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)
    
    @staticmethod
    def verify_telegram_auth_token(token: str) -> Optional[int]:
        """Verify Telegram authentication token"""
        try:
            payload = jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
            if payload.get("type") != "telegram_auth":
                return None
            return payload.get("telegram_id")
        except (jwt.ExpiredSignatureError, jwt.JWTError):
            return None


# Export all models
__all__ = ["User", "UserManager"]