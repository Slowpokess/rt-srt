"""
RT-SRT Server Configuration
Manages all server settings and environment variables
"""

import os
from pathlib import Path
from typing import List, Optional
from pydantic import BaseSettings, Field, validator


class Settings(BaseSettings):
    """Main settings class using Pydantic for validation"""
    
    # Application settings
    app_name: str = "RT-SRT Server"
    app_version: str = "1.0.0"
    debug: bool = Field(False, env="DEBUG")
    
    # Server settings
    host: str = Field("0.0.0.0", env="HOST")
    port: int = Field(8000, env="PORT")
    workers: int = Field(1, env="WORKERS")
    
    # Security settings
    secret_key: str = Field(..., env="SECRET_KEY")
    jwt_algorithm: str = Field("HS256", env="JWT_ALGORITHM")
    jwt_expiration_hours: int = Field(24, env="JWT_EXPIRATION_HOURS")
    allowed_origins: List[str] = Field(
        ["http://localhost:3000", "http://localhost:8000"],
        env="ALLOWED_ORIGINS"
    )
    
    # Telegram Bot settings
    telegram_bot_token: str = Field(..., env="TELEGRAM_BOT_TOKEN")
    telegram_allowed_users: List[int] = Field([], env="TELEGRAM_ALLOWED_USERS")
    telegram_log_channel: Optional[int] = Field(None, env="TELEGRAM_LOG_CHANNEL")
    
    # Database settings
    database_url: str = Field(
        "sqlite:///./rt_srt.db",
        env="DATABASE_URL"
    )
    database_echo: bool = Field(False, env="DATABASE_ECHO")
    
    # File storage settings
    upload_dir: Path = Field(Path("./uploads"), env="UPLOAD_DIR")
    logs_dir: Path = Field(Path("./logs"), env="LOGS_DIR")
    max_upload_size: int = Field(10 * 1024 * 1024, env="MAX_UPLOAD_SIZE")  # 10MB
    
    # Encryption settings
    aes_key: str = Field(..., env="AES_KEY")
    aes_key_size: int = 32  # 256 bits
    
    # WebSocket settings
    ws_heartbeat_interval: int = Field(30, env="WS_HEARTBEAT_INTERVAL")
    ws_max_connections: int = Field(100, env="WS_MAX_CONNECTIONS")
    
    # Rate limiting
    rate_limit_requests: int = Field(100, env="RATE_LIMIT_REQUESTS")
    rate_limit_period: int = Field(60, env="RATE_LIMIT_PERIOD")  # seconds
    
    @validator("telegram_allowed_users", pre=True)
    def parse_telegram_users(cls, v):
        """Parse comma-separated user IDs"""
        if isinstance(v, str):
            return [int(uid.strip()) for uid in v.split(",") if uid.strip()]
        return v
    
    @validator("allowed_origins", pre=True)
    def parse_allowed_origins(cls, v):
        """Parse comma-separated origins"""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v
    
    @validator("upload_dir", "logs_dir")
    def create_directories(cls, v):
        """Ensure directories exist"""
        v = Path(v)
        v.mkdir(parents=True, exist_ok=True)
        return v
    
    @validator("aes_key")
    def validate_aes_key(cls, v):
        """Validate AES key length"""
        if len(v) != 32:  # 256 bits
            raise ValueError("AES key must be 32 characters (256 bits)")
        return v
    
    @validator("secret_key")
    def validate_secret_key(cls, v):
        """Ensure secret key is strong"""
        if len(v) < 32:
            raise ValueError("Secret key must be at least 32 characters")
        return v
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
    
    def get_log_path(self, agent_id: str, timestamp: str) -> Path:
        """Generate path for storing agent logs"""
        return self.logs_dir / agent_id / f"{timestamp}.json"
    
    def get_upload_path(self, filename: str) -> Path:
        """Generate path for uploaded files"""
        return self.upload_dir / filename
    
    @property
    def database_settings(self) -> dict:
        """Get database connection settings"""
        return {
            "echo": self.database_echo,
            "pool_pre_ping": True,
            "pool_recycle": 3600,
        }


# Create global settings instance
settings = Settings()


# Helper functions
def get_jwt_secret() -> str:
    """Get JWT secret key"""
    return settings.secret_key


def is_telegram_user_allowed(user_id: int) -> bool:
    """Check if Telegram user is allowed"""
    if not settings.telegram_allowed_users:
        return True  # If no users specified, allow all
    return user_id in settings.telegram_allowed_users


def get_db_url() -> str:
    """Get database URL"""
    return settings.database_url


# Example .env file content
ENV_EXAMPLE = """
# Server Configuration
DEBUG=False
HOST=0.0.0.0
PORT=8000
WORKERS=1

# Security
SECRET_KEY=your-super-secret-key-change-this-in-production
JWT_ALGORITHM=HS256
JWT_EXPIRATION_HOURS=24
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8000

# Telegram Bot
TELEGRAM_BOT_TOKEN=your-telegram-bot-token
TELEGRAM_ALLOWED_USERS=123456789,987654321
TELEGRAM_LOG_CHANNEL=-1001234567890

# Database
DATABASE_URL=sqlite:///./rt_srt.db
DATABASE_ECHO=False

# File Storage
UPLOAD_DIR=./uploads
LOGS_DIR=./logs
MAX_UPLOAD_SIZE=10485760

# Encryption
AES_KEY=your-32-character-aes-key-change

# WebSocket
WS_HEARTBEAT_INTERVAL=30
WS_MAX_CONNECTIONS=100

# Rate Limiting
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_PERIOD=60
"""

# Create .env.example if it doesn't exist
env_example_path = Path(__file__).parent.parent / ".env.example"
if not env_example_path.exists():
    env_example_path.write_text(ENV_EXAMPLE.strip())