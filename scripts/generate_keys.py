#!/usr/bin/env python3
"""
Generate cryptographic keys for RT-SRT
"""

import secrets
import string
import os
from pathlib import Path

def generate_secret_key(length=64):
    """Generate secure random string for SECRET_KEY"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()_+-="
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def generate_aes_key():
    """Generate 32-byte AES key"""
    return secrets.token_hex(16)  # 16 bytes = 32 hex chars

def create_env_file():
    """Create .env file with generated keys"""
    project_root = Path(__file__).parent.parent
    env_path = project_root / "server" / ".env"
    
    secret_key = generate_secret_key()
    aes_key = generate_aes_key()
    
    env_content = f"""# RT-SRT Server Configuration
# Generated keys - DO NOT COMMIT TO GIT

# Server Configuration
DEBUG=False
HOST=0.0.0.0
PORT=8000
WORKERS=1

# Security
SECRET_KEY={secret_key}
JWT_ALGORITHM=HS256
JWT_EXPIRATION_HOURS=24
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8000

# Telegram Bot (REPLACE WITH YOUR VALUES)
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
AES_KEY={aes_key}

# WebSocket
WS_HEARTBEAT_INTERVAL=30
WS_MAX_CONNECTIONS=100

# Rate Limiting
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_PERIOD=60
"""
    
    # Create .env file
    env_path.write_text(env_content)
    
    print(f"✅ Generated .env file: {env_path}")
    print(f"📁 SECRET_KEY: {secret_key[:10]}...{secret_key[-10:]}")
    print(f"🔐 AES_KEY: {aes_key}")
    print()
    print("⚠️  IMPORTANT:")
    print("1. Replace TELEGRAM_BOT_TOKEN with your actual bot token")
    print("2. Replace TELEGRAM_ALLOWED_USERS with your Telegram user IDs")
    print("3. Keep these keys secret - never commit to git!")
    print("4. Add .env to .gitignore")

if __name__ == "__main__":
    create_env_file()