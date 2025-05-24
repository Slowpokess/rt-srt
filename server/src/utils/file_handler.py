"""
File handling utilities for managing uploaded logs and data
"""

import os
import shutil
import hashlib
import json
import zipfile
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple
import aiofiles
import magic

from ..config import settings


class FileHandler:
    """Handle file operations for logs and uploads"""
    
    def __init__(self):
        self.logs_dir = settings.logs_dir
        self.upload_dir = settings.upload_dir
        self._ensure_directories()
    
    def _ensure_directories(self):
        """Ensure required directories exist"""
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.upload_dir.mkdir(parents=True, exist_ok=True)
    
    def get_agent_log_dir(self, agent_id: str) -> Path:
        """Get or create agent's log directory"""
        agent_dir = self.logs_dir / agent_id
        agent_dir.mkdir(parents=True, exist_ok=True)
        return agent_dir
    
    def save_log_file(
        self,
        agent_id: str,
        data: bytes,
        log_type: str,
        timestamp: Optional[datetime] = None
    ) -> Tuple[Path, str]:
        """
        Save log file for agent
        Returns: (file_path, file_hash)
        """
        timestamp = timestamp or datetime.utcnow()
        
        # Create filename
        filename = f"{log_type}_{timestamp.strftime('%Y%m%d_%H%M%S')}.dat"
        
        # Get agent directory
        agent_dir = self.get_agent_log_dir(agent_id)
        file_path = agent_dir / filename
        
        # Calculate hash
        file_hash = hashlib.sha256(data).hexdigest()
        
        # Save file
        file_path.write_bytes(data)
        
        # Create metadata file
        metadata = {
            "agent_id": agent_id,
            "log_type": log_type,
            "timestamp": timestamp.isoformat(),
            "file_hash": file_hash,
            "file_size": len(data),
            "original_filename": filename
        }
        
        metadata_path = file_path.with_suffix('.meta.json')
        metadata_path.write_text(json.dumps(metadata, indent=2))
        
        return file_path, file_hash
    
    async def save_log_file_async(
        self,
        agent_id: str,
        data: bytes,
        log_type: str,
        timestamp: Optional[datetime] = None
    ) -> Tuple[Path, str]:
        """Async version of save_log_file"""
        timestamp = timestamp or datetime.utcnow()
        
        filename = f"{log_type}_{timestamp.strftime('%Y%m%d_%H%M%S')}.dat"
        agent_dir = self.get_agent_log_dir(agent_id)
        file_path = agent_dir / filename
        
        file_hash = hashlib.sha256(data).hexdigest()
        
        async with aiofiles.open(file_path, 'wb') as f:
            await f.write(data)
        
        metadata = {
            "agent_id": agent_id,
            "log_type": log_type,
            "timestamp": timestamp.isoformat(),
            "file_hash": file_hash,
            "file_size": len(data),
            "original_filename": filename
        }
        
        metadata_path = file_path.with_suffix('.meta.json')
        async with aiofiles.open(metadata_path, 'w') as f:
            await f.write(json.dumps(metadata, indent=2))
        
        return file_path, file_hash
    
    def read_log_file(self, file_path: Path) -> bytes:
        """Read log file"""
        if not file_path.exists():
            raise FileNotFoundError(f"Log file not found: {file_path}")
        
        return file_path.read_bytes()
    
    async def read_log_file_async(self, file_path: Path) -> bytes:
        """Async version of read_log_file"""
        if not file_path.exists():
            raise FileNotFoundError(f"Log file not found: {file_path}")
        
        async with aiofiles.open(file_path, 'rb') as f:
            return await f.read()
    
    def get_log_metadata(self, file_path: Path) -> Dict[str, Any]:
        """Get metadata for log file"""
        metadata_path = file_path.with_suffix('.meta.json')
        
        if metadata_path.exists():
            return json.loads(metadata_path.read_text())
        
        # Generate basic metadata if not found
        stat = file_path.stat()
        return {
            "file_size": stat.st_size,
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
        }
    
    def create_archive(
        self,
        agent_id: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Path:
        """Create archive of agent logs"""
        agent_dir = self.get_agent_log_dir(agent_id)
        
        # Create archive filename
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        archive_name = f"{agent_id}_logs_{timestamp}.zip"
        archive_path = self.upload_dir / archive_name
        
        with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for file_path in agent_dir.glob('*.dat'):
                # Check date range if specified
                if start_date or end_date:
                    metadata = self.get_log_metadata(file_path)
                    file_timestamp = datetime.fromisoformat(
                        metadata.get('timestamp', metadata.get('created'))
                    )
                    
                    if start_date and file_timestamp < start_date:
                        continue
                    if end_date and file_timestamp > end_date:
                        continue
                
                # Add file to archive
                zf.write(file_path, file_path.name)
                
                # Add metadata if exists
                metadata_path = file_path.with_suffix('.meta.json')
                if metadata_path.exists():
                    zf.write(metadata_path, metadata_path.name)
        
        return archive_path
    
    def cleanup_old_logs(self, days: int = 30):
        """Remove logs older than specified days"""
        cutoff_date = datetime.utcnow().timestamp() - (days * 24 * 60 * 60)
        
        removed_count = 0
        for agent_dir in self.logs_dir.iterdir():
            if agent_dir.is_dir():
                for file_path in agent_dir.glob('*.dat'):
                    if file_path.stat().st_mtime < cutoff_date:
                        # Remove data file and metadata
                        file_path.unlink()
                        metadata_path = file_path.with_suffix('.meta.json')
                        if metadata_path.exists():
                            metadata_path.unlink()
                        removed_count += 1
        
        return removed_count
    
    def get_storage_stats(self) -> Dict[str, Any]:
        """Get storage statistics"""
        total_size = 0
        file_count = 0
        agent_count = 0
        
        for agent_dir in self.logs_dir.iterdir():
            if agent_dir.is_dir():
                agent_count += 1
                for file_path in agent_dir.glob('*.dat'):
                    total_size += file_path.stat().st_size
                    file_count += 1
        
        return {
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / 1024 / 1024, 2),
            "file_count": file_count,
            "agent_count": agent_count,
            "average_file_size_kb": round(total_size / file_count / 1024, 2) if file_count > 0 else 0
        }
    
    def validate_upload(self, file_data: bytes, filename: str) -> Tuple[bool, Optional[str]]:
        """
        Validate uploaded file
        Returns: (is_valid, error_message)
        """
        # Check file size
        if len(file_data) > settings.max_upload_size:
            return False, f"File too large. Maximum size is {settings.max_upload_size / 1024 / 1024}MB"
        
        # Check file type (using python-magic)
        try:
            file_type = magic.from_buffer(file_data, mime=True)
            allowed_types = ['application/zip', 'application/octet-stream', 'application/json']
            
            if file_type not in allowed_types:
                return False, f"Invalid file type: {file_type}"
        except Exception:
            # If magic fails, continue validation
            pass
        
        # Check for malicious patterns
        if b'<script' in file_data or b'javascript:' in file_data:
            return False, "File contains potentially malicious content"
        
        return True, None


# Global file handler instance
file_handler = FileHandler()


# Export utilities
__all__ = [
    "FileHandler",
    "file_handler"
]