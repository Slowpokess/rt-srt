# RT-SRT Server

Backend server for RedTeam Stealth Recon Tool, providing API endpoints, Telegram bot integration, and web panel backend.

## Components

- **FastAPI Web Server**: RESTful API and WebSocket support
- **Telegram Bot**: Receive logs and manage agents via Telegram
- **SQLite Database**: Store agents, logs, and commands
- **Web Panel API**: Dashboard and management interface

## Quick Start

### 1. Setup Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment

Create `.env` file from example:
```bash
cp .env.example .env
```

Edit `.env` with your settings:
```env
# Required settings
SECRET_KEY=your-32-character-secret-key-here
TELEGRAM_BOT_TOKEN=your-telegram-bot-token
AES_KEY=your-32-character-aes-key-here

# Optional settings
TELEGRAM_ALLOWED_USERS=123456789,987654321
DEBUG=False
```

### 3. Initialize Database

```bash
# Run database migrations
alembic init alembic
alembic revision --autogenerate -m "Initial migration"
alembic upgrade head
```

### 4. Run Server

```bash
# Development mode (with auto-reload)
uvicorn src.web_panel.app:app --reload --host 0.0.0.0 --port 8000

# Production mode
uvicorn src.web_panel.app:app --host 0.0.0.0 --port 8000 --workers 4
```

### 5. Run Telegram Bot (Optional)

To run only the Telegram bot:
```bash
python -m src.bot.bot
```

## API Endpoints

### Authentication
- `POST /api/auth/login` - Login with username/password
- `GET /api/auth/me` - Get current user info

### Agents
- `GET /api/agents` - List all agents
- `GET /api/agents/{agent_id}` - Get agent details

### Logs
- `GET /api/logs` - List logs with filters
- `GET /api/logs/{log_id}` - Get log details

### Commands
- `POST /api/commands` - Create command for agent

### Statistics
- `GET /api/stats` - Get dashboard statistics

### WebSocket
- `WS /ws` - Real-time updates

## Default Credentials

**⚠️ IMPORTANT: Change immediately after first login!**

- Username: `admin`
- Password: `changeme`

## Telegram Bot Commands

- `/start` - Show welcome message
- `/status` - System status
- `/agents` - List active agents
- `/logs` - Recent logs
- `/stats` - Statistics

## Security Notes

1. **Change default credentials** immediately
2. **Use strong SECRET_KEY** - at least 32 characters
3. **Restrict Telegram access** - set TELEGRAM_ALLOWED_USERS
4. **Use HTTPS** in production
5. **Keep AES_KEY secure** - used for agent communication

## Directory Structure

```
server/
├── src/
│   ├── bot/           # Telegram bot
│   ├── models/        # Database models
│   ├── utils/         # Utilities
│   └── web_panel/     # FastAPI application
├── logs/              # Agent logs storage
├── uploads/           # File uploads
├── requirements.txt   # Python dependencies
└── .env              # Environment configuration
```

## Troubleshooting

### Bot not receiving messages
- Check TELEGRAM_BOT_TOKEN is correct
- Ensure bot privacy mode is disabled in BotFather
- Check firewall allows outgoing HTTPS

### Database errors
- Ensure write permissions on database file
- Check DATABASE_URL in .env
- Run migrations: `alembic upgrade head`

### Agent connection issues
- Verify AES_KEY matches between agent and server
- Check firewall allows incoming connections
- Ensure server is accessible from agent network

## Development

### Run Tests
```bash
pytest tests/
```

### Code Formatting
```bash
black src/
flake8 src/
```

### Type Checking
```bash
mypy src/
```