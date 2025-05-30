#!/bin/bash

# RT-SRT System Launcher
# Автоматический запуск всех компонентов системы

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project root
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"

echo -e "${BLUE}🚀 RT-SRT System Launcher${NC}"
echo -e "Project root: ${PROJECT_ROOT}"
echo ""

# Function to check if port is available
check_port() {
    local port=$1
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
        return 1
    else
        return 0
    fi
}

# Function to wait for server to start
wait_for_server() {
    local url=$1
    local max_attempts=30
    local attempt=1
    
    echo -e "${YELLOW}Waiting for server to start...${NC}"
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s "$url" >/dev/null 2>&1; then
            echo -e "${GREEN}Server is responding!${NC}"
            return 0
        fi
        
        echo -n "."
        sleep 1
        attempt=$((attempt + 1))
    done
    
    echo -e "\n${RED}Server failed to start within $max_attempts seconds${NC}"
    return 1
}

# Function to start server
start_server() {
    echo -e "\n${BLUE}📡 Starting RT-SRT Server...${NC}"
    
    # Check if port 8000 is available
    if ! check_port 8000; then
        echo -e "${RED}Port 8000 is already in use!${NC}"
        echo -e "Kill existing process: ${YELLOW}lsof -ti:8000 | xargs kill -9${NC}"
        return 1
    fi
    
    cd "${PROJECT_ROOT}/server"
    
    # Check if virtual environment exists
    if [ ! -d "venv" ]; then
        echo -e "${YELLOW}Creating Python virtual environment...${NC}"
        python3 -m venv venv
        source venv/bin/activate
        pip install --upgrade pip
        pip install -r requirements.txt
    else
        source venv/bin/activate
    fi
    
    # Check if .env exists
    if [ ! -f ".env" ]; then
        echo -e "${RED}Error: .env file not found!${NC}"
        echo -e "Copy and configure: ${YELLOW}cp .env.example .env${NC}"
        return 1
    fi
    
    # Start server in background
    echo -e "${YELLOW}Starting server process...${NC}"
    nohup python src/web_panel/app.py > server.log 2>&1 &
    SERVER_PID=$!
    
    # Save PID for later cleanup
    echo $SERVER_PID > server.pid
    
    # Wait for server to be ready
    if wait_for_server "http://localhost:8000/api/health"; then
        echo -e "${GREEN}✅ Server started successfully (PID: $SERVER_PID)${NC}"
        echo -e "   Web interface: ${BLUE}http://localhost:8000${NC}"
        echo -e "   API: ${BLUE}http://localhost:8000/api${NC}"
        echo -e "   Logs: ${PROJECT_ROOT}/server/server.log"
        return 0
    else
        echo -e "${RED}❌ Server failed to start${NC}"
        kill $SERVER_PID 2>/dev/null || true
        return 1
    fi
}

# Function to start agent
start_agent() {
    echo -e "\n${BLUE}🤖 Starting RT-SRT Agent...${NC}"
    
    cd "${PROJECT_ROOT}"
    
    # Check if agent binary exists
    if [ -f "dist/rt_srt_agent" ]; then
        AGENT_PATH="dist/rt_srt_agent"
    elif [ -f "build/build/rt_srt_agent" ]; then
        AGENT_PATH="build/build/rt_srt_agent"
    elif [ -f "build/agent/build/rt_srt_agent" ]; then
        AGENT_PATH="build/agent/build/rt_srt_agent"
    else
        echo -e "${RED}❌ Agent binary not found!${NC}"
        echo -e "Build the agent first: ${YELLOW}./scripts/build.sh${NC}"
        return 1
    fi
    
    # Check agent size
    AGENT_SIZE=$(du -k "$AGENT_PATH" | cut -f1)
    echo -e "Agent binary: $AGENT_PATH"
    echo -e "Agent size: ${AGENT_SIZE}KB"
    
    if [ $AGENT_SIZE -gt 1000 ]; then
        echo -e "${YELLOW}Warning: Agent size is large (${AGENT_SIZE}KB). Consider UPX packing.${NC}"
    fi
    
    # Start agent in background
    echo -e "${YELLOW}Starting agent process...${NC}"
    nohup "./$AGENT_PATH" > agent.log 2>&1 &
    AGENT_PID=$!
    
    # Save PID for later cleanup
    echo $AGENT_PID > agent.pid
    
    # Give agent time to initialize
    sleep 3
    
    # Check if agent is still running
    if kill -0 $AGENT_PID 2>/dev/null; then
        echo -e "${GREEN}✅ Agent started successfully (PID: $AGENT_PID)${NC}"
        echo -e "   Logs: ${PROJECT_ROOT}/agent.log"
        return 0
    else
        echo -e "${RED}❌ Agent failed to start${NC}"
        echo -e "Check logs: ${PROJECT_ROOT}/agent.log"
        return 1
    fi
}

# Function to start telegram bot
start_telegram_bot() {
    echo -e "\n${BLUE}📱 Starting Telegram Bot...${NC}"
    
    cd "${PROJECT_ROOT}/server"
    
    # Check if bot token is configured
    if ! grep -q "^TELEGRAM_BOT_TOKEN=" .env || grep -q "your-telegram-bot-token" .env; then
        echo -e "${YELLOW}⚠️  Telegram bot token not configured${NC}"
        echo -e "Configure in .env: ${YELLOW}TELEGRAM_BOT_TOKEN=your-real-token${NC}"
        echo -e "Skipping Telegram bot..."
        return 0
    fi
    
    source venv/bin/activate
    
    # Start bot in background
    echo -e "${YELLOW}Starting Telegram bot...${NC}"
    nohup python src/bot/bot.py > bot.log 2>&1 &
    BOT_PID=$!
    
    # Save PID for later cleanup
    echo $BOT_PID > bot.pid
    
    # Give bot time to initialize
    sleep 2
    
    # Check if bot is still running
    if kill -0 $BOT_PID 2>/dev/null; then
        echo -e "${GREEN}✅ Telegram bot started (PID: $BOT_PID)${NC}"
        echo -e "   Logs: ${PROJECT_ROOT}/server/bot.log"
        return 0
    else
        echo -e "${YELLOW}⚠️  Telegram bot failed to start${NC}"
        echo -e "Check logs: ${PROJECT_ROOT}/server/bot.log"
        return 0
    fi
}

# Function to show status
show_status() {
    echo -e "\n${BLUE}📊 System Status${NC}"
    echo -e "=================="
    
    # Server status
    if [ -f "${PROJECT_ROOT}/server/server.pid" ]; then
        SERVER_PID=$(cat "${PROJECT_ROOT}/server/server.pid")
        if kill -0 $SERVER_PID 2>/dev/null; then
            echo -e "🟢 Server: Running (PID: $SERVER_PID)"
            echo -e "   URL: http://localhost:8000"
        else
            echo -e "🔴 Server: Not running"
        fi
    else
        echo -e "🔴 Server: Not started"
    fi
    
    # Agent status
    if [ -f "${PROJECT_ROOT}/agent.pid" ]; then
        AGENT_PID=$(cat "${PROJECT_ROOT}/agent.pid")
        if kill -0 $AGENT_PID 2>/dev/null; then
            echo -e "🟢 Agent: Running (PID: $AGENT_PID)"
        else
            echo -e "🔴 Agent: Not running"
        fi
    else
        echo -e "🔴 Agent: Not started"
    fi
    
    # Bot status
    if [ -f "${PROJECT_ROOT}/server/bot.pid" ]; then
        BOT_PID=$(cat "${PROJECT_ROOT}/server/bot.pid")
        if kill -0 $BOT_PID 2>/dev/null; then
            echo -e "🟢 Telegram Bot: Running (PID: $BOT_PID)"
        else
            echo -e "🔴 Telegram Bot: Not running"
        fi
    else
        echo -e "🔴 Telegram Bot: Not started"
    fi
    
    echo ""
}

# Function to stop all services
stop_services() {
    echo -e "\n${YELLOW}🛑 Stopping RT-SRT Services...${NC}"
    
    # Stop agent
    if [ -f "${PROJECT_ROOT}/agent.pid" ]; then
        AGENT_PID=$(cat "${PROJECT_ROOT}/agent.pid")
        if kill -0 $AGENT_PID 2>/dev/null; then
            echo -e "Stopping agent (PID: $AGENT_PID)..."
            kill $AGENT_PID
            rm -f "${PROJECT_ROOT}/agent.pid"
        fi
    fi
    
    # Stop bot
    if [ -f "${PROJECT_ROOT}/server/bot.pid" ]; then
        BOT_PID=$(cat "${PROJECT_ROOT}/server/bot.pid")
        if kill -0 $BOT_PID 2>/dev/null; then
            echo -e "Stopping Telegram bot (PID: $BOT_PID)..."
            kill $BOT_PID
            rm -f "${PROJECT_ROOT}/server/bot.pid"
        fi
    fi
    
    # Stop server
    if [ -f "${PROJECT_ROOT}/server/server.pid" ]; then
        SERVER_PID=$(cat "${PROJECT_ROOT}/server/server.pid")
        if kill -0 $SERVER_PID 2>/dev/null; then
            echo -e "Stopping server (PID: $SERVER_PID)..."
            kill $SERVER_PID
            rm -f "${PROJECT_ROOT}/server/server.pid"
        fi
    fi
    
    echo -e "${GREEN}✅ All services stopped${NC}"
}

# Function to show help
show_help() {
    echo -e "${BLUE}RT-SRT System Launcher${NC}"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  start     - Start all services (default)"
    echo "  stop      - Stop all services"
    echo "  restart   - Restart all services"
    echo "  status    - Show service status"
    echo "  server    - Start only server"
    echo "  agent     - Start only agent"
    echo "  bot       - Start only Telegram bot"
    echo "  help      - Show this help"
    echo ""
    echo "Examples:"
    echo "  $0              # Start all services"
    echo "  $0 start        # Start all services"
    echo "  $0 status       # Check status"
    echo "  $0 stop         # Stop everything"
    echo ""
}

# Main function
main() {
    case "${1:-start}" in
        "start")
            echo -e "${GREEN}🚀 Starting RT-SRT System...${NC}"
            start_server
            if [ $? -eq 0 ]; then
                start_agent
                start_telegram_bot
                show_status
                echo -e "\n${GREEN}🎉 RT-SRT System started successfully!${NC}"
                echo -e "Web interface: ${BLUE}http://localhost:8000${NC}"
                echo -e "Credentials: ${YELLOW}admin / changeme${NC}"
            fi
            ;;
        "stop")
            stop_services
            ;;
        "restart")
            stop_services
            sleep 2
            main start
            ;;
        "status")
            show_status
            ;;
        "server")
            start_server
            ;;
        "agent")
            start_agent
            ;;
        "bot")
            start_telegram_bot
            ;;
        "help"|"-h"|"--help")
            show_help
            ;;
        *)
            echo -e "${RED}Unknown command: $1${NC}"
            show_help
            exit 1
            ;;
    esac
}

# Handle Ctrl+C
trap 'echo -e "\n${YELLOW}Interrupted! Stopping services...${NC}"; stop_services; exit 1' INT

# Run main function
main "$@"