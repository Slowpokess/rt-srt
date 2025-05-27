#!/bin/bash

# RT-SRT Deploy Script
# Handles deployment of built components

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"

# Deployment configuration
TARGET_HOST="${1:-localhost}"
TARGET_USER="${2:-$USER}"
DEPLOY_PATH="${3:-/opt/rt-srt}"

echo -e "${BLUE}==== RT-SRT Deployment System ====${NC}"
echo -e "Target host: ${TARGET_HOST}"
echo -e "Target user: ${TARGET_USER}"
echo -e "Deploy path: ${DEPLOY_PATH}"
echo ""

# Function to check if build exists
check_build() {
    echo -e "${YELLOW}Checking build artifacts...${NC}"
    
    if [ ! -d "${PROJECT_ROOT}/dist" ]; then
        echo -e "${RED}Error: Distribution not found. Run ./build.sh first${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}Build artifacts found!${NC}"
}

# Function to deploy server
deploy_server() {
    echo -e "\n${BLUE}Deploying Server...${NC}"
    
    # Copy server files
    if [ "$TARGET_HOST" = "localhost" ]; then
        mkdir -p "${DEPLOY_PATH}/server"
        cp -r "${PROJECT_ROOT}/dist/server/"* "${DEPLOY_PATH}/server/"
        cp "${PROJECT_ROOT}/server/requirements.txt" "${DEPLOY_PATH}/server/"
    else
        ssh "${TARGET_USER}@${TARGET_HOST}" "mkdir -p ${DEPLOY_PATH}/server"
        scp -r "${PROJECT_ROOT}/dist/server/"* "${TARGET_USER}@${TARGET_HOST}:${DEPLOY_PATH}/server/"
        scp "${PROJECT_ROOT}/server/requirements.txt" "${TARGET_USER}@${TARGET_HOST}:${DEPLOY_PATH}/server/"
    fi
    
    # Create systemd service
    if [ "$TARGET_HOST" = "localhost" ]; then
        create_systemd_service
    else
        ssh "${TARGET_USER}@${TARGET_HOST}" "$(declare -f create_systemd_service); create_systemd_service"
    fi
    
    echo -e "${GREEN}Server deployed successfully!${NC}"
}

# Function to create systemd service
create_systemd_service() {
    cat > /tmp/rt-srt-server.service << EOF
[Unit]
Description=RT-SRT Server
After=network.target

[Service]
Type=simple
User=${TARGET_USER}
WorkingDirectory=${DEPLOY_PATH}/server
ExecStart=/usr/bin/python3 web_panel/app.py
Restart=always
RestartSec=10
Environment=PATH=/usr/bin:/usr/local/bin

[Install]
WantedBy=multi-user.target
EOF
    
    sudo mv /tmp/rt-srt-server.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable rt-srt-server
    
    echo -e "${GREEN}Systemd service created and enabled${NC}"
}

# Function to deploy agent
deploy_agent() {
    echo -e "\n${BLUE}Deploying Agent...${NC}"
    
    # Create agent package
    AGENT_FILE=$(find "${PROJECT_ROOT}/dist" -name "rt_srt_agent*" | head -1)
    
    if [ -z "$AGENT_FILE" ]; then
        echo -e "${RED}Error: Agent binary not found${NC}"
        exit 1
    fi
    
    # Copy agent
    if [ "$TARGET_HOST" = "localhost" ]; then
        mkdir -p "${DEPLOY_PATH}/agent"
        cp "$AGENT_FILE" "${DEPLOY_PATH}/agent/"
    else
        ssh "${TARGET_USER}@${TARGET_HOST}" "mkdir -p ${DEPLOY_PATH}/agent"
        scp "$AGENT_FILE" "${TARGET_USER}@${TARGET_HOST}:${DEPLOY_PATH}/agent/"
    fi
    
    echo -e "${GREEN}Agent deployed successfully!${NC}"
}

# Function to start services
start_services() {
    echo -e "\n${BLUE}Starting services...${NC}"
    
    if [ "$TARGET_HOST" = "localhost" ]; then
        sudo systemctl start rt-srt-server
        sudo systemctl status rt-srt-server --no-pager
    else
        ssh "${TARGET_USER}@${TARGET_HOST}" "sudo systemctl start rt-srt-server"
        ssh "${TARGET_USER}@${TARGET_HOST}" "sudo systemctl status rt-srt-server --no-pager"
    fi
    
    echo -e "${GREEN}Services started!${NC}"
}

# Function to show deployment info
show_deployment_info() {
    echo -e "\n${GREEN}==== Deployment Complete! ====${NC}"
    echo -e "Server deployed to: ${TARGET_HOST}:${DEPLOY_PATH}/server"
    echo -e "Agent deployed to: ${TARGET_HOST}:${DEPLOY_PATH}/agent"
    echo -e ""
    echo -e "${YELLOW}Next steps:${NC}"
    echo -e "1. Configure ${DEPLOY_PATH}/server/.env with Telegram bot token"
    echo -e "2. Restart service: sudo systemctl restart rt-srt-server"
    echo -e "3. Check logs: sudo journalctl -u rt-srt-server -f"
    echo -e "4. Deploy agent to target systems from ${DEPLOY_PATH}/agent/"
}

# Main deployment process
main() {
    check_build
    
    # Deploy components
    deploy_server
    deploy_agent
    
    # Start services
    start_services
    
    # Show info
    show_deployment_info
}

# Run main function
main "$@"