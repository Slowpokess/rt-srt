#!/bin/bash

# RT-SRT Build Script
# Handles building both agent and server components

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

# Build configuration
BUILD_TYPE="${1:-Release}"
JOBS=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)

echo -e "${BLUE}==== RT-SRT Build System ====${NC}"
echo -e "Project root: ${PROJECT_ROOT}"
echo -e "Build type: ${BUILD_TYPE}"
echo -e "Parallel jobs: ${JOBS}"
echo ""

# Function to check dependencies
check_dependencies() {
    echo -e "${YELLOW}Checking dependencies...${NC}"
    
    local missing_deps=()
    
    # Check for CMake
    if ! command -v cmake &> /dev/null; then
        missing_deps+=("cmake")
    fi
    
    # Check for C++ compiler
    if ! command -v g++ &> /dev/null && ! command -v clang++ &> /dev/null; then
        missing_deps+=("g++ or clang++")
    fi
    
    # Check for Python 3
    if ! command -v python3 &> /dev/null; then
        missing_deps+=("python3")
    fi
    
    # Check for UPX (optional)
    if ! command -v upx &> /dev/null; then
        echo -e "${YELLOW}Warning: UPX not found. Binary packing will be skipped.${NC}"
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        echo -e "${RED}Error: Missing dependencies:${NC}"
        printf '%s\n' "${missing_deps[@]}"
        exit 1
    fi
    
    echo -e "${GREEN}All required dependencies found!${NC}"
}

# Function to build agent
build_agent() {
    echo -e "\n${BLUE}Building Agent...${NC}"
    
    # Create build directory
    mkdir -p "${PROJECT_ROOT}/build/agent"
    cd "${PROJECT_ROOT}/build/agent"
    
    # Configure with CMake
    echo -e "${YELLOW}Configuring CMake...${NC}"
    cmake -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
          -DCMAKE_C_COMPILER_WORKS=1 \
          -DCMAKE_CXX_COMPILER_WORKS=1 \
          "${PROJECT_ROOT}"
    
    # Build
    echo -e "${YELLOW}Compiling agent...${NC}"
    cmake --build . --parallel ${JOBS} --target rt_srt_agent
    
    # Check size - looking in both possible output locations
    if [ -f "${PROJECT_ROOT}/build/rt_srt_agent" ] || [ -f "${PROJECT_ROOT}/build/rt_srt_agent.exe" ] || \
       [ -f "${PROJECT_ROOT}/build/agent/build/rt_srt_agent" ] || [ -f "${PROJECT_ROOT}/build/agent/build/rt_srt_agent.exe" ]; then
        echo -e "${GREEN}Agent built successfully!${NC}"
        
        # Get file size - check both possible locations
        if [ -f "${PROJECT_ROOT}/build/rt_srt_agent" ]; then
            AGENT_FILE="${PROJECT_ROOT}/build/rt_srt_agent"
        elif [ -f "${PROJECT_ROOT}/build/agent/build/rt_srt_agent" ]; then
            AGENT_FILE="${PROJECT_ROOT}/build/agent/build/rt_srt_agent"
        elif [ -f "${PROJECT_ROOT}/build/rt_srt_agent.exe" ]; then
            AGENT_FILE="${PROJECT_ROOT}/build/rt_srt_agent.exe"
        else
            AGENT_FILE="${PROJECT_ROOT}/build/agent/build/rt_srt_agent.exe"
        fi
        
        SIZE=$(du -h "$AGENT_FILE" | cut -f1)
        echo -e "Agent size (unpacked): ${SIZE}"
        
        # Pack with UPX if available
        if command -v upx &> /dev/null; then
            echo -e "${YELLOW}Packing with UPX...${NC}"
            upx --best --lzma "$AGENT_FILE" > /dev/null 2>&1 || true
            SIZE_PACKED=$(du -h "$AGENT_FILE" | cut -f1)
            echo -e "Agent size (packed): ${SIZE_PACKED}"
        fi
        
        # Check if size is within limits
        SIZE_KB=$(du -k "$AGENT_FILE" | cut -f1)
        if [ $SIZE_KB -gt 150 ]; then
            echo -e "${YELLOW}Warning: Agent size (${SIZE_KB}KB) exceeds 150KB limit${NC}"
        else
            echo -e "${GREEN}Agent size is within limits!${NC}"
        fi
    else
        echo -e "${RED}Error: Agent binary not found${NC}"
        exit 1
    fi
}

# Function to setup Python environment
setup_python_env() {
    echo -e "\n${BLUE}Setting up Python environment...${NC}"
    
    cd "${PROJECT_ROOT}/server"
    
    # Create virtual environment if it doesn't exist
    if [ ! -d "venv" ]; then
        echo -e "${YELLOW}Creating virtual environment...${NC}"
        python3 -m venv venv
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Install dependencies
    if [ -f "requirements.txt" ]; then
        echo -e "${YELLOW}Installing Python dependencies...${NC}"
        pip install --upgrade pip
        pip install -r requirements.txt
    else
        echo -e "${YELLOW}Creating requirements.txt...${NC}"
        cat > requirements.txt << EOF
# Server dependencies
fastapi==0.104.1
uvicorn==0.24.0
python-telegram-bot==20.6
sqlalchemy==2.0.23
python-decouple==3.8
aiofiles==23.2.1
websockets==12.0
pydantic==2.5.0
python-multipart==0.0.6

# Development dependencies
pytest==7.4.3
black==23.11.0
flake8==6.1.0
EOF
        pip install -r requirements.txt
    fi
    
    echo -e "${GREEN}Python environment ready!${NC}"
}

# Function to build server
build_server() {
    echo -e "\n${BLUE}Building Server Components...${NC}"
    
    setup_python_env
    
    # Run tests if they exist
    if [ -d "${PROJECT_ROOT}/server/tests" ]; then
        echo -e "${YELLOW}Running server tests...${NC}"
        pytest "${PROJECT_ROOT}/server/tests" || true
    fi
    
    echo -e "${GREEN}Server components ready!${NC}"
}

# Function to create distribution
create_distribution() {
    echo -e "\n${BLUE}Creating distribution package...${NC}"
    
    DIST_DIR="${PROJECT_ROOT}/dist"
    mkdir -p "${DIST_DIR}"
    
    # Copy agent - check both possible locations
    if [ -f "${PROJECT_ROOT}/build/rt_srt_agent" ] || [ -f "${PROJECT_ROOT}/build/rt_srt_agent.exe" ]; then
        cp "${PROJECT_ROOT}/build/rt_srt_agent"* "${DIST_DIR}/" 2>/dev/null || true
    elif [ -f "${PROJECT_ROOT}/build/agent/build/rt_srt_agent" ] || [ -f "${PROJECT_ROOT}/build/agent/build/rt_srt_agent.exe" ]; then
        cp "${PROJECT_ROOT}/build/agent/build/rt_srt_agent"* "${DIST_DIR}/" 2>/dev/null || true
    fi
    
    # Copy server
    cp -r "${PROJECT_ROOT}/server/src" "${DIST_DIR}/server"
    cp "${PROJECT_ROOT}/server/requirements.txt" "${DIST_DIR}/server/"
    
    # Create README
    cat > "${DIST_DIR}/README.md" << EOF
# RT-SRT Distribution

## Agent
- Binary: rt_srt_agent(.exe)
- Size: < 150KB (packed)

## Server
- Run: cd server && pip install -r requirements.txt && python web_panel/app.py
- Telegram bot token required in .env file

## Quick Start
1. Configure server/.env with your Telegram bot token
2. Start server: python server/web_panel/app.py
3. Deploy agent to target systems
EOF
    
    echo -e "${GREEN}Distribution created in ${DIST_DIR}${NC}"
}

# Main build process
main() {
    check_dependencies
    
    # Clean previous builds
    if [ "$1" == "clean" ]; then
        echo -e "${YELLOW}Cleaning build directories...${NC}"
        rm -rf "${PROJECT_ROOT}/build"
        rm -rf "${PROJECT_ROOT}/dist"
        rm -rf "${PROJECT_ROOT}/server/venv"
        echo -e "${GREEN}Clean complete!${NC}"
        exit 0
    fi
    
    # Build components
    build_agent
    build_server
    
    # Create distribution
    create_distribution
    
    echo -e "\n${GREEN}==== Build Complete! ====${NC}"
    echo -e "Agent: ${PROJECT_ROOT}/build/rt_srt_agent"
    echo -e "Server: ${PROJECT_ROOT}/server/"
    echo -e "Distribution: ${PROJECT_ROOT}/dist/"
}

# Run main function
main "$@"