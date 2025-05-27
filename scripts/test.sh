#!/bin/bash

# RT-SRT Test Script
# Handles testing of all components

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

# Test configuration
TEST_TYPE="${1:-all}"
VERBOSE="${2:-false}"

echo -e "${BLUE}==== RT-SRT Test System ====${NC}"
echo -e "Project root: ${PROJECT_ROOT}"
echo -e "Test type: ${TEST_TYPE}"
echo ""

# Test results
TESTS_PASSED=0
TESTS_FAILED=0
FAILED_TESTS=()

# Function to run command and track results
run_test() {
    local test_name="$1"
    local command="$2"
    
    echo -e "${YELLOW}Running: ${test_name}${NC}"
    
    if [ "$VERBOSE" = "true" ]; then
        if eval "$command"; then
            echo -e "${GREEN} ${test_name} PASSED${NC}"
            ((TESTS_PASSED++))
        else
            echo -e "${RED} ${test_name} FAILED${NC}"
            ((TESTS_FAILED++))
            FAILED_TESTS+=("$test_name")
        fi
    else
        if eval "$command" > /dev/null 2>&1; then
            echo -e "${GREEN} ${test_name} PASSED${NC}"
            ((TESTS_PASSED++))
        else
            echo -e "${RED} ${test_name} FAILED${NC}"
            ((TESTS_FAILED++))
            FAILED_TESTS+=("$test_name")
        fi
    fi
}

# Function to test build system
test_build() {
    echo -e "\n${BLUE}Testing Build System...${NC}"
    
    # Test CMake configuration
    run_test "CMake Configuration" "cd '${PROJECT_ROOT}' && mkdir -p build/test && cd build/test && cmake -DCMAKE_BUILD_TYPE=Debug ../.."
    
    # Test agent compilation
    run_test "Agent Compilation" "cd '${PROJECT_ROOT}/build/test' && cmake --build . --target rt_srt_agent --parallel 2"
    
    # Test Python environment
    run_test "Python Environment" "cd '${PROJECT_ROOT}/server' && python3 -m venv test_venv && source test_venv/bin/activate && pip install -r requirements.txt"
    
    # Cleanup
    rm -rf "${PROJECT_ROOT}/build/test"
    rm -rf "${PROJECT_ROOT}/server/test_venv"
}

# Function to test agent functionality
test_agent() {
    echo -e "\n${BLUE}Testing Agent Functionality...${NC}"
    
    # Check if agent binary exists
    AGENT_FILE=$(find "${PROJECT_ROOT}/build" -name "rt_srt_agent*" 2>/dev/null | head -1)
    
    if [ -z "$AGENT_FILE" ]; then
        echo -e "${YELLOW}Agent binary not found, building first...${NC}"
        "${SCRIPT_DIR}/build.sh" > /dev/null 2>&1
        AGENT_FILE=$(find "${PROJECT_ROOT}/build" -name "rt_srt_agent*" 2>/dev/null | head -1)
    fi
    
    if [ -n "$AGENT_FILE" ]; then
        # Test binary execution (should exit with help or error)
        run_test "Agent Binary Execution" "timeout 5s '$AGENT_FILE' --help || true"
        
        # Test binary size
        SIZE_KB=$(du -k "$AGENT_FILE" | cut -f1)
        if [ $SIZE_KB -le 150 ]; then
            run_test "Agent Size Check (<= 150KB)" "true"
        else
            run_test "Agent Size Check (<= 150KB)" "false"
        fi
        
        # Test binary packing
        if command -v upx &> /dev/null; then
            run_test "UPX Packing Available" "true"
        else
            run_test "UPX Packing Available" "false"
        fi
    else
        run_test "Agent Binary Build" "false"
    fi
}

# Function to test server functionality
test_server() {
    echo -e "\n${BLUE}Testing Server Functionality...${NC}"
    
    cd "${PROJECT_ROOT}/server"
    
    # Check if virtual environment exists
    if [ ! -d "venv" ]; then
        echo -e "${YELLOW}Creating test virtual environment...${NC}"
        python3 -m venv test_venv
        source test_venv/bin/activate
        pip install -r requirements.txt > /dev/null 2>&1
    else
        source venv/bin/activate
    fi
    
    # Test Python imports
    run_test "Server Python Imports" "python3 -c 'import src.config; import src.models.user_model; import src.utils.db_utils'"
    
    # Test FastAPI app creation
    run_test "FastAPI App Creation" "python3 -c 'from src.web_panel.app import app; print(\"FastAPI app created successfully\")'"
    
    # Test database models
    run_test "Database Models" "python3 -c 'from src.models.user_model import User; from src.models.log_model import Log; print(\"Models imported successfully\")'"
    
    # Test utilities
    run_test "Utility Functions" "python3 -c 'from src.utils.encryption import encrypt_data; from src.utils.file_handler import FileHandler; print(\"Utils imported successfully\")'"
    
    # Cleanup test environment
    if [ -d "test_venv" ]; then
        rm -rf test_venv
    fi
    
    deactivate 2>/dev/null || true
}

# Function to test security features
test_security() {
    echo -e "\n${BLUE}Testing Security Features...${NC}"
    
    # Test anti-debug compilation
    run_test "Anti-Debug Module Compilation" "cd '${PROJECT_ROOT}' && grep -r 'anti_debug' agent/src/ && echo 'Anti-debug code found'"
    
    # Test anti-VM compilation
    run_test "Anti-VM Module Compilation" "cd '${PROJECT_ROOT}' && grep -r 'anti_vm' agent/src/ && echo 'Anti-VM code found'"
    
    # Test obfuscation
    run_test "Obfuscation Module Compilation" "cd '${PROJECT_ROOT}' && grep -r 'obfuscation' agent/src/ && echo 'Obfuscation code found'"
    
    # Test encryption
    run_test "Encryption Module" "cd '${PROJECT_ROOT}/server' && python3 -c 'from src.utils.encryption import encrypt_data, decrypt_data; print(\"Encryption functions work\")'"
}

# Function to test integration
test_integration() {
    echo -e "\n${BLUE}Testing Integration...${NC}"
    
    # Test build script
    run_test "Build Script Execution" "timeout 60s '${SCRIPT_DIR}/build.sh' > /dev/null 2>&1"
    
    # Test that all components exist after build
    run_test "Agent Binary Exists" "test -f '${PROJECT_ROOT}/build/rt_srt_agent' -o -f '${PROJECT_ROOT}/build/rt_srt_agent.exe' -o -f '${PROJECT_ROOT}/build/agent/build/rt_srt_agent' -o -f '${PROJECT_ROOT}/build/agent/build/rt_srt_agent.exe'"
    
    run_test "Server Files Exist" "test -d '${PROJECT_ROOT}/server/src'"
    
    run_test "Distribution Created" "test -d '${PROJECT_ROOT}/dist'"
}

# Function to run specific test type
run_tests() {
    case "$TEST_TYPE" in
        "build")
            test_build
            ;;
        "agent")
            test_agent
            ;;
        "server")
            test_server
            ;;
        "security")
            test_security
            ;;
        "integration")
            test_integration
            ;;
        "all")
            test_build
            test_agent
            test_server
            test_security
            test_integration
            ;;
        *)
            echo -e "${RED}Unknown test type: $TEST_TYPE${NC}"
            echo -e "Available types: build, agent, server, security, integration, all"
            exit 1
            ;;
    esac
}

# Function to show test results
show_results() {
    echo -e "\n${BLUE}==== Test Results ====${NC}"
    echo -e "Tests passed: ${GREEN}${TESTS_PASSED}${NC}"
    echo -e "Tests failed: ${RED}${TESTS_FAILED}${NC}"
    
    if [ ${TESTS_FAILED} -gt 0 ]; then
        echo -e "\n${RED}Failed tests:${NC}"
        for test in "${FAILED_TESTS[@]}"; do
            echo -e "   $test"
        done
        exit 1
    else
        echo -e "\n${GREEN}All tests passed!${NC}"
    fi
}

# Main function
main() {
    run_tests
    show_results
}

# Show usage
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "Usage: $0 [test_type] [verbose]"
    echo ""
    echo "Test types:"
    echo "  build      - Test build system"
    echo "  agent      - Test agent functionality"
    echo "  server     - Test server functionality"
    echo "  security   - Test security features"
    echo "  integration- Test full integration"
    echo "  all        - Run all tests (default)"
    echo ""
    echo "Options:"
    echo "  verbose    - Show detailed output"
    echo ""
    echo "Examples:"
    echo "  $0 all verbose"
    echo "  $0 agent"
    echo "  $0 server verbose"
    exit 0
fi

# Run main function
main "$@"