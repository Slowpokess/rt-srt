cmake_minimum_required(VERSION 3.16)
project(RT-SRT VERSION 1.0.0 LANGUAGES CXX C)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Global compile options for size optimization
if(MSVC)
    # Visual Studio flags
    add_compile_options(/O1 /Os /GL /GS- /MT)
    add_link_options(/OPT:REF /OPT:ICF /LTCG)
elseif(APPLE)
    # macOS-specific flags (Apple Clang has different flags)
    add_compile_options(-Os -fno-exceptions -fno-rtti -ffunction-sections -fdata-sections)
    # macOS uses different strip syntax - handled in post-build commands
else()
    # GCC/Clang flags for other platforms
    add_compile_options(-Os -s -fno-exceptions -fno-rtti -ffunction-sections -fdata-sections)
    add_link_options(-Wl,--gc-sections -Wl,--strip-all)
endif()

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/build)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/build)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/build)

# Add subdirectories
add_subdirectory(agent)

# Custom target for comprehensive build report
add_custom_target(build_report
    COMMAND ${CMAKE_COMMAND} -E echo "============= RT-SRT Build Report ============="
    COMMAND ${CMAKE_COMMAND} -E echo "Project: ${PROJECT_NAME} v${PROJECT_VERSION}"
    COMMAND ${CMAKE_COMMAND} -E echo "Build Type: ${CMAKE_BUILD_TYPE}"
    COMMAND ${CMAKE_COMMAND} -E echo "Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}"
    COMMAND ${CMAKE_COMMAND} -E echo "Target Platform: ${CMAKE_SYSTEM_NAME} ${CMAKE_SYSTEM_PROCESSOR}"
    COMMAND ${CMAKE_COMMAND} -E echo ""
    COMMAND ${CMAKE_COMMAND} -E echo "=== Component Sizes ==="
    COMMAND ${CMAKE_COMMAND} -E echo "RT-SRT Agent:"
    COMMAND ${CMAKE_SIZE} $<TARGET_FILE:rt_srt_agent>
    COMMAND ${CMAKE_COMMAND} -E echo "============================================="
    DEPENDS rt_srt_agent
    COMMENT "Generating comprehensive build report"
)

# Legacy alias for backwards compatibility
add_custom_target(size_report DEPENDS build_report)

# ===============================================
# PACKING TARGETS (USE AFTER BUILDING)
# ===============================================
# IMPORTANT: You MUST build the agent first!
# Correct order:
#   1. cmake .. -DCMAKE_BUILD_TYPE=Release
#   2. cmake --build . --parallel
#   3. cmake --build . --target pack_agent
# ===============================================

find_program(UPX_EXECUTABLE upx)
find_program(STRIP_EXECUTABLE strip)

if(UPX_EXECUTABLE)
    # Standard packing (recommended)
    add_custom_target(pack_agent
        COMMAND ${CMAKE_COMMAND} -E echo "============================================="
        COMMAND ${CMAKE_COMMAND} -E echo "PACKING RT-SRT AGENT (AFTER BUILD ONLY!)"
        COMMAND ${CMAKE_COMMAND} -E echo "============================================="
        COMMAND ${CMAKE_COMMAND} -E echo "Original size:"
        COMMAND ${CMAKE_SIZE} $<TARGET_FILE:rt_srt_agent>
        COMMAND ${CMAKE_COMMAND} -E echo "Packing with UPX --best --lzma..."
        COMMAND ${UPX_EXECUTABLE} --best --lzma $<TARGET_FILE:rt_srt_agent>
        COMMAND ${CMAKE_COMMAND} -E echo "Final packed size:"
        COMMAND ${CMAKE_SIZE} $<TARGET_FILE:rt_srt_agent>
        COMMAND ${CMAKE_COMMAND} -E echo "Packing completed successfully!"
        COMMAND ${CMAKE_COMMAND} -E echo "============================================="
        DEPENDS rt_srt_agent
        COMMENT "Standard UPX packing (use AFTER building)"
    )
    
    # Maximum compression (slower)
    add_custom_target(pack_aggressive
        COMMAND ${CMAKE_COMMAND} -E echo "============================================="
        COMMAND ${CMAKE_COMMAND} -E echo "AGGRESSIVE PACKING (MAXIMUM COMPRESSION)"
        COMMAND ${CMAKE_COMMAND} -E echo "============================================="
        COMMAND ${CMAKE_COMMAND} -E echo "Original size:"
        COMMAND ${CMAKE_SIZE} $<TARGET_FILE:rt_srt_agent>
        COMMAND ${CMAKE_COMMAND} -E echo "Packing with UPX --ultra-brute --lzma..."
        COMMAND ${CMAKE_COMMAND} -E echo "Warning: This may take several minutes!"
        COMMAND ${UPX_EXECUTABLE} --ultra-brute --lzma $<TARGET_FILE:rt_srt_agent>
        COMMAND ${CMAKE_COMMAND} -E echo "Final packed size:"
        COMMAND ${CMAKE_SIZE} $<TARGET_FILE:rt_srt_agent>
        COMMAND ${CMAKE_COMMAND} -E echo "Aggressive packing completed!"
        COMMAND ${CMAKE_COMMAND} -E echo "============================================="
        DEPENDS rt_srt_agent
        COMMENT "Maximum UPX compression (use AFTER building, slower)"
    )
    
    message(STATUS "UPX found at: ${UPX_EXECUTABLE}")
    message(STATUS "Packing targets available: pack_agent, pack_aggressive")
    message(STATUS "Usage: cmake --build . --target pack_agent")
else()
    message(WARNING "UPX not found. Packing targets will not be available.")
    message(STATUS "To enable packing, install UPX: https://upx.github.io/")
endif()

# Strip debug symbols separately
if(STRIP_EXECUTABLE AND NOT WIN32)
    add_custom_target(strip_agent
        COMMAND ${STRIP_EXECUTABLE} --strip-all $<TARGET_FILE:rt_srt_agent>
        DEPENDS rt_srt_agent
        COMMENT "Stripping debug symbols from agent"
    )
endif()

# Installation rules
install(TARGETS rt_srt_agent
    RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/agent
)

# Build workflow targets (use in this order)

# Step 1: Clean build (if needed)
add_custom_target(clean_build
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}
    COMMENT "Step 1: Clean rebuild - removing build directory"
)

# Step 2: Quick debug build
add_custom_target(quick_build
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --config Debug --parallel
    COMMENT "Step 2: Quick debug build (no optimization)"
)

# Step 3: Full optimized build (REQUIRED before packing)
add_custom_target(release_build
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --config Release --parallel
    DEPENDS rt_srt_agent
    COMMENT "Step 3: Full optimized release build (REQUIRED before packing)"
)

# Step 4: Test modules (after build)
add_custom_target(module_test
    COMMAND ${CMAKE_COMMAND} -E echo "Testing RT-SRT modules..."
    COMMAND ${CMAKE_COMMAND} -E echo "This would run module-specific tests"
    DEPENDS rt_srt_agent
    COMMENT "Step 4: Running module tests (after build)"
)

# Step 5: Full build + pack workflow
add_custom_target(build_and_pack
    COMMAND ${CMAKE_COMMAND} -E echo "=== Full Build and Pack Workflow ==="
    COMMAND ${CMAKE_COMMAND} -E echo "Step 1: Building release version..."
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --config Release --parallel
    COMMAND ${CMAKE_COMMAND} -E echo "Step 2: Packing with UPX..."
    DEPENDS pack_agent
    COMMENT "Complete build and pack workflow"
)

# CPack configuration for distribution
set(CPACK_PACKAGE_NAME "RT-SRT")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "RedTeam Stealth Recon Tool")
set(CPACK_PACKAGE_VENDOR "RedTeam")
set(CPACK_PACKAGE_CONTACT "redteam@example.com")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
set(CPACK_GENERATOR "ZIP;TGZ")
include(CPack)
