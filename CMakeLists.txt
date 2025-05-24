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

# Custom target for size report
add_custom_target(size_report
    COMMAND ${CMAKE_COMMAND} -E echo "=== Binary Size Report ==="
    COMMAND ${CMAKE_COMMAND} -E echo "Agent size:"
    COMMAND ${CMAKE_SIZE} $<TARGET_FILE:rt_srt_agent>
    DEPENDS rt_srt_agent
    COMMENT "Generating size report"
)

# Custom target for UPX packing
find_program(UPX_EXECUTABLE upx)
if(UPX_EXECUTABLE)
    add_custom_target(pack_agent
        COMMAND ${UPX_EXECUTABLE} --best --lzma $<TARGET_FILE:rt_srt_agent>
        DEPENDS rt_srt_agent
        COMMENT "Packing agent with UPX"
    )
else()
    message(WARNING "UPX not found. Skipping UPX packing.")
endif()

# Installation rules
install(TARGETS rt_srt_agent
    RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/agent
)

# CPack configuration for distribution
set(CPACK_PACKAGE_NAME "RT-SRT")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "RedTeam Stealth Recon Tool")
include(CPack)
