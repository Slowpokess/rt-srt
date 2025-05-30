#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <memory>
#include <map>
#include <chrono>
#include <mutex>
#include <winhttp.h>

// Forward declarations
struct SSL_CTX;
struct SSL;
struct BIO;

// External logging functions (from file_logger.cpp)
extern "C" {
    void InitLogger();
    void LogInfo(const char* message);
    void LogError(const char* message);
    void LogDebug(const char* message);
    void LogWarning(const char* message);
    void CleanupLogger();
}

namespace SecureNetwork {

// Enums for connection types and encryption methods
enum class ConnectionType {
    DIRECT_HTTP = 0,
    DIRECT_HTTPS = 1,
    DOMAIN_FRONTING = 2,
    TOR_PROXY = 3,
    FALLBACK = 4
};

enum class EncryptionLevel {
    TLS_ONLY = 0,          // Just TLS 1.3
    TLS_PLUS_AES = 1,      // TLS 1.3 + AES-256
    TRIPLE_ENCRYPTION = 2   // TLS 1.3 + AES-256 + Custom XOR
};

// Network configuration structure
struct NetworkConfig {
    std::string primaryHost;
    std::string backupHost;
    std::vector<std::string> cdnHosts;
    std::vector<std::string> domainFrontingTargets;
    std::string torProxyAddress;
    int torProxyPort;
    int connectionTimeout;
    int readTimeout;
    bool enableCertificatePinning;
    bool enableDomainFronting;
    bool enableTorRouting;
    EncryptionLevel encryptionLevel;
    
    NetworkConfig() : 
        primaryHost(""),
        backupHost(""),
        torProxyAddress("127.0.0.1"),
        torProxyPort(9050),
        connectionTimeout(30000),
        readTimeout(60000),
        enableCertificatePinning(true),
        enableDomainFronting(false),
        enableTorRouting(false),
        encryptionLevel(EncryptionLevel::TLS_PLUS_AES) {}
};

// Communication result structure
struct CommResult {
    bool success;
    int httpStatus;
    std::vector<uint8_t> responseData;
    std::string errorMessage;
    ConnectionType usedConnection;
    std::chrono::milliseconds responseTime;
    
    CommResult() : success(false), httpStatus(0), usedConnection(ConnectionType::DIRECT_HTTP), 
                   responseTime(std::chrono::milliseconds(0)) {}
};

// TLS/SSL configuration and certificate management
class TLSConfig {
private:
    SSL_CTX* sslContext;
    std::vector<std::string> pinnedCertificates;
    std::string clientCertificate;
    std::string clientPrivateKey;
    
public:
    TLSConfig();
    ~TLSConfig();
    
    bool InitializeSSLContext();
    bool SetTLS13Only();
    bool AddPinnedCertificate(const std::string& certFingerprint);
    bool SetClientCertificate(const std::string& cert, const std::string& key);
    bool VerifyServerCertificate(SSL* ssl);
    SSL_CTX* GetSSLContext() const { return sslContext; }
};

// AES-256 encryption wrapper
class AESEncryption {
private:
    std::vector<uint8_t> encryptionKey;
    std::vector<uint8_t> initVector;
    
    void GenerateRandomKey();
    void GenerateRandomIV();
    
public:
    AESEncryption();
    ~AESEncryption();
    
    bool SetKey(const std::vector<uint8_t>& key);
    bool SetIV(const std::vector<uint8_t>& iv);
    std::vector<uint8_t> GetKey() const { return encryptionKey; }
    std::vector<uint8_t> GetIV() const { return initVector; }
    
    std::vector<uint8_t> Encrypt(const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> Decrypt(const std::vector<uint8_t>& ciphertext);
    
    // Key derivation from password
    bool DeriveKeyFromPassword(const std::string& password, const std::vector<uint8_t>& salt);
};

// Domain fronting implementation
class DomainFronting {
private:
    std::vector<std::string> cdnProviders;
    std::vector<std::string> frontingDomains;
    std::string realTargetHost;
    
public:
    DomainFronting();
    
    void AddCDNProvider(const std::string& provider);
    void AddFrontingDomain(const std::string& domain);
    void SetRealTarget(const std::string& target);
    
    std::string GetFrontingDomain();
    std::map<std::string, std::string> BuildFrontingHeaders(const std::string& realHost);
    bool IsProviderAvailable(const std::string& provider);
};

// Tor proxy connection manager
class TorConnector {
private:
    std::string proxyHost;
    int proxyPort;
    bool isConnected;
    SOCKET proxySocket;
    
    bool EstablishSOCKS5Connection();
    bool AuthenticateSOCKS5();
    bool ConnectThroughSOCKS5(const std::string& targetHost, int targetPort);
    
public:
    TorConnector();
    ~TorConnector();
    
    bool SetProxy(const std::string& host, int port);
    bool TestTorConnection();
    bool ConnectViaProxy(const std::string& targetHost, int targetPort);
    void Disconnect();
    bool IsConnected() const { return isConnected; }
    SOCKET GetSocket() const { return proxySocket; }
};

// Main secure communications class
class SecureComms {
private:
    NetworkConfig config;
    std::unique_ptr<TLSConfig> tlsConfig;
    std::unique_ptr<AESEncryption> aesEncryption;
    std::unique_ptr<DomainFronting> domainFronting;
    std::unique_ptr<TorConnector> torConnector;
    
    HINTERNET hSession;
    HINTERNET hConnection;
    SSL* sslConnection;
    
    mutable std::mutex connectionMutex;
    std::chrono::system_clock::time_point lastConnectionTime;
    
    // Connection management
    bool EstablishConnection(ConnectionType type);
    void CleanupConnection();
    bool TestConnection(const std::string& host, int port);
    
    // Encryption layers
    std::vector<uint8_t> ApplyMultiLayerEncryption(const std::string& data);
    std::string RemoveMultiLayerEncryption(const std::vector<uint8_t>& encryptedData);
    
    // HTTP request helpers
    std::map<std::string, std::string> BuildHeaders(ConnectionType type);
    std::string BuildUserAgent();
    bool SendHTTPRequest(const std::string& method, const std::string& path, 
                        const std::vector<uint8_t>& data, CommResult& result);
    
    // Fallback mechanisms
    bool TryFallbackConnection();
    ConnectionType SelectBestConnection();
    
public:
    SecureComms();
    ~SecureComms();
    
    // Initialization and configuration
    bool Initialize(const NetworkConfig& cfg);
    bool InitTLSConnection();
    void SetEncryptionLevel(EncryptionLevel level);
    
    // Core encryption methods
    std::vector<uint8_t> EncryptPayload(const std::string& data);
    std::string DecryptPayload(const std::vector<uint8_t>& encryptedData);
    
    // Network communication
    CommResult SendEncryptedData(const std::vector<uint8_t>& payload);
    CommResult SendEncryptedData(const std::string& data);
    CommResult GET(const std::string& path);
    CommResult POST(const std::string& path, const std::vector<uint8_t>& data);
    CommResult POST(const std::string& path, const std::string& data);
    
    // Advanced routing methods
    void UseDomainFronting();
    void DisableDomainFronting();
    bool ConnectViaTor();
    bool DisconnectTor();
    
    // Connection testing and health
    bool TestAllConnections();
    bool IsConnectionHealthy();
    ConnectionType GetActiveConnectionType();
    std::vector<std::string> GetConnectionStatus();
    
    // Security features
    bool EnableCertificatePinning(const std::vector<std::string>& fingerprints);
    bool SetClientCertificate(const std::string& cert, const std::string& key);
    void EnableRequestObfuscation();
    void SetCustomUserAgent(const std::string& userAgent);
    
    // Configuration updates
    void UpdateConfiguration(const NetworkConfig& newConfig);
    NetworkConfig GetConfiguration() const;
    
    // Statistics and monitoring
    struct Statistics {
        uint64_t totalRequests;
        uint64_t successfulRequests;
        uint64_t failedRequests;
        uint64_t bytesTransmitted;
        uint64_t bytesReceived;
        std::chrono::milliseconds averageResponseTime;
        std::map<ConnectionType, uint32_t> connectionTypeUsage;
    };
    
    Statistics GetStatistics() const;
    void ResetStatistics();
};

// Utility functions for network operations
namespace NetworkUtils {
    // Base64 encoding/decoding
    std::string Base64Encode(const std::vector<uint8_t>& data);
    std::vector<uint8_t> Base64Decode(const std::string& encoded);
    
    // URL encoding
    std::string URLEncode(const std::string& data);
    std::string URLDecode(const std::string& encoded);
    
    // Random data generation
    std::vector<uint8_t> GenerateRandomBytes(size_t length);
    std::string GenerateRandomString(size_t length);
    
    // Network testing
    bool TestInternetConnection();
    bool TestHostReachability(const std::string& host, int port);
    std::vector<std::string> ResolveDNS(const std::string& hostname);
    
    // Certificate utilities
    std::string GetCertificateFingerprint(const std::string& hostname, int port);
    bool ValidateCertificateChain(const std::string& hostname, int port);
    
    // Tor utilities
    bool IsTorRunning();
    std::string GetTorVersion();
    bool StartTorProcess(const std::string& torPath);
}

// Global instance accessor
SecureComms& GetGlobalSecureComms();

// Easy integration macros
#define SECURE_SEND_DATA(data) \
    SecureNetwork::GetGlobalSecureComms().SendEncryptedData(data)

#define SECURE_GET(path) \
    SecureNetwork::GetGlobalSecureComms().GET(path)

#define SECURE_POST(path, data) \
    SecureNetwork::GetGlobalSecureComms().POST(path, data)

#define ENABLE_DOMAIN_FRONTING() \
    SecureNetwork::GetGlobalSecureComms().UseDomainFronting()

#define ENABLE_TOR_ROUTING() \
    SecureNetwork::GetGlobalSecureComms().ConnectViaTor()

// Error codes for secure communications
#define SECURE_COMM_SUCCESS                 0x00000000
#define SECURE_COMM_ERROR_INIT_FAILED       0x80003001
#define SECURE_COMM_ERROR_TLS_FAILED        0x80003002
#define SECURE_COMM_ERROR_ENCRYPTION_FAILED 0x80003003
#define SECURE_COMM_ERROR_CONNECTION_FAILED 0x80003004
#define SECURE_COMM_ERROR_DOMAIN_FRONTING   0x80003005
#define SECURE_COMM_ERROR_TOR_FAILED        0x80003006
#define SECURE_COMM_ERROR_CERTIFICATE_ERROR 0x80003007
#define SECURE_COMM_ERROR_TIMEOUT           0x80003008

} // namespace SecureNetwork