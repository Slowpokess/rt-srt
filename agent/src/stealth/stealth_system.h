#pragma once

#include <windows.h>
#include <memory>
#include <thread>
#include <mutex>
#include <atomic>
#include <vector>
#include <string>
#include <chrono>
#include <functional>
#include "../logger/file_logger.h"

// Уровни тревоги безопасности
enum class SecurityThreatLevel {
    NONE = 0,
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4
};

// Типы угроз
enum class ThreatType {
    DEBUGGER_DETECTED = 1,
    VM_ENVIRONMENT = 2,
    SANDBOX_DETECTED = 3,
    ANALYSIS_TOOLS = 4,
    MEMORY_SCANNER = 5,
    NETWORK_MONITOR = 6,
    BEHAVIORAL_ANALYSIS = 7,
    UNKNOWN_THREAT = 99
};

// Действия реагирования
enum class ResponseAction {
    LOG_ONLY = 0,
    OBFUSCATE = 1,
    HIDE_PROCESS = 2,
    FAKE_CRASH = 3,
    SELF_DELETE = 4,
    TERMINATE = 5
};

// Информация об угрозе
struct ThreatInfo {
    ThreatType type;
    SecurityThreatLevel level;
    std::string description;
    std::string source;
    DWORD detectedAt;
    bool resolved;
    ResponseAction actionTaken;
    
    ThreatInfo(ThreatType t, SecurityThreatLevel l, const std::string& desc) 
        : type(t), level(l), description(desc), detectedAt(GetTickCount()), 
          resolved(false), actionTaken(ResponseAction::LOG_ONLY) {}
};

// Конфигурация системы безопасности
struct StealthConfig {
    bool enableAntiDebug = true;
    bool enableAntiVM = true;
    bool enableAntiSandbox = true;
    bool enableContinuousMonitoring = true;
    bool enableAutoResponse = true;
    bool enableProcessHiding = true;
    
    DWORD monitoringIntervalMs = 3000;  // 3 секунды
    DWORD threatTimeoutMs = 300000;     // 5 минут
    DWORD maxThreatHistory = 100;
    
    SecurityThreatLevel autoResponseThreshold = SecurityThreatLevel::MEDIUM;
    ResponseAction defaultResponse = ResponseAction::OBFUSCATE;
    
    std::vector<std::string> trustedProcesses = {
        "explorer.exe", "winlogon.exe", "csrss.exe", "dwm.exe"
    };
    
    std::vector<std::string> suspiciousProcesses = {
        "ollydbg.exe", "ida.exe", "x32dbg.exe", "x64dbg.exe",
        "cheatengine.exe", "procmon.exe", "wireshark.exe",
        "fiddler.exe", "burpsuite.exe", "sandboxie.exe"
    };
};

// Класс мониторинга процессов
class ProcessMonitor {
private:
    std::vector<DWORD> previousProcessList_;
    std::mutex processMutex_;
    
public:
    std::vector<DWORD> GetCurrentProcessList();
    std::vector<DWORD> GetNewProcesses(const std::vector<DWORD>& current);
    std::vector<DWORD> GetTerminatedProcesses(const std::vector<DWORD>& current);
    std::string GetProcessName(DWORD processId);
    std::string GetProcessPath(DWORD processId);
    bool IsProcessSuspicious(const std::string& processName);
    bool IsProcessTrusted(const std::string& processName);
    void UpdateProcessList(const std::vector<DWORD>& current);
};

// Класс управления памятью
class MemoryProtector {
private:
    std::vector<LPVOID> protectedRegions_;
    std::mutex memoryMutex_;
    
public:
    bool ProtectMemoryRegion(LPVOID address, SIZE_T size);
    bool UnprotectMemoryRegion(LPVOID address);
    bool DetectMemoryPatching();
    bool DetectCodeInjection();
    void ObfuscateMemoryLayout();
    bool ValidateCodeIntegrity();
    void ClearProtectedRegions();
};

// Класс скрытия процесса
class ProcessHider {
private:
    bool isHidden_;
    DWORD originalPID_;
    std::string fakeName_;
    
public:
    ProcessHider();
    ~ProcessHider();
    
    bool HideCurrentProcess();
    bool ShowCurrentProcess();
    bool SetFakeProcessName(const std::string& name);
    bool IsHidden() const { return isHidden_; }
    void InstallProcessListHooks();
    void RemoveProcessListHooks();
};

// Основная система Stealth
class StealthSystem {
private:
    // Состояние и конфигурация
    std::atomic<bool> isActive_{false};
    std::atomic<bool> shouldStop_{false};
    std::atomic<SecurityThreatLevel> currentThreatLevel_{SecurityThreatLevel::NONE};
    StealthConfig config_;
    
    // Компоненты
    std::unique_ptr<ProcessMonitor> processMonitor_;
    std::unique_ptr<MemoryProtector> memoryProtector_;
    std::unique_ptr<ProcessHider> processHider_;
    
    // Мониторинг
    std::unique_ptr<std::thread> monitoringThread_;
    std::unique_ptr<std::thread> responseThread_;
    
    // История угроз
    std::vector<ThreatInfo> threatHistory_;
    std::mutex threatMutex_;
    
    // Обработчики событий
    std::vector<std::function<void(const ThreatInfo&)>> threatHandlers_;
    
public:
    StealthSystem();
    ~StealthSystem();
    
    // Основное управление
    bool Initialize(const StealthConfig& config = StealthConfig{});
    bool Start();
    bool Stop(DWORD timeoutMs = 10000);
    bool IsActive() const { return isActive_.load(); }
    
    // Конфигурация
    void SetConfig(const StealthConfig& config) { config_ = config; }
    StealthConfig GetConfig() const { return config_; }
    
    // Мониторинг угроз
    void RegisterThreatHandler(std::function<void(const ThreatInfo&)> handler);
    void ReportThreat(ThreatType type, SecurityThreatLevel level, const std::string& description);
    std::vector<ThreatInfo> GetThreatHistory() const;
    SecurityThreatLevel GetCurrentThreatLevel() const { return currentThreatLevel_.load(); }
    
    // Проверки безопасности
    bool PerformSecurityScan();
    bool CheckForDebuggers();
    bool CheckForVirtualization();
    bool CheckForSandbox();
    bool CheckForAnalysisTools();
    
    // Реагирование на угрозы
    bool RespondToThreat(const ThreatInfo& threat);
    void SetAutoResponse(bool enabled) { config_.enableAutoResponse = enabled; }
    bool IsAutoResponseEnabled() const { return config_.enableAutoResponse; }
    
    // Скрытие и обфускация
    bool EnableProcessHiding();
    bool DisableProcessHiding();
    bool ObfuscatePresence();
    bool RestoreVisibility();
    
    // Отчёты и статистика
    std::string GenerateSecurityReport();
    std::string GenerateThreatSummary();
    void LogSecurityStatus();
    
private:
    // Внутренние методы мониторинга
    void MonitoringThreadMain();
    void ResponseThreadMain();
    void PerformContinuousChecks();
    void ProcessNewThreats();
    
    // Обработка угроз
    void HandleThreat(const ThreatInfo& threat);
    ResponseAction DetermineResponse(const ThreatInfo& threat);
    bool ExecuteResponse(ResponseAction action, const ThreatInfo& threat);
    
    // Специфические действия
    bool PerformObfuscation();
    bool PerformFakeCrash();
    bool PerformSelfDelete();
    bool PerformTermination();
    
    // Утилиты
    void UpdateThreatLevel();
    void CleanupOldThreats();
    std::string ThreatTypeToString(ThreatType type);
    std::string ThreatLevelToString(SecurityThreatLevel level);
    std::string ResponseActionToString(ResponseAction action);
};

// Глобальная система Stealth
extern std::unique_ptr<StealthSystem> g_stealthSystem;

// Утилиты для интеграции с существующими модулями
namespace StealthUtils {
    // Интеграция с anti_debug.cpp
    bool CheckDebuggerPresence();
    void ApplyAntiDebugMeasures();
    
    // Интеграция с anti_vm.cpp
    bool CheckVirtualEnvironment();
    void ApplyAntiVMMeasures();
    
    // Дополнительные проверки
    bool CheckProcessIntegrity();
    bool CheckNetworkMonitoring();
    bool CheckBehavioralAnalysis();
    
    // Утилиты скрытия
    bool HideFromTaskManager();
    bool HideFromProcessList();
    bool MaskMemoryUsage();
    bool ObfuscateNetworkTraffic();
}

// Макросы для быстрого использования
#define STEALTH_CHECK_THREAT(type, level, desc) \
    if (g_stealthSystem) { \
        g_stealthSystem->ReportThreat(type, level, desc); \
    }

#define STEALTH_EMERGENCY_RESPONSE() \
    if (g_stealthSystem) { \
        g_stealthSystem->ReportThreat(ThreatType::UNKNOWN_THREAT, \
                                     SecurityThreatLevel::CRITICAL, \
                                     "Emergency response triggered"); \
    }