#include "stealth_system.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <algorithm>
#include <sstream>
#include <iomanip>

// Глобальная система
std::unique_ptr<StealthSystem> g_stealthSystem;

// ProcessMonitor implementation
std::vector<DWORD> ProcessMonitor::GetCurrentProcessList() {
    std::vector<DWORD> processes;
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        LogError("[STEALTH] Failed to create process snapshot");
        return processes;
    }
    
    PROCESSENTRY32W pe32 = {0};
    pe32.dwSize = sizeof(pe32);
    
    if (Process32FirstW(snapshot, &pe32)) {
        do {
            processes.push_back(pe32.th32ProcessID);
        } while (Process32NextW(snapshot, &pe32));
    }
    
    CloseHandle(snapshot);
    return processes;
}

std::vector<DWORD> ProcessMonitor::GetNewProcesses(const std::vector<DWORD>& current) {
    std::lock_guard<std::mutex> lock(processMutex_);
    std::vector<DWORD> newProcesses;
    
    for (DWORD pid : current) {
        if (std::find(previousProcessList_.begin(), previousProcessList_.end(), pid) == previousProcessList_.end()) {
            newProcesses.push_back(pid);
        }
    }
    
    return newProcesses;
}

std::vector<DWORD> ProcessMonitor::GetTerminatedProcesses(const std::vector<DWORD>& current) {
    std::lock_guard<std::mutex> lock(processMutex_);
    std::vector<DWORD> terminated;
    
    for (DWORD pid : previousProcessList_) {
        if (std::find(current.begin(), current.end(), pid) == current.end()) {
            terminated.push_back(pid);
        }
    }
    
    return terminated;
}

std::string ProcessMonitor::GetProcessName(DWORD processId) {
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!process) return "";
    
    char processName[MAX_PATH] = {0};
    GetModuleBaseNameA(process, NULL, processName, MAX_PATH);
    CloseHandle(process);
    
    return std::string(processName);
}

std::string ProcessMonitor::GetProcessPath(DWORD processId) {
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!process) return "";
    
    char processPath[MAX_PATH] = {0};
    GetModuleFileNameExA(process, NULL, processPath, MAX_PATH);
    CloseHandle(process);
    
    return std::string(processPath);
}

void ProcessMonitor::UpdateProcessList(const std::vector<DWORD>& current) {
    std::lock_guard<std::mutex> lock(processMutex_);
    previousProcessList_ = current;
}

// MemoryProtector implementation
bool MemoryProtector::ProtectMemoryRegion(LPVOID address, SIZE_T size) {
    std::lock_guard<std::mutex> lock(memoryMutex_);
    
    DWORD oldProtect;
    if (VirtualProtect(address, size, PAGE_EXECUTE_READ, &oldProtect)) {
        protectedRegions_.push_back(address);
        LogInfo(("[STEALTH] Memory region protected: " + 
                std::to_string(reinterpret_cast<uintptr_t>(address))).c_str());
        return true;
    }
    
    LogError("[STEALTH] Failed to protect memory region");
    return false;
}

bool MemoryProtector::UnprotectMemoryRegion(LPVOID address) {
    std::lock_guard<std::mutex> lock(memoryMutex_);
    
    auto it = std::find(protectedRegions_.begin(), protectedRegions_.end(), address);
    if (it != protectedRegions_.end()) {
        protectedRegions_.erase(it);
        
        DWORD oldProtect;
        VirtualProtect(address, 0, PAGE_EXECUTE_READWRITE, &oldProtect);
        return true;
    }
    
    return false;
}

void MemoryProtector::ClearProtectedRegions() {
    std::lock_guard<std::mutex> lock(memoryMutex_);
    
    for (LPVOID address : protectedRegions_) {
        DWORD oldProtect;
        VirtualProtect(address, 0, PAGE_EXECUTE_READWRITE, &oldProtect);
    }
    
    protectedRegions_.clear();
    LogInfo("[STEALTH] All memory protections cleared");
}

// ProcessHider implementation
ProcessHider::ProcessHider() : isHidden_(false), originalPID_(GetCurrentProcessId()) {
}

ProcessHider::~ProcessHider() {
    if (isHidden_) {
        ShowCurrentProcess();
    }
}

bool ProcessHider::HideCurrentProcess() {
    if (isHidden_) return true;
    
    LogInfo("[STEALTH] Attempting to hide current process");
    
    // Здесь будет реализация скрытия процесса
    // Это сложная процедура, требующая хуков API
    
    isHidden_ = true;
    LogInfo("[STEALTH] Process hiding enabled");
    return true;
}

bool ProcessHider::ShowCurrentProcess() {
    if (!isHidden_) return true;
    
    LogInfo("[STEALTH] Restoring process visibility");
    
    // Удаление хуков и восстановление видимости
    
    isHidden_ = false;
    LogInfo("[STEALTH] Process visibility restored");
    return true;
}

// StealthSystem implementation
StealthSystem::StealthSystem() {
    LogInfo("[STEALTH] Initializing Stealth System");
    
    processMonitor_ = std::make_unique<ProcessMonitor>();
    memoryProtector_ = std::make_unique<MemoryProtector>();
    processHider_ = std::make_unique<ProcessHider>();
    
    LogInfo("[STEALTH] Stealth System components initialized");
}

StealthSystem::~StealthSystem() {
    LogInfo("[STEALTH] Destroying Stealth System");
    
    if (isActive_.load()) {
        Stop(10000);
    }
    
    memoryProtector_->ClearProtectedRegions();
    LogInfo("[STEALTH] Stealth System destroyed");
}

bool StealthSystem::Initialize(const StealthConfig& config) {
    LogInfo("[STEALTH] Initializing Stealth System with configuration");
    
    config_ = config;
    
    // Инициализация базовых защит
    if (config_.enableProcessHiding) {
        processHider_->HideCurrentProcess();
    }
    
    // Защита критических областей памяти
    HMODULE hModule = GetModuleHandle(NULL);
    if (hModule) {
        memoryProtector_->ProtectMemoryRegion(hModule, 4096); // Защищаем заголовок PE
    }
    
    LogInfo("[STEALTH] Stealth System initialized successfully");
    return true;
}

bool StealthSystem::Start() {
    if (isActive_.load()) {
        LogWarning("[STEALTH] Stealth System already active");
        return true;
    }
    
    LogInfo("[STEALTH] Starting Stealth System");
    
    shouldStop_.store(false);
    isActive_.store(true);
    
    // Запуск потока мониторинга
    if (config_.enableContinuousMonitoring) {
        monitoringThread_ = std::make_unique<std::thread>(
            &StealthSystem::MonitoringThreadMain, this
        );
    }
    
    // Запуск потока реагирования
    if (config_.enableAutoResponse) {
        responseThread_ = std::make_unique<std::thread>(
            &StealthSystem::ResponseThreadMain, this
        );
    }
    
    // Первоначальное сканирование
    PerformSecurityScan();
    
    LogInfo("[STEALTH] Stealth System started successfully");
    return true;
}

bool StealthSystem::Stop(DWORD timeoutMs) {
    if (!isActive_.load()) {
        return true;
    }
    
    LogInfo("[STEALTH] Stopping Stealth System");
    
    shouldStop_.store(true);
    auto startTime = std::chrono::steady_clock::now();
    
    // Ждём завершения потоков
    if (monitoringThread_ && monitoringThread_->joinable()) {
        monitoringThread_->join();
    }
    
    if (responseThread_ && responseThread_->joinable()) {
        responseThread_->join();
    }
    
    // Отключение скрытия процесса
    if (processHider_->IsHidden()) {
        processHider_->ShowCurrentProcess();
    }
    
    isActive_.store(false);
    
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime).count();
    
    LogInfo(("[STEALTH] Stealth System stopped in " + 
             std::to_string(elapsed) + "ms").c_str());
    
    return true;
}

void StealthSystem::MonitoringThreadMain() {
    LogInfo("[STEALTH] Monitoring thread started");
    
    try {
        while (!shouldStop_.load()) {
            PerformContinuousChecks();
            
            std::this_thread::sleep_for(
                std::chrono::milliseconds(config_.monitoringIntervalMs)
            );
        }
    } catch (const std::exception& e) {
        LogError(("[STEALTH] Monitoring thread crashed: " + std::string(e.what())).c_str());
        ReportThreat(ThreatType::UNKNOWN_THREAT, SecurityThreatLevel::HIGH, 
                    "Monitoring thread crashed: " + std::string(e.what()));
    }
    
    LogInfo("[STEALTH] Monitoring thread stopped");
}

void StealthSystem::ResponseThreadMain() {
    LogInfo("[STEALTH] Response thread started");
    
    try {
        while (!shouldStop_.load()) {
            ProcessNewThreats();
            CleanupOldThreats();
            
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
    } catch (const std::exception& e) {
        LogError(("[STEALTH] Response thread crashed: " + std::string(e.what())).c_str());
    }
    
    LogInfo("[STEALTH] Response thread stopped");
}

void StealthSystem::PerformContinuousChecks() {
    // Проверка новых процессов
    auto currentProcesses = processMonitor_->GetCurrentProcessList();
    auto newProcesses = processMonitor_->GetNewProcesses(currentProcesses);
    
    for (DWORD pid : newProcesses) {
        std::string processName = processMonitor_->GetProcessName(pid);
        if (!processName.empty()) {
            if (processMonitor_->IsProcessSuspicious(processName)) {
                ReportThreat(ThreatType::ANALYSIS_TOOLS, SecurityThreatLevel::HIGH,
                           "Suspicious process detected: " + processName);
            }
        }
    }
    
    processMonitor_->UpdateProcessList(currentProcesses);
    
    // Периодические проверки безопасности
    static int checkCounter = 0;
    if (++checkCounter % 10 == 0) { // Каждые 30 секунд (при интервале 3 сек)
        if (config_.enableAntiDebug && CheckForDebuggers()) {
            ReportThreat(ThreatType::DEBUGGER_DETECTED, SecurityThreatLevel::CRITICAL,
                        "Debugger presence detected during monitoring");
        }
        
        if (config_.enableAntiVM && CheckForVirtualization()) {
            ReportThreat(ThreatType::VM_ENVIRONMENT, SecurityThreatLevel::HIGH,
                        "Virtual environment detected during monitoring");
        }
    }
}

void StealthSystem::ProcessNewThreats() {
    std::lock_guard<std::mutex> lock(threatMutex_);
    
    for (auto& threat : threatHistory_) {
        if (!threat.resolved && config_.enableAutoResponse) {
            if (threat.level >= config_.autoResponseThreshold) {
                HandleThreat(threat);
                threat.resolved = true;
            }
        }
    }
}

void StealthSystem::ReportThreat(ThreatType type, SecurityThreatLevel level, const std::string& description) {
    std::lock_guard<std::mutex> lock(threatMutex_);
    
    ThreatInfo threat(type, level, description);
    threatHistory_.push_back(threat);
    
    // Обновляем общий уровень угрозы
    if (level > currentThreatLevel_.load()) {
        currentThreatLevel_.store(level);
    }
    
    // Логируем угрозу
    std::string logMsg = "[STEALTH_THREAT] " + ThreatTypeToString(type) + 
                        " (" + ThreatLevelToString(level) + "): " + description;
    
    if (level >= SecurityThreatLevel::HIGH) {
        LogError(logMsg.c_str());
    } else {
        LogWarning(logMsg.c_str());
    }
    
    // Вызываем обработчики
    for (const auto& handler : threatHandlers_) {
        try {
            handler(threat);
        } catch (const std::exception& e) {
            LogError(("[STEALTH] Threat handler exception: " + std::string(e.what())).c_str());
        }
    }
    
    // Ограничиваем размер истории
    if (threatHistory_.size() > config_.maxThreatHistory) {
        threatHistory_.erase(threatHistory_.begin());
    }
}

void StealthSystem::HandleThreat(const ThreatInfo& threat) {
    ResponseAction action = DetermineResponse(threat);
    
    LogInfo(("[STEALTH] Handling threat with action: " + 
             ResponseActionToString(action)).c_str());
    
    if (ExecuteResponse(action, threat)) {
        LogInfo("[STEALTH] Threat response executed successfully");
    } else {
        LogError("[STEALTH] Failed to execute threat response");
    }
}

ResponseAction StealthSystem::DetermineResponse(const ThreatInfo& threat) {
    switch (threat.level) {
        case SecurityThreatLevel::LOW:
            return ResponseAction::LOG_ONLY;
        case SecurityThreatLevel::MEDIUM:
            return ResponseAction::OBFUSCATE;
        case SecurityThreatLevel::HIGH:
            if (threat.type == ThreatType::DEBUGGER_DETECTED) {
                return ResponseAction::FAKE_CRASH;
            }
            return ResponseAction::HIDE_PROCESS;
        case SecurityThreatLevel::CRITICAL:
            return ResponseAction::SELF_DELETE;
        default:
            return config_.defaultResponse;
    }
}

bool StealthSystem::ExecuteResponse(ResponseAction action, const ThreatInfo& threat) {
    switch (action) {
        case ResponseAction::LOG_ONLY:
            return true; // Уже залогировано
            
        case ResponseAction::OBFUSCATE:
            return PerformObfuscation();
            
        case ResponseAction::HIDE_PROCESS:
            return processHider_->HideCurrentProcess();
            
        case ResponseAction::FAKE_CRASH:
            return PerformFakeCrash();
            
        case ResponseAction::SELF_DELETE:
            return PerformSelfDelete();
            
        case ResponseAction::TERMINATE:
            return PerformTermination();
            
        default:
            LogError("[STEALTH] Unknown response action");
            return false;
    }
}

bool StealthSystem::PerformObfuscation() {
    LogInfo("[STEALTH] Performing obfuscation measures");
    
    // Обфускация памяти
    memoryProtector_->ObfuscateMemoryLayout();
    
    // Дополнительные меры обфускации
    // ...
    
    return true;
}

bool StealthSystem::PerformFakeCrash() {
    LogInfo("[STEALTH] Performing fake crash");
    
    // Имитация краха приложения
    // Создание фиктивных дампов, логов ошибок и т.д.
    
    return true;
}

bool StealthSystem::PerformSelfDelete() {
    LogWarning("[STEALTH] Performing self-deletion");
    
    // Запланированное самоудаление
    // Это крайняя мера при критических угрозах
    
    return true;
}

bool StealthSystem::PerformTermination() {
    LogWarning("[STEALTH] Performing emergency termination");
    
    // Экстренное завершение работы
    ExitProcess(0);
    return true;
}

void StealthSystem::CleanupOldThreats() {
    std::lock_guard<std::mutex> lock(threatMutex_);
    
    DWORD currentTime = GetTickCount();
    
    threatHistory_.erase(
        std::remove_if(threatHistory_.begin(), threatHistory_.end(),
            [this, currentTime](const ThreatInfo& threat) {
                return (currentTime - threat.detectedAt) > config_.threatTimeoutMs;
            }),
        threatHistory_.end()
    );
}

std::string StealthSystem::ThreatTypeToString(ThreatType type) {
    switch (type) {
        case ThreatType::DEBUGGER_DETECTED: return "DEBUGGER";
        case ThreatType::VM_ENVIRONMENT: return "VIRTUAL_MACHINE";
        case ThreatType::SANDBOX_DETECTED: return "SANDBOX";
        case ThreatType::ANALYSIS_TOOLS: return "ANALYSIS_TOOLS";
        case ThreatType::MEMORY_SCANNER: return "MEMORY_SCANNER";
        case ThreatType::NETWORK_MONITOR: return "NETWORK_MONITOR";
        case ThreatType::BEHAVIORAL_ANALYSIS: return "BEHAVIORAL_ANALYSIS";
        default: return "UNKNOWN";
    }
}

std::string StealthSystem::ThreatLevelToString(SecurityThreatLevel level) {
    switch (level) {
        case SecurityThreatLevel::NONE: return "NONE";
        case SecurityThreatLevel::LOW: return "LOW";
        case SecurityThreatLevel::MEDIUM: return "MEDIUM";
        case SecurityThreatLevel::HIGH: return "HIGH";
        case SecurityThreatLevel::CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

std::string StealthSystem::ResponseActionToString(ResponseAction action) {
    switch (action) {
        case ResponseAction::LOG_ONLY: return "LOG_ONLY";
        case ResponseAction::OBFUSCATE: return "OBFUSCATE";
        case ResponseAction::HIDE_PROCESS: return "HIDE_PROCESS";
        case ResponseAction::FAKE_CRASH: return "FAKE_CRASH";
        case ResponseAction::SELF_DELETE: return "SELF_DELETE";
        case ResponseAction::TERMINATE: return "TERMINATE";
        default: return "UNKNOWN";
    }
}

// Интеграция с существующими модулями
bool StealthSystem::CheckForDebuggers() {
    // Интеграция с anti_debug.cpp
    extern bool CheckForDebugger();
    return CheckForDebugger();
}

bool StealthSystem::CheckForVirtualization() {
    // Интеграция с anti_vm.cpp
    extern bool CheckVMEnvironment();
    return !CheckVMEnvironment(); // CheckVMEnvironment возвращает true если чисто
}

bool StealthSystem::PerformSecurityScan() {
    LogInfo("[STEALTH] Performing comprehensive security scan");
    
    bool threatsFound = false;
    
    if (config_.enableAntiDebug && CheckForDebuggers()) {
        ReportThreat(ThreatType::DEBUGGER_DETECTED, SecurityThreatLevel::CRITICAL,
                    "Debugger detected during security scan");
        threatsFound = true;
    }
    
    if (config_.enableAntiVM && CheckForVirtualization()) {
        ReportThreat(ThreatType::VM_ENVIRONMENT, SecurityThreatLevel::HIGH,
                    "Virtual environment detected during security scan");
        threatsFound = true;
    }
    
    if (config_.enableAntiSandbox && CheckForSandbox()) {
        ReportThreat(ThreatType::SANDBOX_DETECTED, SecurityThreatLevel::HIGH,
                    "Sandbox environment detected during security scan");
        threatsFound = true;
    }
    
    if (!threatsFound) {
        LogInfo("[STEALTH] Security scan completed - no threats detected");
    }
    
    return !threatsFound;
}

// Заглушки для методов, которые будут доработаны
bool ProcessMonitor::IsProcessSuspicious(const std::string& processName) {
    // Простая проверка по имени процесса
    std::vector<std::string> suspicious = {
        "ollydbg.exe", "ida.exe", "x32dbg.exe", "x64dbg.exe", "cheatengine.exe"
    };
    
    std::string lowerName = processName;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
    
    return std::find(suspicious.begin(), suspicious.end(), lowerName) != suspicious.end();
}

bool ProcessMonitor::IsProcessTrusted(const std::string& processName) {
    std::vector<std::string> trusted = {
        "explorer.exe", "winlogon.exe", "csrss.exe", "dwm.exe"
    };
    
    std::string lowerName = processName;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
    
    return std::find(trusted.begin(), trusted.end(), lowerName) != trusted.end();
}

bool MemoryProtector::DetectMemoryPatching() { return false; }
bool MemoryProtector::DetectCodeInjection() { return false; }
void MemoryProtector::ObfuscateMemoryLayout() {}
bool MemoryProtector::ValidateCodeIntegrity() { return true; }

bool StealthSystem::CheckForSandbox() { return false; }
bool StealthSystem::CheckForAnalysisTools() { return false; }

std::vector<ThreatInfo> StealthSystem::GetThreatHistory() const {
    std::lock_guard<std::mutex> lock(threatMutex_);
    return threatHistory_;
}

void StealthSystem::RegisterThreatHandler(std::function<void(const ThreatInfo&)> handler) {
    threatHandlers_.push_back(handler);
}