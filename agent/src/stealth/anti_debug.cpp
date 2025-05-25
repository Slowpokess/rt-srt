#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <ntsecapi.h>
#include <string>
#include <vector>
#include "../common.h"
#include "../logger/file_logger.h"

// Function pointer types for NTAPI
typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pNtSetInformationThread)(HANDLE, THREADINFOCLASS, PVOID, ULONG);
typedef NTSTATUS (NTAPI *pNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

// Anti-Debug detection and protection
class AntiDebugProtection {
private:
    HMODULE hNtdll;
    pNtQueryInformationProcess NtQueryInformationProcess;
    pNtSetInformationThread NtSetInformationThread;
    pNtQuerySystemInformation NtQuerySystemInformation;
    
public:
    AntiDebugProtection() {
        hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
            NtSetInformationThread = (pNtSetInformationThread)GetProcAddress(hNtdll, "NtSetInformationThread");
            NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
        }
    }
    
    bool IsDebuggerPresent() {
        // Basic debugger detection methods
        if (CheckIsDebuggerPresent()) return true;
        if (CheckRemoteDebugger()) return true;
        if (CheckPEB()) return true;
        if (CheckNtGlobalFlag()) return true;
        if (CheckHeapFlags()) return true;
        if (CheckDebugPort()) return true;
        if (CheckDebugObject()) return true;
        if (CheckHardwareBreakpoints()) return true;
        if (CheckInt3()) return true;
        if (CheckSingleStep()) return true;
        if (CheckDebuggerProcess()) return true;
        if (CheckParentProcess()) return true;
        if (CheckSystemDebugger()) return true;
        if (CheckDebugPrivilege()) return true;
        
        // Advanced detection methods
        if (CheckTimingAttacks()) return true;
        if (CheckAPIHooks()) return true;
        if (CheckMemoryScanning()) return true;
        if (CheckRDTSCTiming()) return true;
        if (CheckExceptionHandling()) return true;
        
        return false;
    }
    
    void ApplyAntiDebugProtection() {
        // Hide from debugger
        HideThread();
        
        // Patch DbgBreakPoint
        PatchDbgBreakPoint();
        
        // Clear debug registers
        ClearDebugRegisters();
        
        // Set trap flag evasion
        SetupTrapFlagProtection();
    }
    
private:
    // Check IsDebuggerPresent API
    bool CheckIsDebuggerPresent() {
        return ::IsDebuggerPresent() == TRUE;
    }
    
    // Check for remote debugger
    bool CheckRemoteDebugger() {
        BOOL isDebuggerPresent = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent);
        return isDebuggerPresent == TRUE;
    }
    
    // Check PEB for debugger flags
    bool CheckPEB() {
        #ifdef _WIN64
            PPEB pPeb = (PPEB)__readgsqword(0x60);
        #else
            PPEB pPeb = (PPEB)__readfsdword(0x30);
        #endif
        
        if (pPeb->BeingDebugged) {
            return true;
        }
        
        return false;
    }
    
    // Check NtGlobalFlag
    bool CheckNtGlobalFlag() {
        #ifdef _WIN64
            PPEB pPeb = (PPEB)__readgsqword(0x60);
            DWORD offsetNtGlobalFlag = 0xBC;
        #else
            PPEB pPeb = (PPEB)__readfsdword(0x30);
            DWORD offsetNtGlobalFlag = 0x68;
        #endif
        
        DWORD NtGlobalFlag = *(PDWORD)((PBYTE)pPeb + offsetNtGlobalFlag);
        
        // Check for debugger flags
        if (NtGlobalFlag & 0x70) { // FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
            return true;
        }
        
        return false;
    }
    
    // Check heap flags
    bool CheckHeapFlags() {
        PVOID heap = GetProcessHeap();
        if (!heap) return false;
        
        #ifdef _WIN64
            DWORD offsetFlags = 0x70;
            DWORD offsetForceFlags = 0x74;
        #else
            DWORD offsetFlags = 0x40;
            DWORD offsetForceFlags = 0x44;
        #endif
        
        DWORD flags = *(PDWORD)((PBYTE)heap + offsetFlags);
        DWORD forceFlags = *(PDWORD)((PBYTE)heap + offsetForceFlags);
        
        // In a debugger, heap flags will be modified
        if ((flags & ~0x00000002) != 0 || forceFlags != 0) {
            return true;
        }
        
        return false;
    }
    
    // Check debug port using NtQueryInformationProcess
    bool CheckDebugPort() {
        if (!NtQueryInformationProcess) return false;
        
        HANDLE hDebugPort = NULL;
        NTSTATUS status = NtQueryInformationProcess(
            GetCurrentProcess(),
            (PROCESSINFOCLASS)7, // ProcessDebugPort
            &hDebugPort,
            sizeof(HANDLE),
            NULL
        );
        
        if (NT_SUCCESS(status) && hDebugPort != NULL) {
            return true;
        }
        
        return false;
    }
    
    // Check debug object handle
    bool CheckDebugObject() {
        if (!NtQueryInformationProcess) return false;
        
        HANDLE hDebugObject = NULL;
        NTSTATUS status = NtQueryInformationProcess(
            GetCurrentProcess(),
            (PROCESSINFOCLASS)30, // ProcessDebugObjectHandle
            &hDebugObject,
            sizeof(HANDLE),
            NULL
        );
        
        if (NT_SUCCESS(status) && hDebugObject != NULL) {
            return true;
        }
        
        return false;
    }
    
    // Check hardware breakpoints
    bool CheckHardwareBreakpoints() {
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        
        if (GetThreadContext(GetCurrentThread(), &ctx)) {
            if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
                return true;
            }
        }
        
        return false;
    }
    
    // Check for INT3 breakpoints in code
    bool CheckInt3() {
        // Check common API functions for INT3 breakpoints
        PVOID functions[] = {
            (PVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CreateFileW"),
            (PVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "OpenProcess"),
            (PVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "ReadProcessMemory"),
            (PVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "WriteProcessMemory"),
            (PVOID)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"),
            (PVOID)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"),
        };
        
        for (PVOID func : functions) {
            if (func) {
                BYTE firstByte = *(PBYTE)func;
                if (firstByte == 0xCC) { // INT3
                    return true;
                }
            }
        }
        
        return false;
    }
    
    // Check single step exception
    bool CheckSingleStep() {
        #ifdef _MSC_VER
        __try {
            __asm {
                pushfd
                or dword ptr[esp], 0x100
                popfd
                nop
            }
            return true; // No exception - debugger is present
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false; // Exception occurred - no debugger
        }
        #else
        // Alternative implementation for non-MSVC compilers
        return false;
        #endif
    }
    
    // Check for common debugger processes
    bool CheckDebuggerProcess() {
        std::vector<std::wstring> debuggers = {
            L"ollydbg.exe", L"ida.exe", L"ida64.exe", L"idag.exe", L"idag64.exe",
            L"idaw.exe", L"idaw64.exe", L"idaq.exe", L"idaq64.exe", L"idau.exe",
            L"idau64.exe", L"scylla.exe", L"scylla_x64.exe", L"scylla_x86.exe",
            L"protection_id.exe", L"x64dbg.exe", L"x32dbg.exe", L"windbg.exe",
            L"reshacker.exe", L"ImportREC.exe", L"IMMUNITYDEBUGGER.EXE",
            L"devenv.exe", L"procmon.exe", L"procmon64.exe", L"procexp.exe",
            L"procexp64.exe", L"ImmunityDebugger.exe", L"Wireshark.exe",
            L"dumpcap.exe", L"HookExplorer.exe", L"PETools.exe", L"LordPE.exe",
            L"SysInspector.exe", L"proc_analyzer.exe", L"sysAnalyzer.exe",
            L"sniff_hit.exe", L"joeboxcontrol.exe", L"joeboxserver.exe",
            L"ResourceHacker.exe", L"x96dbg.exe", L"Fiddler.exe",
            L"httpdebugger.exe", L"cheatengine.exe", L"processhacker.exe"
        };
        
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;
        
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        
        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                std::wstring processName = pe32.szExeFile;
                
                // Convert to lowercase
                for (auto& c : processName) c = towlower(c);
                
                for (const auto& debugger : debuggers) {
                    std::wstring debuggerLower = debugger;
                    for (auto& c : debuggerLower) c = towlower(c);
                    
                    if (processName == debuggerLower) {
                        CloseHandle(hSnapshot);
                        return true;
                    }
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }
        
        CloseHandle(hSnapshot);
        return false;
    }
    
    // Check parent process
    bool CheckParentProcess() {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;
        
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        
        DWORD currentPID = GetCurrentProcessId();
        DWORD parentPID = 0;
        
        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                if (pe32.th32ProcessID == currentPID) {
                    parentPID = pe32.th32ParentProcessID;
                    break;
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }
        
        if (parentPID != 0) {
            // Check parent process name
            if (Process32FirstW(hSnapshot, &pe32)) {
                do {
                    if (pe32.th32ProcessID == parentPID) {
                        std::wstring parentName = pe32.szExeFile;
                        for (auto& c : parentName) c = towlower(c);
                        
                        // Check if parent is a known debugger
                        if (parentName.find(L"ollydbg") != std::wstring::npos ||
                            parentName.find(L"ida") != std::wstring::npos ||
                            parentName.find(L"x64dbg") != std::wstring::npos ||
                            parentName.find(L"x32dbg") != std::wstring::npos ||
                            parentName.find(L"windbg") != std::wstring::npos ||
                            parentName.find(L"immunity") != std::wstring::npos) {
                            CloseHandle(hSnapshot);
                            return true;
                        }
                        break;
                    }
                } while (Process32NextW(hSnapshot, &pe32));
            }
        }
        
        CloseHandle(hSnapshot);
        return false;
    }
    
    // Check for system debugger
    bool CheckSystemDebugger() {
        if (!NtQuerySystemInformation) return false;
        
        // SystemKernelDebuggerInformation
        struct SYSTEM_KERNEL_DEBUGGER_INFORMATION {
            BOOLEAN DebuggerEnabled;
            BOOLEAN DebuggerNotPresent;
        } debugInfo = { 0 };
        
        NTSTATUS status = NtQuerySystemInformation(
            (SYSTEM_INFORMATION_CLASS)35, // SystemKernelDebuggerInformation
            &debugInfo,
            sizeof(debugInfo),
            NULL
        );
        
        if (NT_SUCCESS(status)) {
            if (debugInfo.DebuggerEnabled && !debugInfo.DebuggerNotPresent) {
                return true;
            }
        }
        
        return false;
    }
    
    // Check SeDebugPrivilege
    bool CheckDebugPrivilege() {
        HANDLE hToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            return false;
        }
        
        TOKEN_PRIVILEGES tp;
        DWORD dwSize = sizeof(TOKEN_PRIVILEGES);
        
        // Check for debug privilege using proper LUID lookup
        LUID debugPrivilegeLuid;
        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &debugPrivilegeLuid)) {
            if (GetTokenInformation(hToken, TokenPrivileges, &tp, dwSize, &dwSize)) {
                for (DWORD i = 0; i < tp.PrivilegeCount; i++) {
                    if (tp.Privileges[i].Luid.LowPart == debugPrivilegeLuid.LowPart &&
                        tp.Privileges[i].Luid.HighPart == debugPrivilegeLuid.HighPart) {
                        if (tp.Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) {
                            CloseHandle(hToken);
                            return true;
                        }
                    }
                }
            }
        }
        
        CloseHandle(hToken);
        return false;
    }
    
    // Advanced timing attack detection
    bool CheckTimingAttacks() {
        LARGE_INTEGER start, end, freq;
        QueryPerformanceFrequency(&freq);
        
        // Test multiple timing scenarios
        for (int i = 0; i < 5; i++) {
            QueryPerformanceCounter(&start);
            
            // Execute some operations
            volatile int dummy = 0;
            for (int j = 0; j < 1000; j++) {
                dummy += j * j;
            }
            
            QueryPerformanceCounter(&end);
            
            // Calculate time in microseconds
            double timeTaken = (double)(end.QuadPart - start.QuadPart) * 1000000.0 / freq.QuadPart;
            
            // If timing is significantly slower, might be in debugger/sandbox
            if (timeTaken > 1000.0) { // More than 1ms for simple operations
                return true;
            }
        }
        
        return false;
    }
    
    // Check for API hooks (common in sandboxes)
    bool CheckAPIHooks() {
        struct APICheck {
            const char* module;
            const char* function;
            BYTE expectedBytes[5]; // First 5 bytes
        };
        
        APICheck checks[] = {
            {"kernel32.dll", "CreateFileW", {0x48, 0x89, 0x5C, 0x24, 0x08}}, // mov [rsp+8], rbx (typical start)
            {"kernel32.dll", "CreateProcessW", {0x48, 0x89, 0x5C, 0x24, 0x08}},
            {"ntdll.dll", "NtCreateFile", {0x4C, 0x8B, 0xD1, 0xB8, 0x55}}, // mov r10, rcx; mov eax, 55h
            {"ntdll.dll", "NtQueryInformationProcess", {0x4C, 0x8B, 0xD1, 0xB8, 0x19}},
            {"kernel32.dll", "WriteFile", {0x48, 0x89, 0x5C, 0x24, 0x08}}
        };
        
        for (const auto& check : checks) {
            HMODULE hMod = GetModuleHandleA(check.module);
            if (!hMod) continue;
            
            PVOID pFunc = (PVOID)GetProcAddress(hMod, check.function);
            if (!pFunc) continue;
            
            PBYTE pBytes = (PBYTE)pFunc;
            
            // Check for common hook signatures
            if (pBytes[0] == 0xE9 || pBytes[0] == 0xE8) { // JMP or CALL (hook)
                return true;
            }
            
            if (pBytes[0] == 0x68) { // PUSH (inline hook)
                return true;
            }
            
            // Check for unexpected modifications
            bool matches = true;
            for (int i = 0; i < 5; i++) {
                // Allow some variation but check for obvious hooks
                if (pBytes[i] == 0xCC || pBytes[i] == 0xC3) { // INT3 or RET
                    return true;
                }
            }
        }
        
        return false;
    }
    
    // Check for memory scanning patterns (sandbox behavior)
    bool CheckMemoryScanning() {
        // Allocate memory with specific pattern
        SIZE_T size = 0x10000;
        PVOID pMem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!pMem) return false;
        
        // Fill with pattern
        DWORD pattern = 0xDEADBEEF;
        for (SIZE_T i = 0; i < size / sizeof(DWORD); i++) {
            ((PDWORD)pMem)[i] = pattern;
        }
        
        Sleep(100); // Give sandbox time to scan
        
        // Check if pattern was modified (sign of memory scanning)
        bool modified = false;
        for (SIZE_T i = 0; i < size / sizeof(DWORD); i++) {
            if (((PDWORD)pMem)[i] != pattern) {
                modified = true;
                break;
            }
        }
        
        VirtualFree(pMem, 0, MEM_RELEASE);
        return modified;
    }
    
    // Advanced RDTSC timing checks
    bool CheckRDTSCTiming() {
        DWORD64 tsc1, tsc2, tsc3;
        
        // First measurement
        tsc1 = __rdtsc();
        tsc2 = __rdtsc();
        tsc3 = __rdtsc();
        
        // Check for irregular timing patterns
        DWORD64 diff1 = tsc2 - tsc1;
        DWORD64 diff2 = tsc3 - tsc2;
        
        // In virtual environment, RDTSC might have unusual patterns
        if (diff1 > 1000 || diff2 > 1000 || abs((int)(diff2 - diff1)) > 500) {
            return true;
        }
        
        // Test with operations in between
        tsc1 = __rdtsc();
        Sleep(10);
        tsc2 = __rdtsc();
        
        // 10ms should be roughly 10-30M cycles on modern CPUs
        DWORD64 sleepCycles = tsc2 - tsc1;
        if (sleepCycles < 1000000 || sleepCycles > 100000000) { // Too fast or too slow
            return true;
        }
        
        return false;
    }
    
    // Check for exception handling manipulation
    bool CheckExceptionHandling() {
        volatile bool caught = false;
        
        // Use SetUnhandledExceptionFilter to detect debugging
        LPTOP_LEVEL_EXCEPTION_FILTER originalFilter = SetUnhandledExceptionFilter(NULL);
        SetUnhandledExceptionFilter(originalFilter);
        
        // If no exception filter is set, might be in debugger
        if (originalFilter == NULL) {
            return true;
        }
        
        // Alternative check using VEH
        PVOID vehHandler = AddVectoredExceptionHandler(1, [](PEXCEPTION_POINTERS) -> LONG {
            return EXCEPTION_CONTINUE_SEARCH;
        });
        
        if (vehHandler == NULL) {
            return true; // VEH registration failed, might be debugger
        }
        
        RemoveVectoredExceptionHandler(vehHandler);
        return false;
    }
    
    // Hide thread from debugger
    void HideThread() {
        if (!NtSetInformationThread) return;
        
        HANDLE hThread = GetCurrentThread();
        ULONG hideThread = 1;
        
        NtSetInformationThread(
            hThread,
            (THREADINFOCLASS)17, // ThreadHideFromDebugger
            &hideThread,
            sizeof(ULONG)
        );
    }
    
    // Patch DbgBreakPoint to prevent breaks
    void PatchDbgBreakPoint() {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return;
        
        PVOID pDbgBreakPoint = (PVOID)GetProcAddress(hNtdll, "DbgBreakPoint");
        if (!pDbgBreakPoint) return;
        
        DWORD oldProtect;
        if (VirtualProtect(pDbgBreakPoint, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            *(PBYTE)pDbgBreakPoint = 0xC3; // RET
            VirtualProtect(pDbgBreakPoint, 1, oldProtect, &oldProtect);
        }
    }
    
    // Clear hardware debug registers
    void ClearDebugRegisters() {
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        
        if (GetThreadContext(GetCurrentThread(), &ctx)) {
            ctx.Dr0 = 0;
            ctx.Dr1 = 0;
            ctx.Dr2 = 0;
            ctx.Dr3 = 0;
            ctx.Dr6 = 0;
            ctx.Dr7 = 0;
            
            SetThreadContext(GetCurrentThread(), &ctx);
        }
    }
    
    // Setup trap flag protection
    void SetupTrapFlagProtection() {
        // Install vectored exception handler
        AddVectoredExceptionHandler(1, TrapFlagExceptionHandler);
    }
    
    // Exception handler for trap flag
    static LONG CALLBACK TrapFlagExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo) {
        if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
            // Clear trap flag
            pExceptionInfo->ContextRecord->EFlags &= ~0x100;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        
        return EXCEPTION_CONTINUE_SEARCH;
    }
};

// Define LogWarning as LogError if not available
#ifndef LogWarning
#define LogWarning LogError
#endif

extern "C" {
    bool CheckForDebugger() {
        AntiDebugProtection protection;
        bool debuggerDetected = protection.IsDebuggerPresent();
        
        if (debuggerDetected) {
            LogWarning("Debugger detected!");
            
            // Apply anti-debug protections
            protection.ApplyAntiDebugProtection();
        } else {
            LogInfo("No debugger detected");
        }
        
        return debuggerDetected;
    }
    
    void ApplyAntiDebugProtection() {
        AntiDebugProtection protection;
        protection.ApplyAntiDebugProtection();
        
        LogInfo("Anti-debug protection applied");
    }
    
    bool PerformCompleteAntiDebugCheck() {
        AntiDebugProtection protection;
        bool debuggerDetected = protection.IsDebuggerPresent();
        
        if (debuggerDetected) {
            LogError("Debugger/Analysis tool detected - terminating");
            
            // Apply all protections
            protection.ApplyAntiDebugProtection();
            
            // Additional evasive action
            ExitProcess(1);
        } else {
            LogInfo("Anti-debug check passed");
        }
        
        return !debuggerDetected;
    }
}