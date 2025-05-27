#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <mutex>
#include "../common.h"

class FileLogger {
private:
    std::wstring log_path;
    HANDLE hFile;
    std::mutex log_mutex;
    bool console_output;
    
    // Log levels (matching existing enum)
    enum LogLevel {
        LOG_DEBUG = 0,
        LOG_INFO = 1,
        LOG_WARNING = 2,
        LOG_ERROR = 3,
        LOG_CRITICAL = 4
    };
    
    LogLevel current_level;
    
    // Private helper methods (need to be implemented)
    void InitializeLogPath();
    std::wstring GenerateLogFilename();
    void WriteHeader();
    std::string FormatLogEntry(LogLevel level, const std::string& message);
    std::wstring GenerateRandomString(size_t length);
    std::string GetCurrentTimestamp();
    const char* GetLevelString(LogLevel level);

public:
    FileLogger();
    ~FileLogger();
    
    // Main logging methods
    bool Initialize(const std::wstring& filename = L"");
    void Log(LogLevel level, const std::string& message);
    
    // Convenience methods
    void Debug(const std::string& msg);
    void Info(const std::string& msg);
    void Warning(const std::string& msg);
    void Error(const std::string& msg);
    void Critical(const std::string& msg);
    
    // Template method (must be in header)
    template<typename... Args>
    void LogF(LogLevel level, const char* format, Args... args) {
        char buffer[1024];
        snprintf(buffer, sizeof(buffer), format, args...);
        Log(level, std::string(buffer));
    }
    
    // Configuration methods
    void SetLevel(LogLevel level);
    void SetConsoleOutput(bool enable);
    
    // Utility methods
    std::vector<BYTE> GetLogData();
    void Clear();
    void Close();
    void DeleteLogFile();
};

// C-style interface declarations
extern "C" {
    void InitLogger();
    void LogInfo(const char* message);
    void LogError(const char* message);
    void LogWarning(const char* message);
    void LogDebug(const char* message);
    void CleanupLogger();
}