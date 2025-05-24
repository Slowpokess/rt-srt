#include "file_logger.h"
#include <windows.h>
#include <shlobj.h>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <chrono>
#include <memory>

// Constructor
FileLogger::FileLogger() : hFile(INVALID_HANDLE_VALUE), console_output(false), current_level(LOG_INFO) {
    InitializeLogPath();
}

// Destructor
FileLogger::~FileLogger() {
    Close();
}

// Initialize log file in temp directory
bool FileLogger::Initialize(const std::wstring& filename) {
    std::lock_guard<std::mutex> lock(log_mutex);
    
    if (hFile != INVALID_HANDLE_VALUE) {
        return true; // Already initialized
    }
    
    // Generate filename if not provided
    std::wstring log_filename = filename.empty() ? GenerateLogFilename() : filename;
    std::wstring full_path = log_path + L"\\" + log_filename;
    
    // Create file with minimal footprint
    hFile = CreateFileW(
        full_path.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_HIDDEN | FILE_FLAG_WRITE_THROUGH,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    // Write header
    WriteHeader();
    
    return true;
}

// Main logging function
void FileLogger::Log(LogLevel level, const std::string& message) {
    if (level < current_level) return;
    
    std::lock_guard<std::mutex> lock(log_mutex);
    
    std::string log_entry = FormatLogEntry(level, message);
    
    // Write to file
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(hFile, log_entry.c_str(), (DWORD)log_entry.length(), &written, NULL);
        FlushFileBuffers(hFile);
    }
    
    // Console output for debugging (only in debug builds)
#ifdef _DEBUG
    if (console_output) {
        OutputDebugStringA(log_entry.c_str());
    }
#endif
}

// Convenience methods
void FileLogger::Debug(const std::string& msg) { Log(LOG_DEBUG, msg); }
void FileLogger::Info(const std::string& msg) { Log(LOG_INFO, msg); }
void FileLogger::Warning(const std::string& msg) { Log(LOG_WARNING, msg); }
void FileLogger::Error(const std::string& msg) { Log(LOG_ERROR, msg); }
void FileLogger::Critical(const std::string& msg) { Log(LOG_CRITICAL, msg); }

// Set log level
void FileLogger::SetLevel(LogLevel level) {
    current_level = level;
}

// Enable/disable console output
void FileLogger::SetConsoleOutput(bool enable) {
    console_output = enable;
}

// Get current log data
std::vector<BYTE> FileLogger::GetLogData() {
    std::lock_guard<std::mutex> lock(log_mutex);
    std::vector<BYTE> data;
    
    if (hFile == INVALID_HANDLE_VALUE) {
        return data;
    }
    
    // Get file size
    LARGE_INTEGER size;
    if (!GetFileSizeEx(hFile, &size)) {
        return data;
    }
    
    // Read file content
    data.resize((size_t)size.QuadPart);
    DWORD read;
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    ReadFile(hFile, data.data(), (DWORD)data.size(), &read, NULL);
    SetFilePointer(hFile, 0, NULL, FILE_END);
    
    return data;
}

// Clear log file
void FileLogger::Clear() {
    std::lock_guard<std::mutex> lock(log_mutex);
    
    if (hFile != INVALID_HANDLE_VALUE) {
        SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
        SetEndOfFile(hFile);
        WriteHeader();
    }
}

// Close log file
void FileLogger::Close() {
    std::lock_guard<std::mutex> lock(log_mutex);
    
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
    }
}

// Delete log file
void FileLogger::DeleteLogFile() {
    Close();
    
    // Delete all log files in directory
    std::wstring search_path = log_path + L"\\*.log";
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(search_path.c_str(), &fd);
    
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            std::wstring file_path = log_path + L"\\" + fd.cFileName;
            DeleteFileW(file_path.c_str());
        } while (FindNextFileW(hFind, &fd));
        
        FindClose(hFind);
    }
}

// Private helper methods implementation
void FileLogger::InitializeLogPath() {
    WCHAR temp_path[MAX_PATH];
    GetTempPathW(MAX_PATH, temp_path);
    
    // Create unique subdirectory
    log_path = std::wstring(temp_path) + L"\\~tmp" + GenerateRandomString(6);
    CreateDirectoryW(log_path.c_str(), NULL);
    
    // Hide directory
    SetFileAttributesW(log_path.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
}

std::wstring FileLogger::GenerateLogFilename() {
    // Generate filename with timestamp
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::wstringstream ss;
    ss << L"log_" << time_t << L".log";
    return ss.str();
}

std::wstring FileLogger::GenerateRandomString(size_t length) {
    const wchar_t charset[] = L"abcdefghijklmnopqrstuvwxyz0123456789";
    std::wstring result;
    result.reserve(length);
    
    for (size_t i = 0; i < length; ++i) {
        result += charset[rand() % (sizeof(charset) / sizeof(charset[0]) - 1)];
    }
    
    return result;
}

void FileLogger::WriteHeader() {
    std::string header = "=== RT-SRT Log ===\n";
    header += "Version: 1.0\n";
    header += "Started: " + GetCurrentTimestamp() + "\n";
    header += "==================\n";
    
    DWORD written;
    WriteFile(hFile, header.c_str(), (DWORD)header.length(), &written, NULL);
}

std::string FileLogger::FormatLogEntry(LogLevel level, const std::string& message) {
    std::stringstream ss;
    
    // Timestamp
    ss << "[" << GetCurrentTimestamp() << "] ";
    
    // Level
    ss << "[" << GetLevelString(level) << "] ";
    
    // Message
    ss << message << "\n";
    
    return ss.str();
}

std::string FileLogger::GetCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    struct tm timeinfo;
    localtime_s(&timeinfo, &time_t);
    
    char buffer[32];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &timeinfo);
    
    return std::string(buffer);
}

const char* FileLogger::GetLevelString(LogLevel level) {
    switch (level) {
        case LOG_DEBUG: return "DEBUG";
        case LOG_INFO: return "INFO";
        case LOG_WARNING: return "WARN";
        case LOG_ERROR: return "ERROR";
        case LOG_CRITICAL: return "CRIT";
        default: return "UNKNOWN";
    }
}

// Global logger instance
std::unique_ptr<FileLogger> g_logger;

// C-style interface for easy use
extern "C" {
    void InitLogger() {
        if (!g_logger) {
            g_logger = std::make_unique<FileLogger>();
            g_logger->Initialize();
        }
    }
    
    void LogInfo(const char* message) {
        if (g_logger) g_logger->Info(message);
    }
    
    void LogError(const char* message) {
        if (g_logger) g_logger->Error(message);
    }
    
    void LogDebug(const char* message) {
        if (g_logger) g_logger->Debug(message);
    }
    
    void CleanupLogger() {
        if (g_logger) {
            g_logger->DeleteLogFile();
            g_logger.reset();
        }
    }
}