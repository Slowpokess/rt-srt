#include "utils.h"
#include <shlwapi.h>
#include <codecvt>
#include <locale>

#pragma comment(lib, "shlwapi.lib")

std::wstring Utils::StringToWString(const std::string& str) {
    if (str.empty()) {
        return std::wstring();
    }
    
    // Get required buffer size
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), NULL, 0);
    if (size_needed <= 0) {
        return std::wstring();
    }
    
    // Convert
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), &wstr[0], size_needed);
    
    return wstr;
}

std::string Utils::WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) {
        return std::string();
    }
    
    // Get required buffer size
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), NULL, 0, NULL, NULL);
    if (size_needed <= 0) {
        return std::string();
    }
    
    // Convert
    std::string str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), &str[0], size_needed, NULL, NULL);
    
    return str;
}

bool Utils::DirectoryExists(const std::wstring& path) {
    if (path.empty()) {
        return false;
    }
    
    DWORD attributes = GetFileAttributesW(path.c_str());
    return (attributes != INVALID_FILE_ATTRIBUTES && 
            (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0);
}

bool Utils::FileExists(const std::wstring& path) {
    if (path.empty()) {
        return false;
    }
    
    DWORD attributes = GetFileAttributesW(path.c_str());
    return (attributes != INVALID_FILE_ATTRIBUTES && 
            (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0);
}

size_t Utils::GetFileSize(const std::wstring& path) {
    if (path.empty()) {
        return 0;
    }
    
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, 
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        CloseHandle(hFile);
        return 0;
    }
    
    CloseHandle(hFile);
    
    // Return size if it fits in size_t, otherwise return 0 (too large)
    if (fileSize.QuadPart > SIZE_MAX) {
        return 0;
    }
    
    return (size_t)fileSize.QuadPart;
}

bool Utils::CreateDirectoryRecursive(const std::wstring& path) {
    if (path.empty()) {
        return false;
    }
    
    // Check if already exists
    if (DirectoryExists(path)) {
        return true;
    }
    
    // Find parent directory
    size_t pos = path.find_last_of(L"\\");
    if (pos != std::wstring::npos) {
        std::wstring parent = path.substr(0, pos);
        
        // Recursively create parent
        if (!CreateDirectoryRecursive(parent)) {
            return false;
        }
    }
    
    // Create this directory
    return CreateDirectoryW(path.c_str(), NULL) != 0 || GetLastError() == ERROR_ALREADY_EXISTS;
}