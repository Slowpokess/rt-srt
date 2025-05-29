#pragma once

#include <string>
#include <windows.h>

/**
 * Utility functions for string conversions and file operations
 */
class Utils {
public:
    /**
     * Convert std::string to std::wstring (UTF-8 to UTF-16)
     * @param str Input string
     * @return Wide string
     */
    static std::wstring StringToWString(const std::string& str);
    
    /**
     * Convert std::wstring to std::string (UTF-16 to UTF-8)
     * @param wstr Input wide string
     * @return Regular string
     */
    static std::string WStringToString(const std::wstring& wstr);
    
    /**
     * Check if directory exists
     * @param path Directory path (wide string)
     * @return true if directory exists
     */
    static bool DirectoryExists(const std::wstring& path);
    
    /**
     * Check if file exists
     * @param path File path (wide string)
     * @return true if file exists
     */
    static bool FileExists(const std::wstring& path);
    
    /**
     * Get file size safely
     * @param path File path
     * @return File size in bytes, 0 if file doesn't exist
     */
    static size_t GetFileSize(const std::wstring& path);
    
    /**
     * Create directory recursively
     * @param path Directory path
     * @return true if created or already exists
     */
    static bool CreateDirectoryRecursive(const std::wstring& path);
    
    /**
     * Check if current user has administrator privileges
     * @return true if running as administrator
     */
    static bool IsUserAdmin();
    
    /**
     * Generate random identifier string
     * @param length Length of identifier
     * @return Random identifier string
     */
    static std::string GenerateRandomIdentifier(DWORD length = 8);
    
    /**
     * Generate process-like name
     * @return Process-like name
     */
    static std::string GenerateProcessLikeName();
    
    /**
     * Generate service-like name
     * @return Service-like name
     */
    static std::string GenerateServiceLikeName();
};