#include <windows.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <sstream>
#include "../common.h"

// Edge module - simplified version since Edge uses same Chromium base
class EdgeDataExtractor {
public:
    std::string ExtractAll() {
        // Edge uses similar structure to Chrome (Chromium-based)
        // Path: %LOCALAPPDATA%\Microsoft\Edge\User Data
        
        WCHAR localAppData[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData))) {
            std::wstring edgePath = std::wstring(localAppData) + L"\\Microsoft\\Edge\\User Data";
            
            if (Utils::DirectoryExists(edgePath)) {
                return "{\"browser\":\"edge\",\"note\":\"Edge uses Chromium engine - similar to Chrome\",\"profiles\":[]}";
            }
        }
        
        return "{\"browser\":\"edge\",\"error\":\"not_found\",\"profiles\":[]}";
    }
};

// Export function
extern "C" {
    const char* ExtractEdgeData() {
        static std::string result;
        
        try {
            EdgeDataExtractor extractor;
            result = extractor.ExtractAll();
            
            extern void LogInfo(const char*);
            LogInfo("Edge data extraction completed");
            
            return result.c_str();
        } catch (...) {
            extern void LogError(const char*);
            LogError("Failed to extract Edge data");
            
            result = "{\"browser\":\"edge\",\"error\":\"extraction_failed\",\"profiles\":[]}";
            return result.c_str();
        }
    }
}