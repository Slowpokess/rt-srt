#include "edge_extractor.h"
#include "../utils.h"
#include <shlobj.h>

EdgeExtractor::EdgeExtractor() 
    : ChromiumBase("Edge", GetEdgeUserDataPath()) {
}

std::vector<std::wstring> EdgeExtractor::GetProfileSearchPaths() {
    std::vector<std::wstring> paths;
    
    // Primary Edge user data path
    std::wstring edge_path = GetEdgeUserDataPath();
    if (!edge_path.empty()) {
        paths.push_back(edge_path);
    }
    
    return paths;
}

std::pair<std::string, std::string> EdgeExtractor::GetDatabaseNames() {
    // Edge uses same database names as Chrome since it's Chromium-based
    return std::make_pair("Login Data", "Cookies");
}

std::wstring EdgeExtractor::GetEdgeUserDataPath() {
    WCHAR path[MAX_PATH];
    
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path))) {
        std::wstring edge_path = std::wstring(path) + L"\\Microsoft\\Edge\\User Data";
        
        if (Utils::DirectoryExists(edge_path)) {
            return edge_path;
        }
    }
    
    return L"";
}