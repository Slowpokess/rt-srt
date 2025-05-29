#include "chrome_extractor.h"
#include "../utils.h"
#include <shlobj.h>

ChromeExtractor::ChromeExtractor() 
    : ChromiumBase("Chrome", GetChromeUserDataPath()) {
}

std::vector<std::wstring> ChromeExtractor::GetProfileSearchPaths() {
    std::vector<std::wstring> paths;
    
    // Primary Chrome user data path
    std::wstring chrome_path = GetChromeUserDataPath();
    if (!chrome_path.empty()) {
        paths.push_back(chrome_path);
    }
    
    return paths;
}

std::pair<std::string, std::string> ChromeExtractor::GetDatabaseNames() {
    return std::make_pair("Login Data", "Cookies");
}

std::wstring ChromeExtractor::GetChromeUserDataPath() {
    WCHAR path[MAX_PATH];
    
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path))) {
        std::wstring chrome_path = std::wstring(path) + L"\\Google\\Chrome\\User Data";
        
        if (Utils::DirectoryExists(chrome_path)) {
            return chrome_path;
        }
    }
    
    return L"";
}