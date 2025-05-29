#pragma once

#include "chromium_base.h"

/**
 * Chrome browser data extractor
 * Inherits from ChromiumBase for common Chromium functionality
 */
class ChromeExtractor : public ChromiumBase {
public:
    ChromeExtractor();
    virtual ~ChromeExtractor() = default;

protected:
    /**
     * Get Chrome-specific profile search paths
     * @return Vector of paths where Chrome profiles might be located
     */
    std::vector<std::wstring> GetProfileSearchPaths() override;
    
    /**
     * Get Chrome database names
     * @return Pair of (login_database_name, cookies_database_name)
     */
    std::pair<std::string, std::string> GetDatabaseNames() override;
    
private:
    /**
     * Get Chrome installation path
     * @return Wide string path to Chrome user data
     */
    std::wstring GetChromeUserDataPath();
};