#pragma once

#include "chromium_base.h"

/**
 * Microsoft Edge browser data extractor
 * Inherits from ChromiumBase for common Chromium functionality
 */
class EdgeExtractor : public ChromiumBase {
public:
    EdgeExtractor();
    virtual ~EdgeExtractor() = default;

protected:
    /**
     * Get Edge-specific profile search paths
     * @return Vector of paths where Edge profiles might be located
     */
    std::vector<std::wstring> GetProfileSearchPaths() override;
    
    /**
     * Get Edge database names (same as Chrome since it's Chromium-based)
     * @return Pair of (login_database_name, cookies_database_name)
     */
    std::pair<std::string, std::string> GetDatabaseNames() override;
    
private:
    /**
     * Get Edge installation path
     * @return Wide string path to Edge user data
     */
    std::wstring GetEdgeUserDataPath();
};