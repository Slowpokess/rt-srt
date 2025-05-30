#include "localized_messages.h"
#include "../common.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <ctime>

// Логирование
extern void LogInfo(const char* message);
extern void LogError(const char* message);
extern void LogDebug(const char* message);
extern void LogWarning(const char* message);

namespace LocalizedDeception {

// =======================================================================
// RegionDetector Implementation
// =======================================================================

RegionDetector::RegionDetector() : detectedLanguage(LanguageCode::UNKNOWN), systemLCID(0) {
    LogDebug("RegionDetector: Инициализация детектора региона");
}

RegionDetector::~RegionDetector() {}

bool RegionDetector::DetectSystemLanguage() {
    LogInfo("RegionDetector: Определение языка системы...");
    
    try {
        // Получаем системный LCID
        systemLCID = GetSystemDefaultLCID();
        LogDebug(("RegionDetector: Системный LCID: " + std::to_string(systemLCID)).c_str());
        
        // Получаем язык пользователя
        LCID userLCID = GetUserDefaultLCID();
        LogDebug(("RegionDetector: Пользовательский LCID: " + std::to_string(userLCID)).c_str());
        
        // Используем пользовательский LCID как приоритетный
        LCID targetLCID = userLCID != 0 ? userLCID : systemLCID;
        
        // Определяем язык
        detectedLanguage = MapLCIDToLanguage(targetLCID);
        
        // Получаем коды языка и страны
        char langCode[10] = {0};
        char countryCode[10] = {0};
        
        GetLocaleInfoA(targetLCID, LOCALE_SISO639LANGNAME, langCode, sizeof(langCode));
        GetLocaleInfoA(targetLCID, LOCALE_SISO3166CTRYNAME, countryCode, sizeof(countryCode));
        
        languageCode = std::string(langCode);
        this->countryCode = std::string(countryCode);
        
        LogInfo(("RegionDetector: Обнаружен язык: " + languageCode + 
                ", страна: " + this->countryCode).c_str());
        
        return true;
        
    } catch (const std::exception& e) {
        LogError(("RegionDetector: Ошибка определения языка: " + std::string(e.what())).c_str());
        detectedLanguage = LanguageCode::ENGLISH; // Fallback to English
        return false;
    }
}

LanguageCode RegionDetector::MapLCIDToLanguage(LCID lcid) {
    LANGID langId = LANGIDFROMLCID(lcid);
    WORD primaryLang = PRIMARYLANGID(langId);
    
    LogDebug(("RegionDetector: Первичный язык ID: " + std::to_string(primaryLang)).c_str());
    
    switch (primaryLang) {
        case LANG_ENGLISH:
            return LanguageCode::ENGLISH;
        case LANG_RUSSIAN:
            return LanguageCode::RUSSIAN;
        case LANG_GERMAN:
            return LanguageCode::GERMAN;
        case LANG_FRENCH:
            return LanguageCode::FRENCH;
        case LANG_SPANISH:
            return LanguageCode::SPANISH;
        case LANG_ITALIAN:
            return LanguageCode::ITALIAN;
        case LANG_PORTUGUESE:
            return LanguageCode::PORTUGUESE;
        case LANG_CHINESE:
            // Различаем упрощенный и традиционный китайский
            if (SUBLANGID(langId) == SUBLANG_CHINESE_SIMPLIFIED) {
                return LanguageCode::CHINESE_SIMPLIFIED;
            } else {
                return LanguageCode::CHINESE_TRADITIONAL;
            }
        case LANG_JAPANESE:
            return LanguageCode::JAPANESE;
        case LANG_KOREAN:
            return LanguageCode::KOREAN;
        case LANG_DUTCH:
            return LanguageCode::DUTCH;
        case LANG_POLISH:
            return LanguageCode::POLISH;
        case LANG_CZECH:
            return LanguageCode::CZECH;
        case LANG_HUNGARIAN:
            return LanguageCode::HUNGARIAN;
        case LANG_BULGARIAN:
            return LanguageCode::BULGARIAN;
        case LANG_UKRAINIAN:
            return LanguageCode::UKRAINIAN;
        case LANG_TURKISH:
            return LanguageCode::TURKISH;
        case LANG_ARABIC:
            return LanguageCode::ARABIC;
        case LANG_HEBREW:
            return LanguageCode::HEBREW;
        default:
            LogWarning(("RegionDetector: Неизвестный язык ID: " + std::to_string(primaryLang)).c_str());
            return LanguageCode::ENGLISH; // Default fallback
    }
}

std::string RegionDetector::GetSystemLocaleName() {
    wchar_t localeName[LOCALE_NAME_MAX_LENGTH];
    if (GetSystemDefaultLocaleName(localeName, LOCALE_NAME_MAX_LENGTH) > 0) {
        // Конвертируем WCHAR в std::string
        std::wstring wstr(localeName);
        return std::string(wstr.begin(), wstr.end());
    }
    return "en-US";
}

std::string RegionDetector::GetKeyboardLayout() {
    // Просто получаем название раскладки клавиатуры напрямую
    char layoutName[KL_NAMELENGTH];
    if (GetKeyboardLayoutNameA(layoutName)) {
        return std::string(layoutName);
    }
    return "00000409"; // US English default
}

std::string RegionDetector::GetTimeZone() {
    TIME_ZONE_INFORMATION tzi;
    DWORD result = GetTimeZoneInformation(&tzi);
    
    if (result != TIME_ZONE_ID_INVALID) {
        // Конвертируем WCHAR в std::string
        std::wstring wstr(tzi.StandardName);
        return std::string(wstr.begin(), wstr.end());
    }
    return "UTC";
}

std::string RegionDetector::GetCurrencySymbol() {
    char currency[10];
    if (GetLocaleInfoA(LOCALE_USER_DEFAULT, LOCALE_SCURRENCY, currency, sizeof(currency)) > 0) {
        return std::string(currency);
    }
    return "$";
}

bool RegionDetector::IsRightToLeftLanguage() {
    return (detectedLanguage == LanguageCode::ARABIC || 
            detectedLanguage == LanguageCode::HEBREW);
}

bool RegionDetector::IsAsianLanguage() {
    return (detectedLanguage == LanguageCode::CHINESE_SIMPLIFIED ||
            detectedLanguage == LanguageCode::CHINESE_TRADITIONAL ||
            detectedLanguage == LanguageCode::JAPANESE ||
            detectedLanguage == LanguageCode::KOREAN);
}

// =======================================================================
// LocalizedMessageManager Implementation
// =======================================================================

LocalizedMessageManager::LocalizedMessageManager() : 
    currentLanguage(LanguageCode::ENGLISH), regionDetector(nullptr) {
    LogDebug("LocalizedMessageManager: Инициализация менеджера сообщений");
}

LocalizedMessageManager::~LocalizedMessageManager() {
    if (regionDetector) {
        delete regionDetector;
    }
}

bool LocalizedMessageManager::Initialize() {
    LogInfo("LocalizedMessageManager: Инициализация...");
    
    try {
        // Создаем детектор региона
        regionDetector = new RegionDetector();
        
        // Инициализируем все языки
        InitializeAllLanguages();
        
        // Автоматически определяем язык
        AutoDetectLanguage();
        
        LogInfo(("LocalizedMessageManager: Инициализирован для языка: " + 
                std::to_string(static_cast<int>(currentLanguage))).c_str());
        
        return true;
        
    } catch (const std::exception& e) {
        LogError(("LocalizedMessageManager: Ошибка инициализации: " + std::string(e.what())).c_str());
        return false;
    }
}

void LocalizedMessageManager::AutoDetectLanguage() {
    if (regionDetector && regionDetector->DetectSystemLanguage()) {
        currentLanguage = regionDetector->GetDetectedLanguage();
        LogInfo(("LocalizedMessageManager: Автоматически установлен язык: " + 
                std::to_string(static_cast<int>(currentLanguage))).c_str());
    } else {
        currentLanguage = LanguageCode::ENGLISH;
        LogWarning("LocalizedMessageManager: Не удалось определить язык, используется английский");
    }
}

void LocalizedMessageManager::InitializeAllLanguages() {
    LogDebug("LocalizedMessageManager: Инициализация всех языков...");
    
    InitializeEnglishMessages();
    InitializeRussianMessages();
    InitializeGermanMessages();
    InitializeFrenchMessages();
    InitializeSpanishMessages();
    // Добавьте другие языки по необходимости
    
    LogDebug(("LocalizedMessageManager: Инициализировано " + 
             std::to_string(messageDatabase.size()) + " языков").c_str());
}

void LocalizedMessageManager::InitializeRussianMessages() {
    std::vector<LocalizedMessage> russianMessages;
    
    // Сообщения об ошибках
    for (const auto& msg : MessageTemplates::RUSSIAN_ERRORS) {
        LocalizedMessage locMsg;
        locMsg.language = LanguageCode::RUSSIAN;
        locMsg.errorMessage = msg;
        locMsg.windowTitle = MessageTemplates::RUSSIAN_TITLES[rand() % MessageTemplates::RUSSIAN_TITLES.size()];
        locMsg.buttonOK = "ОК";
        locMsg.buttonCancel = "Отмена";
        russianMessages.push_back(locMsg);
    }
    
    // Сообщения об успехе
    for (const auto& msg : MessageTemplates::RUSSIAN_SUCCESS) {
        LocalizedMessage locMsg;
        locMsg.language = LanguageCode::RUSSIAN;
        locMsg.successMessage = msg;
        locMsg.windowTitle = "Успешно";
        locMsg.buttonOK = "ОК";
        russianMessages.push_back(locMsg);
    }
    
    messageDatabase[LanguageCode::RUSSIAN] = russianMessages;
    LogDebug("LocalizedMessageManager: Русские сообщения загружены");
}

void LocalizedMessageManager::InitializeEnglishMessages() {
    std::vector<LocalizedMessage> englishMessages;
    
    // Сообщения об ошибках
    for (const auto& msg : MessageTemplates::ENGLISH_ERRORS) {
        LocalizedMessage locMsg;
        locMsg.language = LanguageCode::ENGLISH;
        locMsg.errorMessage = msg;
        locMsg.windowTitle = MessageTemplates::ENGLISH_TITLES[rand() % MessageTemplates::ENGLISH_TITLES.size()];
        locMsg.buttonOK = "OK";
        locMsg.buttonCancel = "Cancel";
        englishMessages.push_back(locMsg);
    }
    
    // Сообщения об успехе
    for (const auto& msg : MessageTemplates::ENGLISH_SUCCESS) {
        LocalizedMessage locMsg;
        locMsg.language = LanguageCode::ENGLISH;
        locMsg.successMessage = msg;
        locMsg.windowTitle = "Success";
        locMsg.buttonOK = "OK";
        englishMessages.push_back(locMsg);
    }
    
    messageDatabase[LanguageCode::ENGLISH] = englishMessages;
    LogDebug("LocalizedMessageManager: Английские сообщения загружены");
}

void LocalizedMessageManager::InitializeGermanMessages() {
    std::vector<LocalizedMessage> germanMessages;
    
    // Сообщения об ошибках
    for (const auto& msg : MessageTemplates::GERMAN_ERRORS) {
        LocalizedMessage locMsg;
        locMsg.language = LanguageCode::GERMAN;
        locMsg.errorMessage = msg;
        locMsg.windowTitle = MessageTemplates::GERMAN_TITLES[rand() % MessageTemplates::GERMAN_TITLES.size()];
        locMsg.buttonOK = "OK";
        locMsg.buttonCancel = "Abbrechen";
        germanMessages.push_back(locMsg);
    }
    
    // Сообщения об успехе
    for (const auto& msg : MessageTemplates::GERMAN_SUCCESS) {
        LocalizedMessage locMsg;
        locMsg.language = LanguageCode::GERMAN;
        locMsg.successMessage = msg;
        locMsg.windowTitle = "Erfolgreich";
        locMsg.buttonOK = "OK";
        germanMessages.push_back(locMsg);
    }
    
    messageDatabase[LanguageCode::GERMAN] = germanMessages;
    LogDebug("LocalizedMessageManager: Немецкие сообщения загружены");
}

void LocalizedMessageManager::InitializeFrenchMessages() {
    std::vector<LocalizedMessage> frenchMessages;
    
    // Сообщения об ошибках
    for (const auto& msg : MessageTemplates::FRENCH_ERRORS) {
        LocalizedMessage locMsg;
        locMsg.language = LanguageCode::FRENCH;
        locMsg.errorMessage = msg;
        locMsg.windowTitle = MessageTemplates::FRENCH_TITLES[rand() % MessageTemplates::FRENCH_TITLES.size()];
        locMsg.buttonOK = "OK";
        locMsg.buttonCancel = "Annuler";
        frenchMessages.push_back(locMsg);
    }
    
    // Сообщения об успехе
    for (const auto& msg : MessageTemplates::FRENCH_SUCCESS) {
        LocalizedMessage locMsg;
        locMsg.language = LanguageCode::FRENCH;
        locMsg.successMessage = msg;
        locMsg.windowTitle = "Succès";
        locMsg.buttonOK = "OK";
        frenchMessages.push_back(locMsg);
    }
    
    messageDatabase[LanguageCode::FRENCH] = frenchMessages;
    LogDebug("LocalizedMessageManager: Французские сообщения загружены");
}

void LocalizedMessageManager::InitializeSpanishMessages() {
    std::vector<LocalizedMessage> spanishMessages;
    
    // Сообщения об ошибках
    for (const auto& msg : MessageTemplates::SPANISH_ERRORS) {
        LocalizedMessage locMsg;
        locMsg.language = LanguageCode::SPANISH;
        locMsg.errorMessage = msg;
        locMsg.windowTitle = MessageTemplates::SPANISH_TITLES[rand() % MessageTemplates::SPANISH_TITLES.size()];
        locMsg.buttonOK = "Aceptar";
        locMsg.buttonCancel = "Cancelar";
        spanishMessages.push_back(locMsg);
    }
    
    // Сообщения об успехе
    for (const auto& msg : MessageTemplates::SPANISH_SUCCESS) {
        LocalizedMessage locMsg;
        locMsg.language = LanguageCode::SPANISH;
        locMsg.successMessage = msg;
        locMsg.windowTitle = "Éxito";
        locMsg.buttonOK = "Aceptar";
        spanishMessages.push_back(locMsg);
    }
    
    messageDatabase[LanguageCode::SPANISH] = spanishMessages;
    LogDebug("LocalizedMessageManager: Испанские сообщения загружены");
}

std::string LocalizedMessageManager::GetRandomErrorMessage() {
    auto it = messageDatabase.find(currentLanguage);
    if (it != messageDatabase.end() && !it->second.empty()) {
        const auto& messages = it->second;
        for (const auto& msg : messages) {
            if (!msg.errorMessage.empty()) {
                return msg.errorMessage;
            }
        }
    }
    
    // Fallback to English
    auto enIt = messageDatabase.find(LanguageCode::ENGLISH);
    if (enIt != messageDatabase.end() && !enIt->second.empty()) {
        return enIt->second[0].errorMessage;
    }
    
    return "An error occurred. Please try again.";
}

std::string LocalizedMessageManager::GetRandomSuccessMessage() {
    auto it = messageDatabase.find(currentLanguage);
    if (it != messageDatabase.end() && !it->second.empty()) {
        const auto& messages = it->second;
        for (const auto& msg : messages) {
            if (!msg.successMessage.empty()) {
                return msg.successMessage;
            }
        }
    }
    
    // Fallback to English
    return "Operation completed successfully.";
}

std::string LocalizedMessageManager::GetRandomWindowTitle() {
    auto it = messageDatabase.find(currentLanguage);
    if (it != messageDatabase.end() && !it->second.empty()) {
        const auto& messages = it->second;
        return messages[rand() % messages.size()].windowTitle;
    }
    
    return "System Message";
}

// =======================================================================
// AdaptiveMessageGenerator Implementation
// =======================================================================

AdaptiveMessageGenerator::AdaptiveMessageGenerator() : 
    msgManager(nullptr), regionDetector(nullptr) {
    LogDebug("AdaptiveMessageGenerator: Инициализация генератора сообщений");
}

AdaptiveMessageGenerator::~AdaptiveMessageGenerator() {
    if (msgManager) delete msgManager;
    if (regionDetector) delete regionDetector;
}

bool AdaptiveMessageGenerator::Initialize() {
    LogInfo("AdaptiveMessageGenerator: Инициализация...");
    
    try {
        msgManager = new LocalizedMessageManager();
        regionDetector = new RegionDetector();
        
        if (!msgManager->Initialize()) {
            LogError("AdaptiveMessageGenerator: Ошибка инициализации менеджера сообщений");
            return false;
        }
        
        if (!regionDetector->DetectSystemLanguage()) {
            LogError("AdaptiveMessageGenerator: Ошибка определения языка");
            return false;
        }
        
        // Анализируем систему для контекстных сообщений
        AnalyzeSystemContext();
        
        LogInfo("AdaptiveMessageGenerator: Инициализация завершена успешно");
        return true;
        
    } catch (const std::exception& e) {
        LogError(("AdaptiveMessageGenerator: Исключение при инициализации: " + std::string(e.what())).c_str());
        return false;
    }
}

std::string AdaptiveMessageGenerator::GenerateContextualErrorMessage() {
    std::string baseMessage = msgManager->GetRandomErrorMessage();
    
    // Адаптируем сообщение под регион
    std::string adaptedMessage = AdaptMessageToRegion(baseMessage);
    
    // Добавляем региональные контакты
    adaptedMessage = AddRegionalContacts(adaptedMessage);
    
    // Добавляем местное время
    adaptedMessage = AddLocalDateTime(adaptedMessage);
    
    LogDebug("AdaptiveMessageGenerator: Сгенерировано контекстное сообщение об ошибке");
    return adaptedMessage;
}

std::string AdaptiveMessageGenerator::AdaptMessageToRegion(const std::string& baseMessage) {
    std::string adaptedMessage = baseMessage;
    
    // Получаем информацию о регионе
    std::string countryCode = regionDetector->GetCountryCode();
    std::string currencySymbol = regionDetector->GetCurrencySymbol();
    
    // Заменяем общие контакты на региональные (используем простую замену строк)
    size_t pos = adaptedMessage.find("support@microsoft.com");
    if (pos != std::string::npos) {
        std::string replacement;
        if (countryCode == "RU") {
            replacement = "support@microsoft-russia.ru";
        } else if (countryCode == "DE") {
            replacement = "support@microsoft-deutschland.de";
        } else if (countryCode == "FR") {
            replacement = "support@microsoft-france.fr";
        } else {
            replacement = "support@microsoft.com";
        }
        adaptedMessage.replace(pos, strlen("support@microsoft.com"), replacement);
    }
    
    return adaptedMessage;
}

std::string AdaptiveMessageGenerator::AddRegionalContacts(const std::string& message) {
    std::string result = message;
    
    // Получаем информацию о регионе
    std::string countryCode = regionDetector->GetCountryCode();
    
    // Добавляем региональные контакты в зависимости от страны
    if (countryCode == "RU") {
        result += "\n\nТехническая поддержка Microsoft Russia:\nТел: +7 (495) 916-71-71\nEmail: support@microsoft-russia.com";
    } else if (countryCode == "DE") {
        result += "\n\nMicrosoft Deutschland Support:\nTel: +49 (89) 3176-1000\nEmail: support@microsoft-deutschland.de";
    } else if (countryCode == "FR") {
        result += "\n\nSupport Microsoft France:\nTél: +33 (1) 85-73-03-00\nEmail: support@microsoft-france.fr";
    } else {
        result += "\n\nMicrosoft Support:\nPhone: 1-800-MICROSOFT\nEmail: support@microsoft.com";
    }
    
    return result;
}

std::string AdaptiveMessageGenerator::AddLocalDateTime(const std::string& message) {
    std::time_t now = std::time(0);
    std::tm* timeinfo = std::localtime(&now);
    
    std::ostringstream oss;
    
    // Форматируем время в зависимости от региона
    LanguageCode lang = regionDetector->GetDetectedLanguage();
    
    if (lang == LanguageCode::RUSSIAN) {
        oss << std::put_time(timeinfo, "%d.%m.%Y в %H:%M");
    } else if (lang == LanguageCode::GERMAN) {
        oss << std::put_time(timeinfo, "%d.%m.%Y um %H:%M");
    } else if (lang == LanguageCode::FRENCH) {
        oss << std::put_time(timeinfo, "%d/%m/%Y à %H:%M");
    } else {
        oss << std::put_time(timeinfo, "%m/%d/%Y at %H:%M");
    }
    
    std::string dateTime = oss.str();
    
    // Добавляем время в сообщение, если есть соответствующие плейсхолдеры (простая замена)
    std::string result = message;
    if (result.find("сегодня в ") != std::string::npos) {
        size_t pos = result.find("сегодня в ");
        if (pos != std::string::npos) {
            result.replace(pos, result.find("\n", pos) - pos, "сегодня в " + dateTime);
        }
    }
    if (result.find("today at ") != std::string::npos) {
        size_t pos = result.find("today at ");
        if (pos != std::string::npos) {
            result.replace(pos, result.find("\n", pos) - pos, "today at " + dateTime);
        }
    }
    
    return result;
}

void AdaptiveMessageGenerator::AnalyzeSystemContext() {
    LogDebug("AdaptiveMessageGenerator: Анализ контекста системы...");
    
    // Определяем версию ОС
    OSVERSIONINFOA osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOA));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
    
    if (GetVersionExA(&osvi)) {
        systemVersion = "Windows " + std::to_string(osvi.dwMajorVersion) + "." + std::to_string(osvi.dwMinorVersion);
    } else {
        systemVersion = "Windows";
    }
    
    // Определяем установленное ПО (упрощенная версия)
    DetectInstalledSoftware();
    
    LogDebug(("AdaptiveMessageGenerator: Система: " + systemVersion + 
             ", ПО: " + detectedSoftware).c_str());
}

void AdaptiveMessageGenerator::DetectInstalledSoftware() {
    // Проверяем наличие популярного ПО через реестр
    HKEY hKey;
    std::vector<std::string> softwareList;
    
    const char* regPath = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, regPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        // Проверяем несколько популярных программ
        char subKeyName[256];
        DWORD subKeyNameSize = sizeof(subKeyName);
        DWORD index = 0;
        
        while (RegEnumKeyExA(hKey, index++, subKeyName, &subKeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            std::string keyName(subKeyName);
            
            if (keyName.find("Adobe") != std::string::npos) {
                softwareList.push_back("Adobe");
            } else if (keyName.find("Microsoft Office") != std::string::npos) {
                softwareList.push_back("Microsoft Office");
            } else if (keyName.find("Google Chrome") != std::string::npos) {
                softwareList.push_back("Google Chrome");
            }
            
            subKeyNameSize = sizeof(subKeyName);
            
            // Ограничиваем поиск для производительности
            if (index > 100) break;
        }
        
        RegCloseKey(hKey);
    }
    
    // Объединяем найденное ПО
    if (!softwareList.empty()) {
        detectedSoftware = softwareList[0];
        for (size_t i = 1; i < softwareList.size() && i < 3; ++i) {
            detectedSoftware += ", " + softwareList[i];
        }
    } else {
        detectedSoftware = "Standard";
    }
}

// =======================================================================
// Global instances for C interface
// =======================================================================

static std::unique_ptr<AdaptiveMessageGenerator> g_messageGenerator;
static std::unique_ptr<LocalizedMessageManager> g_messageManager;

// =======================================================================
// C Export Functions Implementation
// =======================================================================

extern "C" {

bool InitLocalizedDeception() {
    try {
        LogInfo("InitLocalizedDeception: Инициализация локализованной системы обмана");
        
        g_messageGenerator = std::make_unique<AdaptiveMessageGenerator>();
        g_messageManager = std::make_unique<LocalizedMessageManager>();
        
        if (!g_messageGenerator->Initialize()) {
            LogError("InitLocalizedDeception: Ошибка инициализации генератора сообщений");
            return false;
        }
        
        if (!g_messageManager->Initialize()) {
            LogError("InitLocalizedDeception: Ошибка инициализации менеджера сообщений");
            return false;
        }
        
        LogInfo("InitLocalizedDeception: Инициализация завершена успешно");
        return true;
        
    } catch (const std::exception& e) {
        LogError(("InitLocalizedDeception: Исключение: " + std::string(e.what())).c_str());
        return false;
    }
}

void ShutdownLocalizedDeception() {
    LogInfo("ShutdownLocalizedDeception: Завершение работы локализованной системы");
    
    g_messageGenerator.reset();
    g_messageManager.reset();
    
    LogInfo("ShutdownLocalizedDeception: Завершение работы завершено");
}

bool AutoDetectSystemLanguage() {
    if (!g_messageManager) {
        LogError("AutoDetectSystemLanguage: Менеджер сообщений не инициализирован");
        return false;
    }
    
    g_messageManager->AutoDetectLanguage();
    return true;
}

int GetDetectedLanguageCode() {
    if (!g_messageManager) {
        return static_cast<int>(LanguageCode::ENGLISH);
    }
    
    return static_cast<int>(g_messageManager->GetCurrentLanguage());
}

void ShowLocalizedError() {
    if (!g_messageGenerator) {
        LogError("ShowLocalizedError: Генератор сообщений не инициализирован");
        return;
    }
    
    try {
        std::string message = g_messageGenerator->GenerateContextualErrorMessage();
        std::string title = g_messageManager->GetRandomWindowTitle();
        
        LogInfo("ShowLocalizedError: Показ локализованного сообщения об ошибке");
        
        // Показываем сообщение с задержкой
        Sleep(2000);
        MessageBoxA(nullptr, message.c_str(), title.c_str(), 
                   MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
        
    } catch (const std::exception& e) {
        LogError(("ShowLocalizedError: Ошибка показа сообщения: " + std::string(e.what())).c_str());
        
        // Fallback сообщение
        MessageBoxA(nullptr, "An error occurred. Please try again.", 
                   "Error", MB_OK | MB_ICONERROR);
    }
}

void ShowLocalizedSuccess() {
    if (!g_messageManager) {
        LogError("ShowLocalizedSuccess: Менеджер сообщений не инициализирован");
        return;
    }
    
    try {
        std::string message = g_messageManager->GetRandomSuccessMessage();
        std::string title = "Success";
        
        // Локализуем заголовок
        LanguageCode lang = g_messageManager->GetCurrentLanguage();
        switch (lang) {
            case LanguageCode::RUSSIAN:
                title = "Успешно";
                break;
            case LanguageCode::GERMAN:
                title = "Erfolgreich";
                break;
            case LanguageCode::FRENCH:
                title = "Succès";
                break;
            case LanguageCode::SPANISH:
                title = "Éxito";
                break;
            default:
                title = "Success";
                break;
        }
        
        LogInfo("ShowLocalizedSuccess: Показ локализованного сообщения об успехе");
        
        Sleep(1500);
        MessageBoxA(nullptr, message.c_str(), title.c_str(), 
                   MB_OK | MB_ICONINFORMATION);
        
    } catch (const std::exception& e) {
        LogError(("ShowLocalizedSuccess: Ошибка показа сообщения: " + std::string(e.what())).c_str());
        
        // Fallback сообщение
        MessageBoxA(nullptr, "Operation completed successfully.", 
                   "Success", MB_OK | MB_ICONINFORMATION);
    }
}

void ShowLocalizedWarning() {
    LogInfo("ShowLocalizedWarning: Показ локализованного предупреждения");
    MessageBoxA(nullptr, "Warning message.", "Warning", MB_OK | MB_ICONWARNING);
}

void ShowLocalizedInfo() {
    LogInfo("ShowLocalizedInfo: Показ локализованной информации");
    MessageBoxA(nullptr, "Information message.", "Information", MB_OK | MB_ICONINFORMATION);
}

const char* GetLocalizationStatus() {
    static std::string status;
    
    if (!g_messageManager) {
        status = "Not initialized";
        return status.c_str();
    }
    
    try {
        LanguageCode lang = g_messageManager->GetCurrentLanguage();
        status = "Active, Language: " + std::to_string(static_cast<int>(lang));
        return status.c_str();
        
    } catch (...) {
        status = "Error getting status";
        return status.c_str();
    }
}

bool IsLanguageSupported(int languageCode) {
    LanguageCode lang = static_cast<LanguageCode>(languageCode);
    
    // Список поддерживаемых языков
    return (lang == LanguageCode::ENGLISH ||
            lang == LanguageCode::RUSSIAN ||
            lang == LanguageCode::GERMAN ||
            lang == LanguageCode::FRENCH ||
            lang == LanguageCode::SPANISH ||
            lang == LanguageCode::ITALIAN ||
            lang == LanguageCode::PORTUGUESE ||
            lang == LanguageCode::CHINESE_SIMPLIFIED ||
            lang == LanguageCode::JAPANESE ||
            lang == LanguageCode::KOREAN);
}

int GetSupportedLanguageCount() {
    return 10; // Количество поддерживаемых языков
}

} // extern "C"

} // namespace LocalizedDeception