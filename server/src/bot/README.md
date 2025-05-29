Вот что делают файлы в данной папке:

  bot.py (412 строк) - основной Python Telegram бот:
  - Полнофункциональный асинхронный Telegram бот с командами /start, /status, /agents,
  /logs, /stats
  - Обрабатывает зашифрованные логи от агентов через документы
  - Интеграция с базой данных для хранения агентов и логов
  - Авторизация пользователей, статистика, управление файлами
  - Расшифровка пакетов данных от агентов

  bot.cpp (301 строка) - C++ интерфейс для Telegram:
  - TelegramBot класс с потоковой обработкой сообщений
  - Rate limiting (30 сообщений/минуту)
  - Уведомления о логах, статусе агентов, алертах
  - extern "C" функции для интеграции с agent кодом
  - Глобальный bot instance для вызовов из main.cpp

  telegram_utils.cpp/h (418/261 строка) - низкоуровневые HTTP утилиты:
  - Кроссплатформенный HTTP клиент (WinINet/libcurl)
  - Telegram API методы: sendMessage, getUpdates, setWebhook
  - URL encoding, markdown форматирование
  - Rate limiting, error handling
  - C++ класс + C интерфейс

⏺ Update Todos
  ⎿  ☒ Analyze bot.py functionality and purpose
     ☒ Review bot.cpp role in the project
     ☒ Examine telegram_utils.cpp and telegram_utils.h
     ☒ Determine Python-C++ integration patterns
     ☐ Check for any compilation or integration issues

⏺ Схема интеграции:
  - bot.py работает автономно как сервер
  - bot.cpp интегрируется в agent.dll через telegram_bot_init()
  - Агент отправляет уведомления через C функции
  - Python бот получает зашифрованные файлы и обрабатывает их