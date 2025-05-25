#ifndef OBFUSCATION_H
#define OBFUSCATION_H

#include <string>
#include <vector>
#include <chrono>
#include <random>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace Utils {
    std::string EncodeHex(const std::vector<uint8_t>& data);
    std::vector<uint8_t> DecodeHexData(const std::string& hex);
    std::string EncodeBase64(const std::vector<uint8_t>& data);
    std::vector<uint8_t> DecodeBase64(const std::string& base64);
    uint64_t GetCurrentTimestamp();
    std::string GenerateRandomString(size_t length);
    uint32_t GetRandomSeed();
}

class StringObfuscator {
private:
    std::mt19937 rng;
    std::vector<uint8_t> key;
    
public:
    StringObfuscator();
    explicit StringObfuscator(const std::vector<uint8_t>& custom_key);
    
    std::string ObfuscateXOR(const std::string& input);
    std::string DeobfuscateXOR(const std::string& obfuscated);
    
    std::string ObfuscateRC4(const std::string& input);
    std::string DeobfuscateRC4(const std::string& obfuscated);
    
    std::vector<std::string> SplitString(const std::string& input, size_t max_chunk_size = 8);
    std::string JoinString(const std::vector<std::string>& chunks);
    
    std::string ObfuscateMultiLevel(const std::string& input);
    std::string DeobfuscateMultiLevel(const std::string& obfuscated);
    
    void RotateKey();
    void SetKey(const std::vector<uint8_t>& new_key);
};

class NameObfuscator {
private:
    std::mt19937 rng;
    std::vector<std::string> name_pool;
    std::vector<std::string> used_names;
    
    void InitializeNamePool();
    
public:
    NameObfuscator();
    
    std::string GenerateProcessName();
    std::string GenerateDesktopName();
    std::string GenerateServiceName();
    std::string GenerateFileName();
    
    void MarkNameAsUsed(const std::string& name);
    void ClearUsedNames();
    void RefreshNamePool();
    
    std::string ObfuscateName(const std::string& original);
    bool IsNameSafe(const std::string& name);
};

class FileObfuscator {
private:
    std::string temp_directory;
    std::vector<std::string> created_files;
    StringObfuscator string_obfuscator;
    
public:
    FileObfuscator();
    explicit FileObfuscator(const std::string& temp_dir);
    
    std::string CreateObfuscatedFile(const std::vector<uint8_t>& data, const std::string& extension = ".tmp");
    bool ReadObfuscatedFile(const std::string& file_path, std::vector<uint8_t>& data);
    
    void CleanupFiles();
    void SetTempDirectory(const std::string& temp_dir);
    
    std::string ObfuscateFilePath(const std::string& original_path);
    bool CreateDecoyFiles(size_t count = 5);
};

class CommandObfuscator {
private:
    StringObfuscator string_obfuscator;
    NameObfuscator name_obfuscator;
    
public:
    CommandObfuscator();
    
    std::string ObfuscateCommand(const std::string& command);
    std::string DeobfuscateCommand(const std::string& obfuscated_command);
    
    std::string ObfuscateArguments(const std::vector<std::string>& args);
    std::vector<std::string> DeobfuscateArguments(const std::string& obfuscated_args);
    
    std::string CreateStealthScript(const std::string& original_script);
    bool ExecuteObfuscatedCommand(const std::string& command, const std::vector<std::string>& args);
};

// Main obfuscation manager class
class ObfuscationManager {
private:
    StringObfuscator string_obf;
    NameObfuscator name_obf;
    FileObfuscator file_obf;
    CommandObfuscator cmd_obf;
    
    bool enabled;
    uint32_t obfuscation_level; // 1-5, higher = more obfuscation
    
public:
    ObfuscationManager();
    
    void SetObfuscationLevel(uint32_t level);
    void Enable(bool enable = true);
    void Disable();
    bool IsEnabled() const;
    
    // String operations
    std::string ObfuscateString(const std::string& input);
    std::string DeobfuscateString(const std::string& obfuscated);
    
    // Name operations
    std::string GenerateObfuscatedName(const std::string& type);
    std::string ObfuscateName(const std::string& original);
    
    // File operations
    std::string CreateObfuscatedTempFile(const std::vector<uint8_t>& data);
    bool ReadObfuscatedTempFile(const std::string& file_path, std::vector<uint8_t>& data);
    
    // Command operations
    std::string PrepareObfuscatedCommand(const std::string& command, const std::vector<std::string>& args);
    bool ExecuteObfuscatedCommand(const std::string& command, const std::vector<std::string>& args);
    
    // Cleanup
    void Cleanup();
    void RotateKeys();
};

// Global instance
extern ObfuscationManager g_obfuscation_manager;

// Convenience macros
#define OBFUSCATE_STR(str) (g_obfuscation_manager.IsEnabled() ? g_obfuscation_manager.ObfuscateString(str) : str)
#define DEOBFUSCATE_STR(str) (g_obfuscation_manager.IsEnabled() ? g_obfuscation_manager.DeobfuscateString(str) : str)
#define GENERATE_NAME(type) g_obfuscation_manager.GenerateObfuscatedName(type)

#endif // OBFUSCATION_H