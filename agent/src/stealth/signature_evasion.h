#pragma once

#include "dynamic_obfuscation.h"
#include <vector>
#include <string>
#include <map>

namespace SignatureEvasion {

// Signature detection and evasion
class SignatureEvader {
private:
    struct Signature {
        std::vector<uint8_t> pattern;
        std::vector<uint8_t> mask;  // 0xFF = must match, 0x00 = wildcard
        std::string name;
        DWORD severity;             // 1-10, higher = more critical
    };
    
    std::vector<Signature> knownSignatures;
    DynamicObfuscation::DynamicObfuscator* obfuscator;
    
    void LoadKnownSignatures();
    bool MatchesSignature(const std::vector<uint8_t>& code, const Signature& sig) const;
    
public:
    SignatureEvader();
    ~SignatureEvader();
    
    // Detection
    std::vector<std::string> ScanForSignatures(const std::vector<uint8_t>& code);
    bool HasCriticalSignatures(const std::vector<uint8_t>& code);
    
    // Evasion
    std::vector<uint8_t> EvadeSignatures(const std::vector<uint8_t>& code);
    bool BreakSignature(std::vector<uint8_t>& code, const std::string& signatureName);
    
    // Continuous monitoring
    void StartSignatureMonitoring();
    void StopSignatureMonitoring();
};

// Anti-AV specific evasions
class AntiAVEvasion {
public:
    // Behavioral evasion
    static void SimulateNormalActivity();
    static void DelayExecution(DWORD minMs, DWORD maxMs);
    static void FragmentOperations();
    
    // Memory evasion
    static bool AllocateDecoyMemory();
    static void ScrambleMemoryLayout();
    static bool UseAlternateAPIs();
    
    // File system evasion
    static bool CreateDecoyFiles();
    static void TouchLegitimateFiles();
    static bool UseFilelessExecution();
};

} // namespace SignatureEvasion