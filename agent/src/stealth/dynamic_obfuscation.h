#pragma once

#include <windows.h>
#include <vector>
#include <memory>
#include <map>
#include <functional>
#include <random>
#include <chrono>
#include <thread>
#include <mutex>

namespace DynamicObfuscation {

// Forward declarations
class CodeBlock;
class PolymorphicEngine;
class RuntimePatcher;

// Obfuscation techniques enumeration
enum class ObfuscationTechnique {
    CONTROL_FLOW_FLATTENING = 0x01,
    DUMMY_INSTRUCTION_INSERTION = 0x02,
    BASIC_BLOCK_SHUFFLING = 0x04,
    INSTRUCTION_SUBSTITUTION = 0x08,
    REGISTER_RENAMING = 0x10,
    DEAD_CODE_INSERTION = 0x20,
    OPAQUE_PREDICATES = 0x40,
    VIRTUALIZATION = 0x80,
    ALL_TECHNIQUES = 0xFF
};

// Code transformation result
struct TransformationResult {
    std::vector<uint8_t> originalCode;
    std::vector<uint8_t> transformedCode;
    std::map<DWORD, DWORD> addressMapping;  // Original RVA -> New RVA
    bool success;
    std::string errorMessage;
    
    TransformationResult() : success(false) {}
};

// Function signature for obfuscated functions
typedef void(*ObfuscatedFunction)();

// Code block representation
class CodeBlock {
public:
    std::vector<uint8_t> code;
    DWORD originalRVA;
    DWORD currentRVA;
    DWORD size;
    bool isObfuscated;
    DWORD obfuscationLevel;
    std::chrono::system_clock::time_point lastModified;
    
    CodeBlock(const std::vector<uint8_t>& codeData, DWORD rva);
    ~CodeBlock();
    
    bool IsExpired(DWORD lifetimeMs) const;
    void UpdateCode(const std::vector<uint8_t>& newCode);
    std::vector<uint8_t> GetDecryptedCode() const;
};

// Runtime code patcher for self-modifying code
class RuntimePatcher {
private:
    std::map<LPVOID, SIZE_T> patchedRegions;
    std::mutex patchMutex;
    
public:
    RuntimePatcher();
    ~RuntimePatcher();
    
    bool PatchCodeAtRuntime(LPVOID address, const std::vector<uint8_t>& newCode);
    bool RestoreOriginalCode(LPVOID address);
    bool MakeCodeExecutable(LPVOID address, SIZE_T size);
    bool ProtectCode(LPVOID address, SIZE_T size, DWORD protection);
    
    // VirtualProtect wrapper with error handling
    bool ChangeMemoryProtection(LPVOID address, SIZE_T size, DWORD newProtect, DWORD* oldProtect);
};

// Polymorphic code generation engine
class PolymorphicEngine {
private:
    std::mt19937 rng;
    std::vector<std::vector<uint8_t>> instructionTemplates;
    std::vector<std::vector<uint8_t>> nopVariants;
    
    void InitializeInstructionTemplates();
    void InitializeNopVariants();
    
public:
    PolymorphicEngine();
    
    // Generate equivalent instruction sequences
    std::vector<uint8_t> GenerateEquivalentInstruction(const std::vector<uint8_t>& original);
    std::vector<uint8_t> GenerateRandomNops(DWORD count);
    std::vector<uint8_t> GenerateRandomJunk(DWORD minSize, DWORD maxSize);
    std::vector<uint8_t> GenerateOpaquePredicates();
    
    // Advanced polymorphic transformations
    std::vector<uint8_t> SubstituteInstructions(const std::vector<uint8_t>& code);
    std::vector<uint8_t> InsertRandomBranches(const std::vector<uint8_t>& code);
};

// Main dynamic obfuscation class
class DynamicObfuscator {
private:
    // Core components
    std::unique_ptr<PolymorphicEngine> polymorphicEngine;
    std::unique_ptr<RuntimePatcher> runtimePatcher;
    
    // Configuration
    DWORD obfuscationInterval;     // Milliseconds between obfuscation cycles
    DWORD techniqueMask;           // Bitmask of enabled techniques
    DWORD maxObfuscationLevel;     // Maximum complexity level (1-10)
    
    // State management
    bool isActive;
    std::thread obfuscationThread;
    std::mutex obfuscatorMutex;
    mutable std::mutex codeBlocksMutex;
    
    // Code management
    std::vector<std::unique_ptr<CodeBlock>> codeBlocks;
    std::map<std::string, ObfuscatedFunction> obfuscatedFunctions;
    std::vector<LPVOID> protectedRegions;
    
    // Statistics and monitoring
    DWORD regenerationCount;
    DWORD successfulTransformations;
    DWORD failedTransformations;
    std::chrono::system_clock::time_point lastRegeneration;
    
    // Internal methods
    void ObfuscationWorkerThread();
    bool ScanAndRegisterCode();
    bool TransformCodeBlock(CodeBlock& block);
    void CleanupExpiredBlocks();
    
    // Technique implementations
    TransformationResult ApplyControlFlowFlatteningInternal(const std::vector<uint8_t>& code);
    TransformationResult InsertDummyInstructionsInternal(const std::vector<uint8_t>& code);
    TransformationResult ShuffleBasicBlocksInternal(const std::vector<uint8_t>& code);
    TransformationResult ApplyInstructionSubstitution(const std::vector<uint8_t>& code);
    TransformationResult InsertOpaquePredicates(const std::vector<uint8_t>& code);
    
public:
    DynamicObfuscator();
    ~DynamicObfuscator();
    
    // Core functionality
    bool Initialize(DWORD intervalMs = 300000, DWORD techniques = static_cast<DWORD>(ObfuscationTechnique::ALL_TECHNIQUES));
    bool Start();
    void Stop();
    bool IsActive() const;
    
    // Configuration
    void SetObfuscationInterval(DWORD intervalMs);
    void SetEnabledTechniques(DWORD techniqueMask);
    void SetMaxObfuscationLevel(DWORD level);
    
    // Manual obfuscation triggers
    bool RegenerateCode();
    bool ApplyControlFlowFlattening();
    bool InsertDummyInstructions();
    bool ShuffleBasicBlocks();
    
    // Function-specific obfuscation
    bool ObfuscateFunction(const std::string& functionName, LPVOID functionAddress, SIZE_T functionSize);
    bool DeobfuscateFunction(const std::string& functionName);
    ObfuscatedFunction GetObfuscatedFunction(const std::string& functionName);
    
    // Advanced techniques
    bool ApplyVirtualization();
    bool CreateDecoyFunctions();
    bool ApplyAntiDisassembly();
    bool InsertAntiDebugChecks();
    
    // Code registration and management
    bool RegisterCodeRegion(LPVOID address, SIZE_T size, const std::string& name = "");
    bool UnregisterCodeRegion(LPVOID address);
    void ClearAllRegistrations();
    
    // Statistics and monitoring
    struct ObfuscationStats {
        DWORD totalRegenerations;
        DWORD successfulTransformations;
        DWORD failedTransformations;
        DWORD activeCodeBlocks;
        DWORD averageTransformationTime;
        std::chrono::system_clock::time_point lastActivity;
    };
    
    ObfuscationStats GetStatistics() const;
    void ResetStatistics();
    
    // Emergency functionality
    void EmergencyObfuscation();    // Immediate full obfuscation
    void EmergencyCleanup();        // Remove all obfuscation
    
    // Signature evasion
    bool EvadeStaticSignatures();
    bool EvadeBehavioralSignatures();
    bool RandomizeCodeLayout();
    
    // Integration helpers
    static DynamicObfuscator& GetInstance();
    bool IntegrateWithStealth();    // Integration with existing stealth system
};

// Global utility functions
namespace Utils {
    // Assembly analysis utilities
    bool IsValidInstruction(const std::vector<uint8_t>& bytes);
    DWORD GetInstructionLength(const uint8_t* instruction);
    bool IsJumpInstruction(const uint8_t* instruction);
    bool IsCallInstruction(const uint8_t* instruction);
    
    // Code generation utilities
    std::vector<uint8_t> GenerateRandomBytes(DWORD count);
    std::vector<uint8_t> XorObfuscate(const std::vector<uint8_t>& data, uint8_t key);
    std::vector<uint8_t> RotateObfuscate(const std::vector<uint8_t>& data, uint8_t rotations);
    
    // Memory utilities
    bool IsExecutableMemory(LPVOID address);
    bool IsWritableMemory(LPVOID address);
    LPVOID AllocateExecutableMemory(SIZE_T size);
    void FreeExecutableMemory(LPVOID address, SIZE_T size);
    
    // Debug detection
    bool IsDebuggerPresent();
    bool IsBeingDebugged();
    bool IsBreakpointPresent(LPVOID address, SIZE_T size);
}

// Macros for easy integration
#define DYNAMIC_OBFUSCATION_INIT() \
    DynamicObfuscation::DynamicObfuscator::GetInstance().Initialize()

#define DYNAMIC_OBFUSCATION_START() \
    DynamicObfuscation::DynamicObfuscator::GetInstance().Start()

#define DYNAMIC_OBFUSCATION_STOP() \
    DynamicObfuscation::DynamicObfuscator::GetInstance().Stop()

#define REGISTER_FUNCTION_FOR_OBFUSCATION(name, func, size) \
    DynamicObfuscation::DynamicObfuscator::GetInstance().ObfuscateFunction(name, (LPVOID)func, size)

#define EMERGENCY_OBFUSCATION() \
    DynamicObfuscation::DynamicObfuscator::GetInstance().EmergencyObfuscation()

// Error codes
#define OBFUSCATION_SUCCESS                 0x00000000
#define OBFUSCATION_ERROR_INVALID_CODE      0x80001001
#define OBFUSCATION_ERROR_MEMORY_PROTECTION 0x80001002
#define OBFUSCATION_ERROR_INSUFFICIENT_SIZE 0x80001003
#define OBFUSCATION_ERROR_DEBUGGER_DETECTED 0x80001004
#define OBFUSCATION_ERROR_ALREADY_ACTIVE    0x80001005

} // namespace DynamicObfuscation