#include "dynamic_obfuscation.h"
#include "../logger/file_logger.h"
#include "../common.h"
#include <psapi.h>
#include <intrin.h>
#include <algorithm>
#include <iomanip>
#include <sstream>

#pragma comment(lib, "psapi.lib")

namespace DynamicObfuscation {

// Global instance
static std::unique_ptr<DynamicObfuscator> g_obfuscatorInstance;
static std::once_flag g_instanceFlag;

// External logging functions
extern "C" {
    void LogInfo(const char* message);
    void LogError(const char* message);
    void LogDebug(const char* message);
    void LogWarning(const char* message);
}

// ================================
// CodeBlock Implementation
// ================================

CodeBlock::CodeBlock(const std::vector<uint8_t>& codeData, DWORD rva) 
    : code(codeData), originalRVA(rva), currentRVA(rva), 
      size(static_cast<DWORD>(codeData.size())), isObfuscated(false), obfuscationLevel(0) {
    lastModified = std::chrono::system_clock::now();
}

CodeBlock::~CodeBlock() {
    // Cleanup if needed
}

bool CodeBlock::IsExpired(DWORD lifetimeMs) const {
    auto now = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastModified);
    return elapsed.count() > static_cast<long long>(lifetimeMs);
}

void CodeBlock::UpdateCode(const std::vector<uint8_t>& newCode) {
    code = newCode;
    size = static_cast<DWORD>(newCode.size());
    lastModified = std::chrono::system_clock::now();
    isObfuscated = true;
    obfuscationLevel++;
}

std::vector<uint8_t> CodeBlock::GetDecryptedCode() const {
    // Simple XOR decryption for demonstration
    std::vector<uint8_t> decrypted = code;
    uint8_t key = static_cast<uint8_t>(obfuscationLevel ^ 0xAA);
    
    for (auto& byte : decrypted) {
        byte ^= key;
    }
    
    return decrypted;
}

// ================================
// RuntimePatcher Implementation
// ================================

RuntimePatcher::RuntimePatcher() {
    LogDebug("RuntimePatcher initialized");
}

RuntimePatcher::~RuntimePatcher() {
    std::lock_guard<std::mutex> lock(patchMutex);
    
    // Restore all patched regions
    for (const auto& region : patchedRegions) {
        DWORD oldProtect;
        VirtualProtect(region.first, region.second, PAGE_EXECUTE_READ, &oldProtect);
    }
    
    LogDebug("RuntimePatcher destroyed");
}

bool RuntimePatcher::PatchCodeAtRuntime(LPVOID address, const std::vector<uint8_t>& newCode) {
    std::lock_guard<std::mutex> lock(patchMutex);
    
    if (!address || newCode.empty()) {
        LogError("RuntimePatcher: Invalid parameters");
        return false;
    }
    
    DWORD oldProtect;
    SIZE_T codeSize = newCode.size();
    
    // Make memory writable
    if (!ChangeMemoryProtection(address, codeSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        LogError("RuntimePatcher: Failed to change memory protection");
        return false;
    }
    
    // Apply patch
    __try {
        memcpy(address, newCode.data(), codeSize);
        FlushInstructionCache(GetCurrentProcess(), address, codeSize);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        LogError("RuntimePatcher: Exception during patching");
        ChangeMemoryProtection(address, codeSize, oldProtect, nullptr);
        return false;
    }
    
    // Restore original protection
    ChangeMemoryProtection(address, codeSize, oldProtect, nullptr);
    
    // Track patched region
    patchedRegions[address] = codeSize;
    
    LogDebug("RuntimePatcher: Successfully patched code");
    return true;
}

bool RuntimePatcher::RestoreOriginalCode(LPVOID address) {
    std::lock_guard<std::mutex> lock(patchMutex);
    
    auto it = patchedRegions.find(address);
    if (it != patchedRegions.end()) {
        patchedRegions.erase(it);
        LogDebug("RuntimePatcher: Restored original code");
        return true;
    }
    
    return false;
}

bool RuntimePatcher::MakeCodeExecutable(LPVOID address, SIZE_T size) {
    DWORD oldProtect;
    return ChangeMemoryProtection(address, size, PAGE_EXECUTE_READ, &oldProtect);
}

bool RuntimePatcher::ProtectCode(LPVOID address, SIZE_T size, DWORD protection) {
    DWORD oldProtect;
    return ChangeMemoryProtection(address, size, protection, &oldProtect);
}

bool RuntimePatcher::ChangeMemoryProtection(LPVOID address, SIZE_T size, DWORD newProtect, DWORD* oldProtect) {
    DWORD tempOldProtect;
    DWORD* protectPtr = oldProtect ? oldProtect : &tempOldProtect;
    
    if (!VirtualProtect(address, size, newProtect, protectPtr)) {
        DWORD error = GetLastError();
        std::stringstream ss;
        ss << "VirtualProtect failed with error: " << error;
        LogError(ss.str().c_str());
        return false;
    }
    
    return true;
}

// ================================
// PolymorphicEngine Implementation
// ================================

PolymorphicEngine::PolymorphicEngine() {
    // Initialize random number generator with high entropy
    std::random_device rd;
    rng.seed(rd() ^ static_cast<unsigned>(std::chrono::high_resolution_clock::now().time_since_epoch().count()));
    
    InitializeInstructionTemplates();
    InitializeNopVariants();
    
    LogDebug("PolymorphicEngine initialized");
}

void PolymorphicEngine::InitializeInstructionTemplates() {
    // Initialize common instruction equivalencies
    
    // NOP variants (0x90)
    instructionTemplates.push_back({0x90});                    // nop
    instructionTemplates.push_back({0x66, 0x90});              // nop (16-bit prefix)
    instructionTemplates.push_back({0x0F, 0x1F, 0x00});        // nop [eax]
    instructionTemplates.push_back({0x0F, 0x1F, 0x40, 0x00});  // nop [eax+00]
    instructionTemplates.push_back({0x0F, 0x1F, 0x44, 0x00, 0x00}); // nop [eax+eax+00]
    
    // MOV equivalents
    instructionTemplates.push_back({0x89, 0xC0});              // mov eax, eax
    instructionTemplates.push_back({0x8B, 0xC0});              // mov eax, eax (alternative)
    
    // Push/Pop pairs (effectively NOP)
    instructionTemplates.push_back({0x50, 0x58});              // push eax; pop eax
    instructionTemplates.push_back({0x51, 0x59});              // push ecx; pop ecx
    instructionTemplates.push_back({0x52, 0x5A});              // push edx; pop edx
}

void PolymorphicEngine::InitializeNopVariants() {
    // Various NOP instruction variants
    nopVariants.push_back({0x90});                             // Standard NOP
    nopVariants.push_back({0x66, 0x90});                       // 16-bit NOP
    nopVariants.push_back({0x0F, 0x1F, 0x00});                 // 3-byte NOP
    nopVariants.push_back({0x0F, 0x1F, 0x40, 0x00});           // 4-byte NOP
    nopVariants.push_back({0x0F, 0x1F, 0x44, 0x00, 0x00});     // 5-byte NOP
    nopVariants.push_back({0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00}); // 6-byte NOP
    nopVariants.push_back({0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00}); // 7-byte NOP
    nopVariants.push_back({0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00}); // 8-byte NOP
    nopVariants.push_back({0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00}); // 9-byte NOP
}

std::vector<uint8_t> PolymorphicEngine::GenerateEquivalentInstruction(const std::vector<uint8_t>& original) {
    if (original.empty()) return original;
    
    // For demonstration, we'll focus on NOP instruction transformation
    if (original.size() == 1 && original[0] == 0x90) {
        // Replace single NOP with equivalent
        std::uniform_int_distribution<size_t> dist(0, nopVariants.size() - 1);
        return nopVariants[dist(rng)];
    }
    
    // For other instructions, return original for now
    // In a full implementation, we'd have comprehensive instruction equivalencies
    return original;
}

std::vector<uint8_t> PolymorphicEngine::GenerateRandomNops(DWORD count) {
    std::vector<uint8_t> result;
    result.reserve(count);
    
    while (result.size() < count) {
        std::uniform_int_distribution<size_t> dist(0, nopVariants.size() - 1);
        const auto& nop = nopVariants[dist(rng)];
        
        if (result.size() + nop.size() <= count) {
            result.insert(result.end(), nop.begin(), nop.end());
        } else {
            // Fill remaining space with single-byte NOPs
            while (result.size() < count) {
                result.push_back(0x90);
            }
        }
    }
    
    return result;
}

std::vector<uint8_t> PolymorphicEngine::GenerateRandomJunk(DWORD minSize, DWORD maxSize) {
    std::uniform_int_distribution<DWORD> sizeDist(minSize, maxSize);
    DWORD junkSize = sizeDist(rng);
    
    std::vector<uint8_t> junk;
    junk.reserve(junkSize);
    
    // Generate random but valid instructions that don't affect program flow
    std::uniform_int_distribution<uint8_t> byteDist(0, 255);
    
    for (DWORD i = 0; i < junkSize; ++i) {
        // For simplicity, generate NOPs with random prefixes
        if (i % 3 == 0) {
            // Add a random NOP variant
            const auto& nop = nopVariants[byteDist(rng) % nopVariants.size()];
            junk.insert(junk.end(), nop.begin(), nop.end());
            i += static_cast<DWORD>(nop.size() - 1); // Adjust counter
        } else {
            junk.push_back(0x90); // Simple NOP
        }
    }
    
    return junk;
}

std::vector<uint8_t> PolymorphicEngine::GenerateOpaquePredicates() {
    std::vector<uint8_t> predicate;
    
    // Generate always-true predicate: (x * 2) % 2 == 0
    // mov eax, [esp+4]  ; Get parameter
    predicate.insert(predicate.end(), {0x8B, 0x44, 0x24, 0x04});
    
    // shl eax, 1        ; Multiply by 2
    predicate.insert(predicate.end(), {0xD1, 0xE0});
    
    // and eax, 1        ; Check if odd (always false for even numbers)
    predicate.insert(predicate.end(), {0x83, 0xE0, 0x01});
    
    // test eax, eax     ; Test if zero
    predicate.insert(predicate.end(), {0x85, 0xC0});
    
    // jz +5             ; Jump if zero (always taken)
    predicate.insert(predicate.end(), {0x74, 0x05});
    
    // Unreachable junk code
    auto junk = GenerateRandomJunk(3, 5);
    predicate.insert(predicate.end(), junk.begin(), junk.end());
    
    return predicate;
}

std::vector<uint8_t> PolymorphicEngine::SubstituteInstructions(const std::vector<uint8_t>& code) {
    std::vector<uint8_t> result;
    result.reserve(code.size() * 2); // Reserve extra space for expansion
    
    for (size_t i = 0; i < code.size(); ++i) {
        std::vector<uint8_t> instruction;
        instruction.push_back(code[i]);
        
        // Try to substitute with equivalent instruction
        auto equivalent = GenerateEquivalentInstruction(instruction);
        result.insert(result.end(), equivalent.begin(), equivalent.end());
        
        // Randomly insert NOPs
        std::uniform_int_distribution<int> shouldInsert(0, 10);
        if (shouldInsert(rng) < 2) { // 20% chance
            auto nops = GenerateRandomNops(1 + (rng() % 3));
            result.insert(result.end(), nops.begin(), nops.end());
        }
    }
    
    return result;
}

std::vector<uint8_t> PolymorphicEngine::InsertRandomBranches(const std::vector<uint8_t>& code) {
    std::vector<uint8_t> result = code;
    
    // Insert conditional jumps that always/never taken
    std::uniform_int_distribution<size_t> posDist(0, result.size() - 1);
    std::uniform_int_distribution<int> branchType(0, 1);
    
    size_t insertPos = posDist(rng);
    
    if (branchType(rng) == 0) {
        // Always taken branch
        std::vector<uint8_t> alwaysBranch = {
            0x83, 0xC0, 0x00,  // add eax, 0 (sets flags predictably)
            0x74, 0x02,        // jz +2 (always taken if eax was 0)
            0xEB, 0x00         // jmp +0 (fallthrough)
        };
        result.insert(result.begin() + insertPos, alwaysBranch.begin(), alwaysBranch.end());
    } else {
        // Never taken branch
        std::vector<uint8_t> neverBranch = {
            0x83, 0xF8, 0xFF,  // cmp eax, -1
            0x7F, 0x02,        // jg +2 (never taken for normal values)
            0xEB, 0x00         // jmp +0 (fallthrough)
        };
        result.insert(result.begin() + insertPos, neverBranch.begin(), neverBranch.end());
    }
    
    return result;
}

// ================================
// DynamicObfuscator Implementation - Core Methods
// ================================

DynamicObfuscator::DynamicObfuscator() 
    : obfuscationInterval(300000), // 5 minutes default
      techniqueMask(static_cast<DWORD>(ObfuscationTechnique::ALL_TECHNIQUES)),
      maxObfuscationLevel(5),
      isActive(false),
      regenerationCount(0),
      successfulTransformations(0),
      failedTransformations(0) {
    
    polymorphicEngine = std::make_unique<PolymorphicEngine>();
    runtimePatcher = std::make_unique<RuntimePatcher>();
    
    lastRegeneration = std::chrono::system_clock::now();
    
    LogInfo("DynamicObfuscator initialized");
}

DynamicObfuscator::~DynamicObfuscator() {
    Stop();
    LogInfo("DynamicObfuscator destroyed");
}

bool DynamicObfuscator::Initialize(DWORD intervalMs, DWORD techniques) {
    std::lock_guard<std::mutex> lock(obfuscatorMutex);
    
    if (isActive) {
        LogWarning("DynamicObfuscator already initialized");
        return true;
    }
    
    obfuscationInterval = intervalMs;
    techniqueMask = techniques;
    
    // Scan and register existing code
    if (!ScanAndRegisterCode()) {
        LogError("Failed to scan and register code");
        return false;
    }
    
    LogInfo("DynamicObfuscator initialization completed");
    return true;
}

bool DynamicObfuscator::Start() {
    std::lock_guard<std::mutex> lock(obfuscatorMutex);
    
    if (isActive) {
        LogWarning("DynamicObfuscator already active");
        return true;
    }
    
    isActive = true;
    
    // Start obfuscation worker thread
    try {
        obfuscationThread = std::thread(&DynamicObfuscator::ObfuscationWorkerThread, this);
        LogInfo("DynamicObfuscator started successfully");
        return true;
    }
    catch (const std::exception& e) {
        isActive = false;
        std::string error = "Failed to start obfuscation thread: ";
        error += e.what();
        LogError(error.c_str());
        return false;
    }
}

void DynamicObfuscator::Stop() {
    {
        std::lock_guard<std::mutex> lock(obfuscatorMutex);
        if (!isActive) return;
        isActive = false;
    }
    
    // Wait for worker thread to finish
    if (obfuscationThread.joinable()) {
        obfuscationThread.join();
    }
    
    // Cleanup
    EmergencyCleanup();
    
    LogInfo("DynamicObfuscator stopped");
}

bool DynamicObfuscator::IsActive() const {
    std::lock_guard<std::mutex> lock(obfuscatorMutex);
    return isActive;
}

// ================================
// Configuration Methods
// ================================

void DynamicObfuscator::SetObfuscationInterval(DWORD intervalMs) {
    std::lock_guard<std::mutex> lock(obfuscatorMutex);
    obfuscationInterval = intervalMs;
    LogDebug("Obfuscation interval updated");
}

void DynamicObfuscator::SetEnabledTechniques(DWORD techniqueMask) {
    std::lock_guard<std::mutex> lock(obfuscatorMutex);
    this->techniqueMask = techniqueMask;
    LogDebug("Enabled techniques updated");
}

void DynamicObfuscator::SetMaxObfuscationLevel(DWORD level) {
    std::lock_guard<std::mutex> lock(obfuscatorMutex);
    maxObfuscationLevel = std::min(level, 10u); // Cap at 10
    LogDebug("Max obfuscation level updated");
}

// ================================
// Manual Obfuscation Methods
// ================================

bool DynamicObfuscator::RegenerateCode() {
    std::lock_guard<std::mutex> lock(codeBlocksMutex);
    
    LogInfo("Starting manual code regeneration");
    
    bool allSuccess = true;
    for (auto& block : codeBlocks) {
        if (!TransformCodeBlock(*block)) {
            allSuccess = false;
        }
    }
    
    if (allSuccess) {
        regenerationCount++;
        lastRegeneration = std::chrono::system_clock::now();
        LogInfo("Manual code regeneration completed successfully");
    } else {
        LogWarning("Manual code regeneration completed with some failures");
    }
    
    return allSuccess;
}

bool DynamicObfuscator::ApplyControlFlowFlattening() {
    if (!(techniqueMask & static_cast<DWORD>(ObfuscationTechnique::CONTROL_FLOW_FLATTENING))) {
        LogWarning("Control flow flattening is disabled");
        return false;
    }
    
    LogInfo("Applying control flow flattening");
    
    std::lock_guard<std::mutex> lock(codeBlocksMutex);
    bool success = true;
    
    for (auto& block : codeBlocks) {
        auto result = ApplyControlFlowFlatteningInternal(block->code);
        if (result.success) {
            block->UpdateCode(result.transformedCode);
            successfulTransformations++;
        } else {
            failedTransformations++;
            success = false;
            LogError(("Control flow flattening failed: " + result.errorMessage).c_str());
        }
    }
    
    return success;
}

bool DynamicObfuscator::InsertDummyInstructions() {
    if (!(techniqueMask & static_cast<DWORD>(ObfuscationTechnique::DUMMY_INSTRUCTION_INSERTION))) {
        LogWarning("Dummy instruction insertion is disabled");
        return false;
    }
    
    LogInfo("Inserting dummy instructions");
    
    std::lock_guard<std::mutex> lock(codeBlocksMutex);
    bool success = true;
    
    for (auto& block : codeBlocks) {
        auto result = InsertDummyInstructionsInternal(block->code);
        if (result.success) {
            block->UpdateCode(result.transformedCode);
            successfulTransformations++;
        } else {
            failedTransformations++;
            success = false;
            LogError(("Dummy instruction insertion failed: " + result.errorMessage).c_str());
        }
    }
    
    return success;
}

bool DynamicObfuscator::ShuffleBasicBlocks() {
    if (!(techniqueMask & static_cast<DWORD>(ObfuscationTechnique::BASIC_BLOCK_SHUFFLING))) {
        LogWarning("Basic block shuffling is disabled");
        return false;
    }
    
    LogInfo("Shuffling basic blocks");
    
    std::lock_guard<std::mutex> lock(codeBlocksMutex);
    bool success = true;
    
    for (auto& block : codeBlocks) {
        auto result = ShuffleBasicBlocksInternal(block->code);
        if (result.success) {
            block->UpdateCode(result.transformedCode);
            successfulTransformations++;
        } else {
            failedTransformations++;
            success = false;
            LogError(("Basic block shuffling failed: " + result.errorMessage).c_str());
        }
    }
    
    return success;
}

// ================================
// Singleton and Utilities
// ================================

DynamicObfuscator& DynamicObfuscator::GetInstance() {
    std::call_once(g_instanceFlag, []() {
        g_obfuscatorInstance = std::make_unique<DynamicObfuscator>();
    });
    return *g_obfuscatorInstance;
}

// ================================
// Internal Implementation Stubs
// ================================

void DynamicObfuscator::ObfuscationWorkerThread() {
    LogInfo("Obfuscation worker thread started");
    
    while (isActive) {
        try {
            // Wait for next obfuscation cycle
            std::this_thread::sleep_for(std::chrono::milliseconds(obfuscationInterval));
            
            if (!isActive) break;
            
            // Perform obfuscation cycle
            RegenerateCode();
            CleanupExpiredBlocks();
            
        } catch (const std::exception& e) {
            std::string error = "Obfuscation worker thread error: ";
            error += e.what();
            LogError(error.c_str());
        }
    }
    
    LogInfo("Obfuscation worker thread ended");
}

bool DynamicObfuscator::ScanAndRegisterCode() {
    // This is a simplified implementation
    // In a real scenario, we would scan the process memory for executable code sections
    LogInfo("Code scanning and registration completed");
    return true;
}

bool DynamicObfuscator::TransformCodeBlock(CodeBlock& block) {
    // Apply enabled transformations
    bool transformed = false;
    
    if (techniqueMask & static_cast<DWORD>(ObfuscationTechnique::DUMMY_INSTRUCTION_INSERTION)) {
        auto result = InsertDummyInstructionsInternal(block.code);
        if (result.success) {
            block.UpdateCode(result.transformedCode);
            transformed = true;
        }
    }
    
    return transformed;
}

void DynamicObfuscator::CleanupExpiredBlocks() {
    std::lock_guard<std::mutex> lock(codeBlocksMutex);
    
    auto it = std::remove_if(codeBlocks.begin(), codeBlocks.end(),
        [this](const std::unique_ptr<CodeBlock>& block) {
            return block->IsExpired(obfuscationInterval * 10); // 10x interval lifetime
        });
    
    if (it != codeBlocks.end()) {
        codeBlocks.erase(it, codeBlocks.end());
        LogDebug("Cleaned up expired code blocks");
    }
}

// Simplified transformation implementations for demonstration
TransformationResult DynamicObfuscator::ApplyControlFlowFlatteningInternal(const std::vector<uint8_t>& code) {
    TransformationResult result;
    result.originalCode = code;
    result.transformedCode = code; // Simplified - just copy for now
    result.success = true;
    return result;
}

TransformationResult DynamicObfuscator::InsertDummyInstructionsInternal(const std::vector<uint8_t>& code) {
    TransformationResult result;
    result.originalCode = code;
    
    // Insert random NOPs throughout the code
    result.transformedCode = polymorphicEngine->SubstituteInstructions(code);
    result.success = true;
    
    return result;
}

TransformationResult DynamicObfuscator::ShuffleBasicBlocksInternal(const std::vector<uint8_t>& code) {
    TransformationResult result;
    result.originalCode = code;
    result.transformedCode = polymorphicEngine->InsertRandomBranches(code);
    result.success = true;
    return result;
}

TransformationResult DynamicObfuscator::ApplyInstructionSubstitution(const std::vector<uint8_t>& code) {
    TransformationResult result;
    result.originalCode = code;
    result.transformedCode = polymorphicEngine->SubstituteInstructions(code);
    result.success = true;
    return result;
}

TransformationResult DynamicObfuscator::InsertOpaquePredicates(const std::vector<uint8_t>& code) {
    TransformationResult result;
    result.originalCode = code;
    
    auto transformed = code;
    auto predicates = polymorphicEngine->GenerateOpaquePredicates();
    
    // Insert predicates at random positions
    if (!transformed.empty()) {
        size_t insertPos = transformed.size() / 2;
        transformed.insert(transformed.begin() + insertPos, predicates.begin(), predicates.end());
    }
    
    result.transformedCode = transformed;
    result.success = true;
    return result;
}

// Additional method implementations
void DynamicObfuscator::EmergencyObfuscation() {
    LogWarning("Emergency obfuscation triggered");
    RegenerateCode();
}

void DynamicObfuscator::EmergencyCleanup() {
    std::lock_guard<std::mutex> lock(codeBlocksMutex);
    codeBlocks.clear();
    protectedRegions.clear();
    LogInfo("Emergency cleanup completed");
}

DynamicObfuscator::ObfuscationStats DynamicObfuscator::GetStatistics() const {
    std::lock_guard<std::mutex> lock(codeBlocksMutex);
    
    ObfuscationStats stats;
    stats.totalRegenerations = regenerationCount;
    stats.successfulTransformations = successfulTransformations;
    stats.failedTransformations = failedTransformations;
    stats.activeCodeBlocks = static_cast<DWORD>(codeBlocks.size());
    stats.averageTransformationTime = 0; // Would need timing measurements
    stats.lastActivity = lastRegeneration;
    
    return stats;
}

void DynamicObfuscator::ResetStatistics() {
    regenerationCount = 0;
    successfulTransformations = 0;
    failedTransformations = 0;
    LogDebug("Statistics reset");
}

// Utility functions implementation
namespace Utils {

bool IsValidInstruction(const std::vector<uint8_t>& bytes) {
    // Simplified validation
    return !bytes.empty() && bytes.size() <= 15; // Max x86 instruction length
}

DWORD GetInstructionLength(const uint8_t* instruction) {
    // Simplified implementation - would need full x86 decoder
    if (!instruction) return 0;
    
    // Handle common single-byte instructions
    switch (*instruction) {
        case 0x90: return 1; // NOP
        case 0x50: case 0x51: case 0x52: case 0x53: // PUSH reg
        case 0x54: case 0x55: case 0x56: case 0x57:
        case 0x58: case 0x59: case 0x5A: case 0x5B: // POP reg
        case 0x5C: case 0x5D: case 0x5E: case 0x5F:
            return 1;
        default:
            return 1; // Default to 1 for simplicity
    }
}

bool IsJumpInstruction(const uint8_t* instruction) {
    if (!instruction) return false;
    
    return (*instruction >= 0x70 && *instruction <= 0x7F) ||  // Short conditional jumps
           (*instruction == 0xEB) ||                          // Short unconditional jump
           (*instruction == 0xE9) ||                          // Near unconditional jump
           (*instruction == 0x0F && instruction[1] >= 0x80 && instruction[1] <= 0x8F); // Long conditional jumps
}

bool IsCallInstruction(const uint8_t* instruction) {
    if (!instruction) return false;
    return *instruction == 0xE8 || *instruction == 0xFF; // CALL near/far
}

std::vector<uint8_t> GenerateRandomBytes(DWORD count) {
    std::vector<uint8_t> bytes(count);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dist(0, 255);
    
    for (auto& byte : bytes) {
        byte = dist(gen);
    }
    
    return bytes;
}

std::vector<uint8_t> XorObfuscate(const std::vector<uint8_t>& data, uint8_t key) {
    std::vector<uint8_t> result = data;
    for (auto& byte : result) {
        byte ^= key;
    }
    return result;
}

std::vector<uint8_t> RotateObfuscate(const std::vector<uint8_t>& data, uint8_t rotations) {
    std::vector<uint8_t> result = data;
    uint8_t rot = rotations & 7; // Limit to 0-7
    
    for (auto& byte : result) {
        byte = (byte << rot) | (byte >> (8 - rot));
    }
    
    return result;
}

bool IsExecutableMemory(LPVOID address) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    }
    return false;
}

bool IsWritableMemory(LPVOID address) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        return (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0;
    }
    return false;
}

LPVOID AllocateExecutableMemory(SIZE_T size) {
    return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

void FreeExecutableMemory(LPVOID address, SIZE_T size) {
    if (address) {
        VirtualFree(address, 0, MEM_RELEASE);
    }
}

bool IsDebuggerPresent() {
    return ::IsDebuggerPresent() || CheckRemoteDebuggerPresent(GetCurrentProcess(), NULL);
}

bool IsBeingDebugged() {
    // Multiple debugger detection methods
    if (::IsDebuggerPresent()) return true;
    
    // Check PEB flag
    PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60)); // x64
    if (peb && peb->BeingDebugged) return true;
    
    // Check remote debugger
    BOOL remoteDebugger = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger);
    if (remoteDebugger) return true;
    
    return false;
}

bool IsBreakpointPresent(LPVOID address, SIZE_T size) {
    if (!address || !size) return false;
    
    __try {
        const uint8_t* bytes = static_cast<const uint8_t*>(address);
        for (SIZE_T i = 0; i < size; ++i) {
            if (bytes[i] == 0xCC || bytes[i] == 0xCD) { // INT3 or INT n
                return true;
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return true; // Access violation might indicate debugging
    }
    
    return false;
}

} // namespace Utils

} // namespace DynamicObfuscation