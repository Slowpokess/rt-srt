#include <windows.h>
#include <winternl.h>
#include <string>
#include <vector>
#include "../common.h"

// PE Headers structures
#pragma pack(push, 1)
typedef struct _IMAGE_BASE_RELOCATION {
    DWORD VirtualAddress;
    DWORD SizeOfBlock;
} IMAGE_BASE_RELOCATION, *PIMAGE_BASE_RELOCATION;

typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD Hint;
    CHAR Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
#pragma pack(pop)

class InMemoryLoader {
private:
    std::vector<uint8_t> peData;
    void* allocatedMemory;
    SIZE_T imageSize;
    
public:
    InMemoryLoader() : allocatedMemory(nullptr), imageSize(0) {}
    
    ~InMemoryLoader() {
        if (allocatedMemory) {
            VirtualFree(allocatedMemory, 0, MEM_RELEASE);
        }
    }
    
    bool LoadPEFromMemory(const std::vector<uint8_t>& data) {
        peData = data;
        
        if (peData.size() < sizeof(IMAGE_DOS_HEADER)) {
            return false;
        }
        
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peData.data();
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return false;
        }
        
        if (peData.size() < dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)) {
            return false;
        }
        
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(peData.data() + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return false;
        }
        
        imageSize = ntHeaders->OptionalHeader.SizeOfImage;
        
        // Allocate memory for the image
        allocatedMemory = VirtualAlloc(
            (LPVOID)ntHeaders->OptionalHeader.ImageBase,
            imageSize,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE
        );
        
        if (!allocatedMemory) {
            // Try allocating at any address
            allocatedMemory = VirtualAlloc(
                nullptr,
                imageSize,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_EXECUTE_READWRITE
            );
            
            if (!allocatedMemory) {
                return false;
            }
        }
        
        // Copy headers
        memcpy(allocatedMemory, peData.data(), ntHeaders->OptionalHeader.SizeOfHeaders);
        
        // Copy sections
        PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (sectionHeader[i].SizeOfRawData > 0) {
                void* sectionDest = (uint8_t*)allocatedMemory + sectionHeader[i].VirtualAddress;
                void* sectionSrc = peData.data() + sectionHeader[i].PointerToRawData;
                
                memcpy(sectionDest, sectionSrc, sectionHeader[i].SizeOfRawData);
            }
        }
        
        // Update base address if needed
        DWORD_PTR deltaBase = (DWORD_PTR)allocatedMemory - ntHeaders->OptionalHeader.ImageBase;
        if (deltaBase != 0) {
            if (!ProcessRelocations(deltaBase)) {
                return false;
            }
        }
        
        // Resolve imports
        if (!ResolveImports()) {
            return false;
        }
        
        // Set proper memory protections
        SetMemoryProtections();
        
        return true;
    }
    
    void* GetEntryPoint() {
        if (!allocatedMemory || peData.empty()) {
            return nullptr;
        }
        
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peData.data();
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(peData.data() + dosHeader->e_lfanew);
        
        return (uint8_t*)allocatedMemory + ntHeaders->OptionalHeader.AddressOfEntryPoint;
    }
    
    void* GetExportAddress(const char* functionName) {
        if (!allocatedMemory) return nullptr;
        
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)allocatedMemory;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((uint8_t*)allocatedMemory + dosHeader->e_lfanew);
        
        if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) {
            return nullptr;
        }
        
        PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)
            ((uint8_t*)allocatedMemory + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        
        DWORD* names = (DWORD*)((uint8_t*)allocatedMemory + exportDir->AddressOfNames);
        DWORD* functions = (DWORD*)((uint8_t*)allocatedMemory + exportDir->AddressOfFunctions);
        WORD* ordinals = (WORD*)((uint8_t*)allocatedMemory + exportDir->AddressOfNameOrdinals);
        
        for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
            char* name = (char*)((uint8_t*)allocatedMemory + names[i]);
            if (strcmp(name, functionName) == 0) {
                return (uint8_t*)allocatedMemory + functions[ordinals[i]];
            }
        }
        
        return nullptr;
    }
    
private:
    bool ProcessRelocations(DWORD_PTR deltaBase) {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)allocatedMemory;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((uint8_t*)allocatedMemory + dosHeader->e_lfanew);
        
        if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress == 0) {
            return true; // No relocations needed
        }
        
        DWORD relocSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)
            ((uint8_t*)allocatedMemory + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        
        while (relocation->VirtualAddress > 0 && relocation->SizeOfBlock > 0) {
            DWORD numEntries = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* relocData = (WORD*)((uint8_t*)relocation + sizeof(IMAGE_BASE_RELOCATION));
            
            for (DWORD i = 0; i < numEntries; i++) {
                if ((relocData[i] >> 12) == IMAGE_REL_BASED_HIGHLOW || (relocData[i] >> 12) == IMAGE_REL_BASED_DIR64) {
                    DWORD_PTR* patchAddr = (DWORD_PTR*)((uint8_t*)allocatedMemory + relocation->VirtualAddress + (relocData[i] & 0xFFF));
                    *patchAddr += deltaBase;
                }
            }
            
            relocation = (PIMAGE_BASE_RELOCATION)((uint8_t*)relocation + relocation->SizeOfBlock);
        }
        
        return true;
    }
    
    bool ResolveImports() {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)allocatedMemory;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((uint8_t*)allocatedMemory + dosHeader->e_lfanew);
        
        if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0) {
            return true; // No imports
        }
        
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)
            ((uint8_t*)allocatedMemory + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        
        while (importDesc->Name != 0) {
            char* dllName = (char*)((uint8_t*)allocatedMemory + importDesc->Name);
            HMODULE hLib = LoadLibraryA(dllName);
            
            if (!hLib) {
                return false;
            }
            
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((uint8_t*)allocatedMemory + importDesc->FirstThunk);
            PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)((uint8_t*)allocatedMemory + 
                (importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk));
            
            while (origThunk->u1.Function != 0) {
                void* funcAddr = nullptr;
                
                if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    // Import by ordinal
                    funcAddr = GetProcAddress(hLib, (LPCSTR)(origThunk->u1.Ordinal & 0xFFFF));
                } else {
                    // Import by name
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)
                        ((uint8_t*)allocatedMemory + origThunk->u1.AddressOfData);
                    funcAddr = GetProcAddress(hLib, importByName->Name);
                }
                
                if (!funcAddr) {
                    return false;
                }
                
                thunk->u1.Function = (DWORD_PTR)funcAddr;
                
                thunk++;
                origThunk++;
            }
            
            importDesc++;
        }
        
        return true;
    }
    
    void SetMemoryProtections() {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)allocatedMemory;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((uint8_t*)allocatedMemory + dosHeader->e_lfanew);
        
        PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            DWORD protection = PAGE_NOACCESS;
            
            if (sectionHeader[i].Characteristics & IMAGE_SCN_MEM_READ) {
                if (sectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
                    if (sectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                        protection = PAGE_EXECUTE_READWRITE;
                    } else {
                        protection = PAGE_READWRITE;
                    }
                } else {
                    if (sectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                        protection = PAGE_EXECUTE_READ;
                    } else {
                        protection = PAGE_READONLY;
                    }
                }
            }
            
            if (protection != PAGE_NOACCESS) {
                DWORD oldProtect;
                VirtualProtect(
                    (uint8_t*)allocatedMemory + sectionHeader[i].VirtualAddress,
                    sectionHeader[i].Misc.VirtualSize,
                    protection,
                    &oldProtect
                );
            }
        }
    }
};

// Global loader instance
static std::unique_ptr<InMemoryLoader> g_loader;

// Export functions
extern "C" {
    bool LoadPEFromMemory(const void* data, size_t size) {
        try {
            g_loader = std::make_unique<InMemoryLoader>();
            
            std::vector<uint8_t> peData((uint8_t*)data, (uint8_t*)data + size);
            bool success = g_loader->LoadPEFromMemory(peData);
            
            if (!success) {
                g_loader.reset();
                return false;
            }
            
            extern void LogInfo(const char*);
            LogInfo("PE loaded successfully in memory");
            
            return true;
        } catch (...) {
            extern void LogError(const char*);
            LogError("Failed to load PE in memory");
            
            g_loader.reset();
            return false;
        }
    }
    
    void* GetLoadedPEEntryPoint() {
        if (!g_loader) return nullptr;
        return g_loader->GetEntryPoint();
    }
    
    void* GetLoadedPEExport(const char* functionName) {
        if (!g_loader) return nullptr;
        return g_loader->GetExportAddress(functionName);
    }
    
    void UnloadPE() {
        if (g_loader) {
            extern void LogInfo(const char*);
            LogInfo("Unloading PE from memory");
            
            g_loader.reset();
        }
    }
    
    bool ExecuteLoadedPE() {
        if (!g_loader) return false;
        
        void* entryPoint = g_loader->GetEntryPoint();
        if (!entryPoint) return false;
        
        try {
            extern void LogInfo(const char*);
            LogInfo("Executing loaded PE");
            
            // Execute as DLL entry point
            typedef BOOL (WINAPI *DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
            DllEntryProc dllEntry = (DllEntryProc)entryPoint;
            
            BOOL result = dllEntry((HINSTANCE)g_loader.get(), DLL_PROCESS_ATTACH, nullptr);
            
            return result == TRUE;
        } catch (...) {
            extern void LogError(const char*);
            LogError("Exception during PE execution");
            return false;
        }
    }
}