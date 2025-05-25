#include <windows.h>
#include <intrin.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <string>
#include <vector>
#include "../common.h"

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
};

// Export functions for main agent
extern "C" {
    bool CheckEnvironment() {
        AntiVMDetector detector;
        bool isClean = detector.CheckEnvironment();
        
        if (!isClean) {
            extern void LogWarning(const char*);
            std::string warning = "Virtual machine detected: " + detector.GetDetectedVM();
            LogWarning(warning.c_str());
        } else {
            extern void LogInfo(const char*);
            LogInfo("Environment check passed - no VM detected");
        }
        
        return isClean;
    }
    
    bool CheckVMEnvironment() {
        AntiVMDetector detector;
        bool isClean = detector.CheckEnvironment();
        
        if (!isClean) {
            extern void LogWarning(const char*);
            std::string warning = "Virtual machine detected: " + detector.GetDetectedVM();
            LogWarning(warning.c_str());
        }
        
        return isClean;
    }
}