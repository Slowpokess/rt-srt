#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Advanced Persistence Management Functions
// These functions provide comprehensive Windows persistence mechanisms
// with AES encryption, multiple fallback paths, and detailed verification

/**
 * Install advanced persistence mechanisms
 * - Uses AES-256 encryption instead of weak obfuscation
 * - Multiple fallback paths for non-admin scenarios
 * - Scheduled tasks, registry entries, startup links, services, COM objects
 * - Controlled watchdog process with time limits
 * @return true if at least one persistence method was installed successfully
 */
bool InstallAdvancedPersistence();

/**
 * Verify installed persistence mechanisms and attempt repair
 * - Checks all installed persistence methods using WinAPI
 * - Automatically attempts to reinstall failed methods
 * - Verifies file integrity and watchdog status
 * @return true if all installed methods are verified and functional
 */
bool VerifyAdvancedPersistence();

/**
 * Comprehensive scan for any persistence mechanisms (regardless of installation status)
 * - Scans all possible persistence locations using WinAPI
 * - Checks scheduled tasks, registry entries, startup folders, services, COM objects
 * - Independent of installation records - forensic analysis capability
 * @return true if any persistence mechanisms are found
 */
bool ScanForPersistence();

/**
 * Complete removal of all persistence mechanisms
 * - Removes all installed persistence methods
 * - Cleans up copied files and registry entries
 * - Stops and removes watchdog processes
 * - Schedules remaining files for deletion on reboot
 * @return true if cleanup was successful
 */
bool CleanupPersistence();

/**
 * Get detailed status of persistence mechanisms
 * - Returns structured status string with individual method status
 * - Format: "Tasks:1,Registry:1,Startup:0,Services:1,COM:0,AdvReg:1,Watchdog:1"
 * - 1 = active, 0 = inactive
 * @param statusBuffer Output buffer for status string
 * @param bufferSize Size of the output buffer
 * @return true if status was successfully retrieved
 */
bool GetPersistenceStatus(char* statusBuffer, int bufferSize);

#ifdef __cplusplus
}
#endif