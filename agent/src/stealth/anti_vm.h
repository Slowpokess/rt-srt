#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Anti-VM Detection Functions
// These functions detect various virtual machine environments
// and analysis tools to evade automated analysis

/**
 * Main environment check function
 * Runs comprehensive VM and analysis detection
 * @return true if environment is clean, false if VM/analysis detected
 */
bool CheckEnvironment();

/**
 * Detailed VM detection with specific VM type identification
 * @param detectedVM Output string for detected VM type
 * @return true if VM detected, false otherwise
 */
bool DetectVirtualMachine(char* detectedVM, int bufferSize);

/**
 * Check for specific analysis tools
 * @return true if analysis tools detected
 */
bool HasAnalysisTools();

/**
 * Advanced timing-based detection
 * @return true if suspicious timing detected
 */
bool CheckTimingAnomalies();

#ifdef __cplusplus
}
#endif