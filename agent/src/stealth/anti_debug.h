#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Anti-Debug Protection Functions
// These functions detect and prevent debugging attempts
// using various Windows API techniques

/**
 * Initialize anti-debug protection
 * Sets up various anti-debugging mechanisms
 * @return true if protection was successfully initialized
 */
bool InitAntiDebugProtection();

/**
 * Check for debugger presence
 * Uses multiple detection techniques
 * @return true if debugger detected
 */
bool IsDebuggerAttached();

/**
 * Enable advanced anti-debug protection
 * Activates thread information manipulation and other advanced techniques
 * @return true if advanced protection enabled
 */
bool EnableAdvancedAntiDebug();

/**
 * Continuous debugger monitoring
 * Should be called periodically to maintain protection
 * @return true if system remains clean
 */
bool MonitorDebuggerPresence();

#ifdef __cplusplus
}
#endif