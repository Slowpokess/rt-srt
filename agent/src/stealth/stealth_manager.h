#ifndef STEALTH_MANAGER_H
#define STEALTH_MANAGER_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// Anti-Debug Functions
bool CheckForDebugger();
void ApplyAntiDebugProtection();
bool PerformCompleteAntiDebugCheck();

// Anti-VM Functions  
bool CheckEnvironment();
bool CheckVMEnvironment();
bool CheckSandboxEnvironment();
bool PerformCompleteAnalysisCheck();

// Stealth Manager Functions
bool InitializeStealthProtection();
bool PerformFullEnvironmentCheck();
void ApplyAllProtections();
bool IsEnvironmentSafe();
void TerminateIfUnsafe();

#ifdef __cplusplus
}
#endif

#endif // STEALTH_MANAGER_H