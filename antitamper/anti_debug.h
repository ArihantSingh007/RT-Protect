// antitamper/anti_debug.h
//
// Platform-specific anti-debugging and instrumentation detection.
//
// Detects active user-mode debuggers (IsDebuggerPresent, CheckRemoteDebuggerPresent),
// hardware debug registers (DR0-DR3), and timing discrepancies caused by
// interactive single-stepping.

#pragma once

#include <cstdint>

namespace rtprotect::antitamper {

// Checks whether a debugger is attached via standard OS API.
bool CheckDebuggerPresent();

// Checks whether a remote debugger is attached to the process.
bool CheckRemoteDebugger();

// Scans thread debug registers (DR0, DR1, DR2, DR3) for active hardware breakpoints.
bool CheckHardwareBreakpoints();

// Returns true if hardware breakpoints were detected by any check or watchdog.
bool IsHardwareBreakpointDetected();

// Starts an optional background watchdog thread that periodically scans process threads for hardware breakpoints.
void StartHardwareBreakpointWatchdog(std::uint32_t interval_ms = 1000);

// Stops the background hardware breakpoint watchdog thread if running.
void StopHardwareBreakpointWatchdog();

// Measures execution time of a tight computational loop to detect single-stepping delays.
bool CheckExecutionTimingAnomaly();

// Detects inline hooks, trampolines, or software breakpoints (INT 3) on critical security APIs.
bool CheckMemoryTampered();

}  // namespace rtprotect::antitamper
