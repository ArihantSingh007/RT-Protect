// antitamper/anti_debug.h
//
// Platform-specific anti-debugging and instrumentation detection.
//
// Detects active user-mode debuggers (IsDebuggerPresent, CheckRemoteDebuggerPresent),
// hardware debug registers (DR0-DR3), and timing discrepancies caused by
// interactive single-stepping.

#pragma once

namespace rtprotect::antitamper {

// Checks whether a debugger is attached via standard OS API.
bool CheckDebuggerPresent();

// Checks whether a remote debugger is attached to the process.
bool CheckRemoteDebugger();

// Scans thread debug registers (DR0, DR1, DR2, DR3) for active hardware breakpoints.
bool CheckHardwareBreakpoints();

// Measures execution time of a tight computational loop to detect single-stepping delays.
bool CheckExecutionTimingAnomaly();

}  // namespace rtprotect::antitamper
