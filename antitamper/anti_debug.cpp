// antitamper/anti_debug.cpp

#include "antitamper/anti_debug.h"

#include <cstdint>

#if defined(_WIN32)
#include <windows.h>
#else
#include <fstream>
#include <string>
#include <ctime>
#endif

namespace rtprotect::antitamper {

bool CheckDebuggerPresent() {
#if defined(_WIN32)
  return ::IsDebuggerPresent() != 0;
#else
  std::ifstream f("/proc/self/status");
  std::string line;
  while (f && std::getline(f, line)) {
    if (line.rfind("TracerPid:", 0) == 0) {
      long pid = std::stol(line.substr(10));
      return pid > 0;
    }
  }
  return false;
#endif
}

bool CheckRemoteDebugger() {
#if defined(_WIN32)
  BOOL is_debugger = FALSE;
  if (::CheckRemoteDebuggerPresent(::GetCurrentProcess(), &is_debugger)) {
    return is_debugger != 0;
  }
  return false;
#else
  // Linux does not have a distinct remote debugger API analogous to Win32;
  // local/remote debugging is surfaced through TracerPid in CheckDebuggerPresent().
  // Returning false avoids double-counting a single TracerPid signal.
  return false;
#endif
}

bool CheckHardwareBreakpoints() {
#if defined(_WIN32)
  DWORD current_tid = ::GetCurrentThreadId();
  bool found_bp = false;
  HANDLE helper = ::CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
    DWORD target_tid = *reinterpret_cast<DWORD*>(param);
    HANDLE target = ::OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, target_tid);
    if (!target) return 0;
    if (::SuspendThread(target) != static_cast<DWORD>(-1)) {
      CONTEXT ctx{};
      ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
      if (::GetThreadContext(target, &ctx)) {
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
          ::ResumeThread(target);
          ::CloseHandle(target);
          return 1;
        }
      }
      ::ResumeThread(target);
    }
    ::CloseHandle(target);
    return 0;
  }, &current_tid, 0, nullptr);

  if (helper) {
    ::WaitForSingleObject(helper, 100);
    DWORD exit_code = 0;
    if (::GetExitCodeThread(helper, &exit_code) && exit_code == 1) {
      found_bp = true;
    }
    ::CloseHandle(helper);
  }
  return found_bp;
#else
  return false;
#endif
}

bool CheckExecutionTimingAnomaly() {
  // Measures whether a tiny deterministic computational loop takes an
  // abnormally long time (characteristic of an interactive debugger breakpoint or step).
#if defined(_WIN32)
  LARGE_INTEGER freq, start, end;
  if (!::QueryPerformanceFrequency(&freq) || !::QueryPerformanceCounter(&start)) {
    return false;
  }

  volatile std::uint64_t dummy = 0;
  for (int i = 0; i < 5000; ++i) {
    dummy += (i * 3) ^ (dummy >> 2);
  }

  ::QueryPerformanceCounter(&end);
  double elapsed_seconds = static_cast<double>(end.QuadPart - start.QuadPart) / static_cast<double>(freq.QuadPart);
  // 5000 iterations takes microseconds. > 0.25 seconds indicates pausing/stepping.
  return elapsed_seconds > 0.25;
#else
  struct timespec start{}, end{};
  clock_gettime(CLOCK_MONOTONIC, &start);

  volatile std::uint64_t dummy = 0;
  for (int i = 0; i < 5000; ++i) {
    dummy += (i * 3) ^ (dummy >> 2);
  }

  clock_gettime(CLOCK_MONOTONIC, &end);
  double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) * 1e-9;
  return elapsed > 0.25;
#endif
}

}  // namespace rtprotect::antitamper
