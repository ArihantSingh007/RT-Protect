// antitamper/anti_debug.cpp

#include "antitamper/anti_debug.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <thread>

#if defined(_WIN32)
#include <windows.h>
#include <tlhelp32.h>
#if defined(_MSC_VER)
#include <intrin.h>
#endif
#else
#include <fstream>
#include <string>
#include <ctime>
#include <sys/ptrace.h>
#endif

namespace rtprotect::antitamper {

namespace {
std::atomic<bool> g_hw_bp_detected{false};
std::atomic<bool> g_watchdog_running{false};
std::thread g_watchdog_thread;
std::mutex g_watchdog_mu;
}  // namespace

bool IsHardwareBreakpointDetected() {
  return g_hw_bp_detected.load(std::memory_order_relaxed);
}

#if defined(_WIN32)
namespace {

const unsigned char* GetPebAddress() {
#if defined(_M_X64) || defined(__x86_64__)
  const unsigned char* peb = nullptr;
  #if defined(__GNUC__) || defined(__clang__)
  __asm__("movq %%gs:0x60, %0" : "=r"(peb));
  #elif defined(_MSC_VER)
  peb = reinterpret_cast<const unsigned char*>(__readgsqword(0x60));
  #endif
  return peb;
#elif defined(_M_IX86) || defined(__i386__)
  const unsigned char* peb = nullptr;
  #if defined(__GNUC__) || defined(__clang__)
  __asm__("movl %%fs:0x30, %0" : "=r"(peb));
  #elif defined(_MSC_VER)
  peb = reinterpret_cast<const unsigned char*>(__readfsdword(0x30));
  #endif
  return peb;
#else
  return nullptr;
#endif
}

bool CheckDirectPebDebugFlags() {
  const unsigned char* peb = GetPebAddress();
  if (!peb) return false;

  // BeingDebugged byte is at offset 2
  if (peb[2] != 0) return true;

#if defined(_M_X64) || defined(__x86_64__)
  // NtGlobalFlag dword is at offset 0xBC on x64
  std::uint32_t nt_global_flag = *reinterpret_cast<const std::uint32_t*>(peb + 0xBC);
  if ((nt_global_flag & 0x70) != 0) return true;
#elif defined(_M_IX86) || defined(__i386__)
  // NtGlobalFlag dword is at offset 0x68 on x86
  std::uint32_t nt_global_flag = *reinterpret_cast<const std::uint32_t*>(peb + 0x68);
  if ((nt_global_flag & 0x70) != 0) return true;
#endif

  return false;
}

bool CheckNtQueryProcessDebug() {
  typedef LONG (NTAPI *pfnNtQueryInformationProcess)(
      HANDLE, ULONG, PVOID, ULONG, PULONG);
  HMODULE hNtdll = ::GetModuleHandleA("ntdll.dll");
  if (!hNtdll) return false;

  auto pNtQIP = reinterpret_cast<pfnNtQueryInformationProcess>(
      reinterpret_cast<void*>(::GetProcAddress(hNtdll, "NtQueryInformationProcess")));
  if (!pNtQIP) return false;

  // Class 7 = ProcessDebugPort
  DWORD_PTR debug_port = 0;
  ULONG ret_len = 0;
  if (pNtQIP(::GetCurrentProcess(), 7, &debug_port, sizeof(debug_port), &ret_len) == 0) {
    if (debug_port != 0) return true;
  }

  // Class 0x1E (30) = ProcessDebugObjectHandle
  HANDLE debug_obj = nullptr;
  if (pNtQIP(::GetCurrentProcess(), 30, &debug_obj, sizeof(debug_obj), &ret_len) == 0) {
    if (debug_obj != nullptr) return true;
  }

  return false;
}

}  // namespace
#endif

bool CheckDebuggerPresent() {
#if defined(_WIN32)
  // 1. Direct unhookable PEB inspection
  if (CheckDirectPebDebugFlags()) return true;

  // 2. Direct NT kernel query via NtQueryInformationProcess
  if (CheckNtQueryProcessDebug()) return true;

  // 3. Standard Win32 API check
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

#if defined(_WIN32)
static bool ScanProcessThreadsForHardwareBreakpoints() {
  DWORD pid = ::GetCurrentProcessId();
  DWORD self_tid = ::GetCurrentThreadId();
  HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (snap == INVALID_HANDLE_VALUE) {
    return false;
  }
  THREADENTRY32 te{};
  te.dwSize = sizeof(te);
  bool found = false;
  if (::Thread32First(snap, &te)) {
    do {
      if (te.th32OwnerProcessID == pid && te.th32ThreadID != self_tid) {
        HANDLE th = ::OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
        if (th) {
          if (::SuspendThread(th) != static_cast<DWORD>(-1)) {
            CONTEXT ctx{};
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (::GetThreadContext(th, &ctx)) {
              if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
                found = true;
              }
            }
            ::ResumeThread(th);
          }
          ::CloseHandle(th);
          if (found) break;
        }
      }
    } while (::Thread32Next(snap, &te));
  }
  ::CloseHandle(snap);
  return found;
}
#endif

bool CheckHardwareBreakpoints() {
  if (g_hw_bp_detected.load(std::memory_order_relaxed)) {
    return true;
  }

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
  if (found_bp) {
    g_hw_bp_detected.store(true, std::memory_order_relaxed);
  }
  return found_bp;
#else
  return false;
#endif
}

void StartHardwareBreakpointWatchdog(std::uint32_t interval_ms) {
  std::lock_guard<std::mutex> lock(g_watchdog_mu);
  if (g_watchdog_running.load()) return;
  g_watchdog_running.store(true);
  g_watchdog_thread = std::thread([interval_ms]() {
    while (g_watchdog_running.load()) {
#if defined(_WIN32)
      if (ScanProcessThreadsForHardwareBreakpoints()) {
        g_hw_bp_detected.store(true, std::memory_order_relaxed);
        break;
      }
#endif
      std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
    }
  });
}

void StopHardwareBreakpointWatchdog() {
  std::lock_guard<std::mutex> lock(g_watchdog_mu);
  if (!g_watchdog_running.load()) return;
  g_watchdog_running.store(false);
  if (g_watchdog_thread.joinable()) {
    g_watchdog_thread.join();
  }
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

bool CheckMemoryTampered() {
#if defined(_WIN32)
  const char* apis[] = {
      "IsDebuggerPresent",
      "CheckRemoteDebuggerPresent",
      "VirtualProtect",
      "GetProcAddress"
  };
  HMODULE hKernel32 = ::GetModuleHandleA("kernel32.dll");
  HMODULE hKernelBase = ::GetModuleHandleA("kernelbase.dll");
  for (const char* api_name : apis) {
    const unsigned char* p = nullptr;
    if (hKernelBase) {
      p = reinterpret_cast<const unsigned char*>(::GetProcAddress(hKernelBase, api_name));
    }
    if (!p && hKernel32) {
      p = reinterpret_cast<const unsigned char*>(::GetProcAddress(hKernel32, api_name));
    }
    if (p) {
      // 0xCC: Software breakpoint (INT 3)
      if (p[0] == 0xCC) return true;
      // 0xE9: 32-bit relative jump (inline hook)
      if (p[0] == 0xE9) return true;
      // 0xFF 0x25: 64-bit indirect jump [rip + disp32] (MinHook / Detours)
      if (p[0] == 0xFF && p[1] == 0x25) return true;
    }
  }
#endif
  return false;
}

}  // namespace rtprotect::antitamper
