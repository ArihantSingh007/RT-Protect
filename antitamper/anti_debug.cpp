// antitamper/anti_debug.cpp
//
// Windows Anti-Debugging & Runtime Tamper Detection Subsystem.
// Implements multi-layered, unhookable Windows protection checks:
// - Direct PEB inspection (BeingDebugged and NtGlobalFlag) via gs:0x60/fs:0x30
// - Direct NT kernel queries via NtQueryInformationProcess (ProcessDebugPort & ProcessDebugObjectHandle)
// - Dynamic hashed API resolution for IsDebuggerPresent and CheckRemoteDebuggerPresent
// - Multi-threaded Hardware Breakpoint detection via debug registers (DR0..DR3)
// - Execution timing anomaly detection via QueryPerformanceCounter
// - Inline hook and software breakpoint detection (INT 3, JMP detours)

#include "antitamper/anti_debug.h"
#include "antitamper/dynamic_import.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <thread>
#include <windows.h>
#include <tlhelp32.h>
#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace rtprotect::antitamper {

namespace {
std::atomic<bool> g_hw_bp_detected{false};
std::atomic<bool> g_watchdog_running{false};
std::thread g_watchdog_thread;
std::mutex g_watchdog_mu;

// Direct unhookable PEB inspection
bool CheckDirectPebDebugFlags() {
#if defined(_M_X64) || defined(__x86_64__)
  const unsigned char* pPeb = nullptr;
#if defined(_MSC_VER)
  pPeb = reinterpret_cast<const unsigned char*>(__readgsqword(0x60));
#elif defined(__GNUC__) || defined(__clang__)
  __asm__ __volatile__("movq %%gs:0x60, %0" : "=r"(pPeb));
#endif
  if (!pPeb) return false;

  // BeingDebugged flag is located at offset 0x02 in PEB
  if (pPeb[2] != 0) return true;

  // NtGlobalFlag is located at offset 0xBC in 64-bit PEB
  // Flags: FLG_HEAP_ENABLE_TAIL_CHECK (0x10) | FLG_HEAP_ENABLE_FREE_CHECK (0x20) | FLG_HEAP_VALIDATE_PARAMETERS (0x40)
  std::uint32_t ntGlobalFlag = *reinterpret_cast<const std::uint32_t*>(pPeb + 0xBC);
  if ((ntGlobalFlag & 0x70) == 0x70) return true;

#elif defined(_M_IX86) || defined(__i386__)
  const unsigned char* pPeb = nullptr;
#if defined(_MSC_VER)
  pPeb = reinterpret_cast<const unsigned char*>(__readfsdword(0x30));
#elif defined(__GNUC__) || defined(__clang__)
  __asm__ __volatile__("movl %%fs:0x30, %0" : "=r"(pPeb));
#endif
  if (!pPeb) return false;

  if (pPeb[2] != 0) return true;

  std::uint32_t ntGlobalFlag = *reinterpret_cast<const std::uint32_t*>(pPeb + 0x68);
  if ((ntGlobalFlag & 0x70) == 0x70) return true;
#endif

  return false;
}

// Direct NT kernel query via NtQueryInformationProcess
bool CheckNtQueryProcessDebug() {
  typedef NTSTATUS(NTAPI *pfnNtQueryInformationProcess)(
      HANDLE ProcessHandle,
      ULONG ProcessInformationClass,
      PVOID ProcessInformation,
      ULONG ProcessInformationLength,
      PULONG ReturnLength);

  void* hNtdll = GetLoadedModuleBaseByHash(kHashNtdll);
  if (!hNtdll) return false;

  auto fnNtQuery = reinterpret_cast<pfnNtQueryInformationProcess>(
      ResolveExportByHash(hNtdll, kHashNtQueryInformationProcess));
  if (!fnNtQuery) return false;

  // ProcessDebugPort = 7
  DWORD_PTR debug_port = 0;
  NTSTATUS status = fnNtQuery(::GetCurrentProcess(), 7, &debug_port, sizeof(debug_port), nullptr);
  if (status == 0 && debug_port != 0) return true;

  // ProcessDebugObjectHandle = 30
  HANDLE debug_obj = nullptr;
  status = fnNtQuery(::GetCurrentProcess(), 30, &debug_obj, sizeof(debug_obj), nullptr);
  if (status == 0 && debug_obj != nullptr) {
    ::CloseHandle(debug_obj);
    return true;
  }

  return false;
}

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
          ::SuspendThread(th);
          CONTEXT ctx{};
          ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
          if (::GetThreadContext(th, &ctx)) {
            if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
              found = true;
            }
          }
          ::ResumeThread(th);
          ::CloseHandle(th);
          if (found) break;
        }
      }
    } while (::Thread32Next(snap, &te));
  }
  ::CloseHandle(snap);
  return found;
}

}  // namespace

bool IsHardwareBreakpointDetected() {
  return g_hw_bp_detected.load(std::memory_order_relaxed);
}

bool CheckDebuggerPresent() {
  // 1. Direct unhookable PEB inspection
  if (CheckDirectPebDebugFlags()) return true;

  // 2. Direct NT kernel query via NtQueryInformationProcess
  if (CheckNtQueryProcessDebug()) return true;

  // 3. Dynamic hashed API check (eliminates static IAT entry)
  typedef BOOL (WINAPI *pfnIsDebuggerPresent)();
  auto fnIsDebuggerPresent = ResolveApi<pfnIsDebuggerPresent>(kHashKernel32, kHashIsDebuggerPresent);
  if (!fnIsDebuggerPresent) {
    fnIsDebuggerPresent = ResolveApi<pfnIsDebuggerPresent>(kHashKernelBase, kHashIsDebuggerPresent);
  }
  if (fnIsDebuggerPresent && fnIsDebuggerPresent() != 0) {
    return true;
  }
  return false;
}

bool CheckRemoteDebugger() {
  typedef BOOL (WINAPI *pfnCheckRemoteDebuggerPresent)(HANDLE, PBOOL);
  auto fnCheckRemoteDebugger = ResolveApi<pfnCheckRemoteDebuggerPresent>(
      kHashKernel32, kHashCheckRemoteDebuggerPresent);
  if (!fnCheckRemoteDebugger) {
    fnCheckRemoteDebugger = ResolveApi<pfnCheckRemoteDebuggerPresent>(
        kHashKernelBase, kHashCheckRemoteDebuggerPresent);
  }
  if (fnCheckRemoteDebugger) {
    BOOL is_debugger = FALSE;
    if (fnCheckRemoteDebugger(::GetCurrentProcess(), &is_debugger)) {
      return is_debugger != 0;
    }
  }
  return false;
}

bool CheckHardwareBreakpoints() {
  if (g_hw_bp_detected.load(std::memory_order_relaxed)) {
    return true;
  }

  // Scan existing application threads via snapshot
  if (ScanProcessThreadsForHardwareBreakpoints()) {
    g_hw_bp_detected.store(true, std::memory_order_relaxed);
    return true;
  }

  // Check calling thread registers via a temporary helper thread
  struct HelperParam {
    HANDLE target_thread = nullptr;
    bool found_bp = false;
  } param;

  HANDLE cur_thread = ::GetCurrentThread();
  HANDLE dup_thread = nullptr;
  if (!::DuplicateHandle(::GetCurrentProcess(), cur_thread, ::GetCurrentProcess(),
                         &dup_thread, THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
                         FALSE, 0)) {
    return false;
  }
  param.target_thread = dup_thread;

  HANDLE helper = ::CreateThread(nullptr, 0, [](LPVOID p) -> DWORD {
    auto* hp = static_cast<HelperParam*>(p);
    ::SuspendThread(hp->target_thread);
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (::GetThreadContext(hp->target_thread, &ctx)) {
      if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
        hp->found_bp = true;
      }
    }
    ::ResumeThread(hp->target_thread);
    return hp->found_bp ? 1 : 0;
  }, &param, 0, nullptr);

  bool found_bp = false;
  if (helper) {
    ::WaitForSingleObject(helper, 100);
    DWORD exit_code = 0;
    if (::GetExitCodeThread(helper, &exit_code) && exit_code == 1) {
      found_bp = true;
    }
    ::CloseHandle(helper);
  }
  ::CloseHandle(dup_thread);

  if (found_bp) {
    g_hw_bp_detected.store(true, std::memory_order_relaxed);
  }
  return found_bp;
}

void StartHardwareBreakpointWatchdog(std::uint32_t interval_ms) {
  std::lock_guard<std::mutex> lock(g_watchdog_mu);
  if (g_watchdog_running.load()) return;
  g_watchdog_running.store(true);
  g_watchdog_thread = std::thread([interval_ms]() {
    while (g_watchdog_running.load()) {
      if (ScanProcessThreadsForHardwareBreakpoints()) {
        g_hw_bp_detected.store(true, std::memory_order_relaxed);
        break;
      }
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
  return elapsed_seconds > 0.25;
}

bool CheckMemoryTampered() {
  static const std::uint32_t kCheckedApiHashes[] = {
      kHashIsDebuggerPresent,
      kHashCheckRemoteDebuggerPresent,
      kHashVirtualProtect,
      kHashGetProcAddress
  };
  void* hKernel32 = GetLoadedModuleBaseByHash(kHashKernel32);
  void* hKernelBase = GetLoadedModuleBaseByHash(kHashKernelBase);
  for (std::uint32_t api_hash : kCheckedApiHashes) {
    const unsigned char* p = nullptr;
    if (hKernelBase) {
      p = reinterpret_cast<const unsigned char*>(ResolveExportByHash(hKernelBase, api_hash));
    }
    if (!p && hKernel32) {
      p = reinterpret_cast<const unsigned char*>(ResolveExportByHash(hKernel32, api_hash));
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
  return false;
}

}  // namespace rtprotect::antitamper
