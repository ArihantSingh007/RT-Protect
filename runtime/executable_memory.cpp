#include "runtime/executable_memory.h"

#include <cstring>
#include <mutex>
#include <utility>

#include "runtime/native_payload.h"

#if defined(_WIN32)
#include <windows.h>
#if !defined(_MSC_VER)
#include <csetjmp>
#endif
#else
#include <csetjmp>
#include <csignal>
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace rtprotect::runtime {

const char* ToString(LoadError error) {
  switch (error) {
    case LoadError::kNone: return "none";
    case LoadError::kAllocationFailed: return "memory allocation failed";
    case LoadError::kProtectionChangeFailed: return "changing page protection (RW -> RX) failed";
    case LoadError::kPayloadTooLarge: return "payload exceeds one page";
    case LoadError::kPayloadNotRecognized:
      return "payload bytes do not exactly match a known-reviewed payload";
  }
  return "unknown LoadError";
}

namespace {

#if defined(_WIN32) && !defined(_MSC_VER)
thread_local jmp_buf g_win_jmp_buf;
thread_local volatile int g_win_in_protected_call = 0;

static LONG WINAPI MinGWVectoredHandler(PEXCEPTION_POINTERS ep) {
  (void)ep;
  if (g_win_in_protected_call) {
    longjmp(g_win_jmp_buf, 1);
  }
  return EXCEPTION_CONTINUE_SEARCH;
}
#endif

#if !defined(_WIN32)
// --- POSIX fault-isolation machinery (test-harness path) ---------------
//
// This exists ONLY so this experiment can be built and tested in a
// Linux/GCC environment, matching this project's established pattern
// (see crypto/CMakeLists.txt's toolchain note, carried through every
// phase) of writing Windows-first code that's also exercised on the
// available Linux toolchain. The Windows deployment path uses Structured
// Exception Handling (__try/__except) instead -- see Call()'s #ifdef
// _WIN32 branch below -- which is the real, documented mechanism for this
// on the primary target platform.
thread_local sigjmp_buf g_fault_jmp_buf;
thread_local volatile std::sig_atomic_t g_in_protected_call = 0;

// Serializes the install-call-restore sequence in Call() below across
// threads. THE RACE THIS CLOSES: sigaction() installs a PROCESS-WIDE
// signal handler -- it is not per-thread, unlike g_fault_jmp_buf above
// (which correctly IS thread_local, since each thread needs its own
// longjmp target). If two threads both called Call() concurrently without
// this mutex, their sigaction() install/restore calls could interleave
// arbitrarily: thread A installs FaultSignalHandler, thread B installs
// FaultSignalHandler again (redundant but harmless) and saves what it
// believes was the "original" handler (actually thread A's installation,
// not the true original), then thread A finishes first and restores
// using ITS saved "original" (correct), but thread B then finishes and
// restores using WHAT IT SAVED -- which was thread A's handler, not the
// process's true original -- leaving the process's signal handler table
// in a state that depends on execution interleaving rather than being
// well-defined. A per-thread jump-buffer alone does not fix this: the
// hazard is in the shared, process-wide handler TABLE itself, which a
// thread_local variable has no influence over. This mutex makes the
// entire sequence atomic with respect to other threads calling into this
// same function, which is sufficient because installing/restoring the
// signal handler is the only process-wide state Call() touches -- it does
// not fix concurrent execution of unrelated code that might also touch
// SIGSEGV/SIGBUS/SIGILL handlers via some other path outside this file,
// which remains a real, acknowledged limitation of layering fault
// isolation on top of process-wide signal handling at all (see
// docs/RUNTIME_RECONSTRUCTION.md).
std::mutex g_signal_handler_mutex;

extern "C" void FaultSignalHandler(int sig) {
  if (g_in_protected_call) {
    siglongjmp(g_fault_jmp_buf, 1);
  } else {
    // A fault signal arrived while we were NOT inside a protected call --
    // this handler should never be active outside that window (it's
    // installed and removed around the call, see Call() below). Restore
    // the default handler and re-raise rather than silently swallowing an
    // unrelated fault.
    std::signal(sig, SIG_DFL);
    std::raise(sig);
  }
}
#endif

// Returns true if `payload`/`payload_len` is byte-for-byte identical to
// one of this project's small, fixed set of reviewed native-code
// payloads. See executable_memory.h's header comment on why Create()
// enforces this itself rather than trusting callers to only ever supply
// the reviewed payload.
bool IsRecognizedPayload(const std::uint8_t* payload, std::size_t payload_len) {
  if (payload_len == kPayloadSysV.size() &&
      std::memcmp(payload, kPayloadSysV.data(), payload_len) == 0) {
    return true;
  }
  if (payload_len == kPayloadMsx64.size() &&
      std::memcmp(payload, kPayloadMsx64.data(), payload_len) == 0) {
    return true;
  }
  // See kFaultTestPayload's comment: included so this
  // project's own fault-isolation tests exercise the real public API
  // (Create()/Call()) rather than a separate, less representative
  // test-only path.
  if (payload_len == kFaultTestPayload.size() &&
      std::memcmp(payload, kFaultTestPayload.data(), payload_len) == 0) {
    return true;
  }
  return false;
}

std::size_t PageSize() {
#if defined(_WIN32)
  SYSTEM_INFO si;
  GetSystemInfo(&si);
  return static_cast<std::size_t>(si.dwPageSize);
#else
  long sz = sysconf(_SC_PAGESIZE);
  return sz > 0 ? static_cast<std::size_t>(sz) : 4096;
#endif
}

}  // namespace

std::optional<ExecutableMemoryRegion> ExecutableMemoryRegion::Create(const std::uint8_t* payload,
                                                                       std::size_t payload_len,
                                                                       LoadError* out_error) {
  auto fail = [&](LoadError e) -> std::optional<ExecutableMemoryRegion> {
    if (out_error) *out_error = e;
    return std::nullopt;
  };

  std::size_t page = PageSize();
  if (payload_len > page) {
    // This experiment's payload (native_payload.h) is 6 bytes; a page is
    // typically 4096. Rejecting anything over one page is a deliberate,
    // simple sanity bound -- not a real-world size limit for this
    // technique in general, just appropriate for what this phase actually
    // ships.
    return fail(LoadError::kPayloadTooLarge);
  }

  // Enforced here, not merely documented at the call site -- see
  // executable_memory.h's header comment and IsRecognizedPayload()'s
  // comment above. Checked before any allocation or memory-protection
  // change, so a payload that fails this check never touches the OS
  // memory-management calls below at all.
  if (!IsRecognizedPayload(payload, payload_len)) {
    return fail(LoadError::kPayloadNotRecognized);
  }

#if defined(_WIN32)
  // Step 1: allocate READ-WRITE. Never request PAGE_EXECUTE_READWRITE --
  // that would violate W^X by making the region simultaneously writable
  // and executable, which is exactly the pattern DEP and modern hardened
  // runtimes (and most EDR heuristics) flag.
  void* mem = VirtualAlloc(nullptr, page, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!mem) return fail(LoadError::kAllocationFailed);

  std::memcpy(mem, payload, payload_len);

  // Step 2: transition to READ-EXECUTE (not WRITE-EXECUTE) -- the payload
  // is now immutable as far as this process's own code is concerned.
  DWORD old_protect = 0;
  if (!VirtualProtect(mem, page, PAGE_EXECUTE_READ, &old_protect)) {
    VirtualFree(mem, 0, MEM_RELEASE);
    return fail(LoadError::kProtectionChangeFailed);
  }

  // Step 3: instruction-cache synchronization. On x86/x64 this is
  // documented by Microsoft as unnecessary in practice (the architecture
  // keeps the I-cache coherent with the D-cache for same-process writes)
  // but FlushInstructionCache is still the documented, correct API to
  // call after writing executable code at runtime, and is NOT optional on
  // ARM64 Windows, where I/D-cache coherency is NOT automatic -- skipping
  // this call would be a real, platform-dependent correctness bug that
  // happens not to manifest on x86/x64. Always call it, AND check its
  // result -- a discarded return value here would mean an ARM64 Windows
  // build could silently proceed with a stale instruction cache (and
  // consequently execute garbage/stale bytes) if the flush itself failed,
  // exactly the "ignored failure that lets the protected operation
  // proceed anyway" pattern this project's hardening review was asked to
  // close everywhere, not only in the VM/manifest/crypto layers.
  if (!FlushInstructionCache(GetCurrentProcess(), mem, page)) {
    VirtualFree(mem, 0, MEM_RELEASE);
    return fail(LoadError::kProtectionChangeFailed);
  }

  return ExecutableMemoryRegion(mem, page);
#else
  // POSIX test-harness path -- see the file-level comment above.
  void* mem = mmap(nullptr, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mem == MAP_FAILED) return fail(LoadError::kAllocationFailed);

  std::memcpy(mem, payload, payload_len);

  if (mprotect(mem, page, PROT_READ | PROT_EXEC) != 0) {
    munmap(mem, page);
    return fail(LoadError::kProtectionChangeFailed);
  }

  // __builtin___clear_cache is GCC/Clang's portable instruction-cache
  // flush primitive. On x86-64 (this project's test environment) it's a
  // documented no-op at the instruction level (the ISA guarantees I/D
  // coherency), but calling it unconditionally is still correct practice
  // and is what makes this code portable to an architecture (e.g. ARM)
  // where it is NOT a no-op -- same reasoning as FlushInstructionCache
  // above.
  __builtin___clear_cache(static_cast<char*>(mem), static_cast<char*>(mem) + page);

  return ExecutableMemoryRegion(mem, page);
#endif
}

ExecutableMemoryRegion::ExecutableMemoryRegion(void* mem, std::size_t size)
    : mem_(mem), size_(size) {}

ExecutableMemoryRegion::ExecutableMemoryRegion(ExecutableMemoryRegion&& other) noexcept
    : mem_(other.mem_), size_(other.size_) {
  other.mem_ = nullptr;
  other.size_ = 0;
}

ExecutableMemoryRegion& ExecutableMemoryRegion::operator=(ExecutableMemoryRegion&& other) noexcept {
  if (this != &other) {
    // Release whatever THIS object currently owns, then take ownership of
    // `other`'s resources -- via a dedicated private helper, NOT by
    // calling this->~ExecutableMemoryRegion() directly. The previous
    // version of this function called the destructor explicitly and then
    // went on to write to mem_/size_ afterward: per the C++ object model,
    // an explicit destructor call ends the object's lifetime, and writing
    // to its members afterward (to "resurrect" it with new values,
    // without a placement-new) is undefined behavior -- a fragile pattern
    // regardless of whether it happens to work for today's trivial
    // member types on today's compiler. ReleaseResources() frees the
    // underlying OS mapping without touching the object's lifetime at
    // all; this object remains the same, valid (if momentarily empty)
    // object throughout, exactly as a hand-written destructor followed by
    // ordinary member assignment should behave, without relying on the
    // explicit-destructor-call trick to get there.
    ReleaseResources();
    mem_ = other.mem_;
    size_ = other.size_;
    other.mem_ = nullptr;
    other.size_ = 0;
  }
  return *this;
}

ExecutableMemoryRegion::~ExecutableMemoryRegion() { ReleaseResources(); }

void ExecutableMemoryRegion::ReleaseResources() {
  if (!mem_) return;
#if defined(_WIN32)
  VirtualFree(mem_, 0, MEM_RELEASE);
#else
  munmap(mem_, size_);
#endif
  mem_ = nullptr;
  size_ = 0;
}

ExecutableMemoryRegion::CallResult ExecutableMemoryRegion::Call(std::int64_t arg) const {
  using Fn = std::int64_t (*)(std::int64_t);
  Fn fn = reinterpret_cast<Fn>(mem_);

  CallResult result;

#if defined(_MSC_VER)
  // Structured Exception Handling: catches hardware faults (access
  // violation, illegal instruction) raised while executing `fn` and
  // converts them into a normal C++ return value instead of an unhandled
  // exception that would terminate the process. This is the standard,
  // documented Windows mechanism for MSVC.
  __try {
    result.value = fn(arg);
    result.faulted = false;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    result.faulted = true;
    result.value = 0;
  }
#elif defined(_WIN32)
  // MinGW GCC on Windows does not support MSVC __try/__except in C++ mode.
  // Use Windows Vectored Exception Handling (VEH) with setjmp/longjmp.
  PVOID veh = AddVectoredExceptionHandler(1, MinGWVectoredHandler);
  g_win_in_protected_call = 1;
  if (setjmp(g_win_jmp_buf) == 0) {
    result.value = fn(arg);
    result.faulted = false;
  } else {
    result.faulted = true;
    result.value = 0;
  }
  g_win_in_protected_call = 0;
  if (veh) RemoveVectoredExceptionHandler(veh);
#else
  // POSIX test-harness path: install fault handlers for the signals a bad
  // instruction or bad memory access would raise, call through a
  // sigsetjmp checkpoint, and longjmp back out if one fires. See the
  // FaultSignalHandler comment above for why this is test-harness-only
  // machinery, not the Windows deployment path.
  //
  // g_signal_handler_mutex serializes the entire install-call-restore
  // sequence across threads -- see that mutex's declaration comment for
  // the exact race this closes (concurrent sigaction() calls racing on
  // the process-wide handler table, which a thread_local jump buffer
  // alone does not and cannot fix).
  std::lock_guard<std::mutex> signal_handler_lock(g_signal_handler_mutex);

  struct sigaction new_action{};
  struct sigaction old_segv{}, old_bus{}, old_ill{};
  new_action.sa_handler = FaultSignalHandler;
  sigemptyset(&new_action.sa_mask);
  new_action.sa_flags = 0;

  sigaction(SIGSEGV, &new_action, &old_segv);
  sigaction(SIGBUS, &new_action, &old_bus);
  sigaction(SIGILL, &new_action, &old_ill);

  g_in_protected_call = 1;
  if (sigsetjmp(g_fault_jmp_buf, 1) == 0) {
    result.value = fn(arg);
    result.faulted = false;
  } else {
    result.value = 0;
    result.faulted = true;
  }
  g_in_protected_call = 0;

  sigaction(SIGSEGV, &old_segv, nullptr);
  sigaction(SIGBUS, &old_bus, nullptr);
  sigaction(SIGILL, &old_ill, nullptr);
#endif

  return result;
}

}  // namespace rtprotect::runtime
