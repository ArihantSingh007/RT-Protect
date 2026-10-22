#include "runtime/executable_memory.h"

#include <cstring>
#include <mutex>
#include <utility>

#include <windows.h>
#if !defined(_MSC_VER)
#include <csetjmp>
#endif

#include "runtime/native_payload.h"

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

#if !defined(_MSC_VER)
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

// Returns true if `payload`/`payload_len` is byte-for-byte identical to
// one of this project's small, fixed set of reviewed native-code
// payloads.
bool IsRecognizedPayload(const std::uint8_t* payload, std::size_t payload_len) {
  if (payload_len == kPayloadSysV.size() &&
      std::memcmp(payload, kPayloadSysV.data(), payload_len) == 0) {
    return true;
  }
  if (payload_len == kPayloadMsx64.size() &&
      std::memcmp(payload, kPayloadMsx64.data(), payload_len) == 0) {
    return true;
  }
  if (payload_len == kFaultTestPayload.size() &&
      std::memcmp(payload, kFaultTestPayload.data(), payload_len) == 0) {
    return true;
  }
  return false;
}

std::size_t PageSize() {
  SYSTEM_INFO si;
  GetSystemInfo(&si);
  return static_cast<std::size_t>(si.dwPageSize);
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
    return fail(LoadError::kPayloadTooLarge);
  }

  if (!IsRecognizedPayload(payload, payload_len)) {
    return fail(LoadError::kPayloadNotRecognized);
  }

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

  // Step 3: instruction-cache synchronization via FlushInstructionCache.
  if (!FlushInstructionCache(GetCurrentProcess(), mem, page)) {
    VirtualFree(mem, 0, MEM_RELEASE);
    return fail(LoadError::kProtectionChangeFailed);
  }

  return ExecutableMemoryRegion(mem, page);
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
  VirtualFree(mem_, 0, MEM_RELEASE);
  mem_ = nullptr;
  size_ = 0;
}

ExecutableMemoryRegion::CallResult ExecutableMemoryRegion::Call(std::int64_t arg) const {
  using Fn = std::int64_t (*)(std::int64_t);
  Fn fn = reinterpret_cast<Fn>(mem_);

  CallResult result;

#if defined(_MSC_VER)
  // Structured Exception Handling on MSVC: catches hardware faults
  __try {
    result.value = fn(arg);
    result.faulted = false;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    result.faulted = true;
    result.value = 0;
  }
#else
  // MinGW GCC on Windows: use Windows Vectored Exception Handling (VEH)
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
#endif

  return result;
}

}  // namespace rtprotect::runtime
