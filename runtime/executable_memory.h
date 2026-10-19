// runtime/executable_memory.h
//
// Loads a byte buffer into freshly-allocated memory and makes it
// executable, following the W^X (write XOR execute) discipline: memory is
// NEVER simultaneously writable and executable. It is allocated
// read-write, the payload is copied in, and only then is it transitioned
// to read-execute -- the two-step sequence DEP (Windows), NX (Linux), and
// modern hardened-runtime policies on every platform require. See
// docs/RUNTIME_RECONSTRUCTION.md for the full platform requirements this
// implements (VirtualAlloc/VirtualProtect/FlushInstructionCache on
// Windows; the POSIX mmap/mprotect equivalent used ONLY as this project's
// test harness, since the primary target toolchain is Windows/MSVC) and
// for the real, documented limitations this technique has (Control Flow
// Guard incompatibility, antivirus/EDR heuristic detection risk,
// instruction-cache coherency requirements) that this header's comments
// summarize but do not repeat in full.
//
// SCOPE, restated and now ENFORCED (not merely documented) from
// native_payload.h: Create() takes a byte pointer and length because the
// decrypt-then-load pipeline this exists for (runtime/
// reconstructed_function.h) is only meaningful if the bytes it loads are
// the ones that came out of decryption -- a version of this function with
// no byte parameter at all, hardcoded to always load native_payload.h's
// constant directly, would make the AEAD decrypt step pointless theater
// (the "protected" code would just be the hardcoded constant, regardless
// of what was actually encrypted or whether decryption even ran). That
// was considered and rejected as a "fix" for exactly this reason -- see
// docs/RUNTIME_RECONSTRUCTION.md's hardening section.
//
// What IS enforced, inside Create() itself rather than left to caller
// discipline: the provided bytes are compared, exactly, against this
// project's small fixed set of known-reviewed payloads
// (kPayloadSysV, kPayloadMsx64). Anything
// that doesn't match byte-for-byte is rejected with
// LoadError::kPayloadNotRecognized BEFORE any memory is allocated or made
// executable. This closes the gap a purely documentation-level
// restriction ("please only call this with the reviewed payload") cannot
// close: a caller mistake, or a future change to this project that forgot
// the restriction, is now rejected by Create() itself, not merely
// discouraged by a comment the caller might not have read.
//
// This does NOT make Create() a safe general-purpose code-execution
// sandbox for arbitrary input -- it makes it a loader for ONE OF A SMALL,
// FIXED ALLOWLIST of payloads this project's own source reviewed and
// tested, which is a categorically different and much narrower claim. See
// docs/RUNTIME_RECONSTRUCTION.md for the full reasoning.

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

namespace rtprotect::runtime {

enum class LoadError {
  kNone = 0,
  kAllocationFailed,
  kProtectionChangeFailed,
  kPayloadTooLarge,
  kPayloadNotRecognized,  // bytes don't exactly match a known-reviewed
                          // payload -- see Create()'s comment below for
                          // why this check exists and what it does and
                          // does not achieve
};

const char* ToString(LoadError error);

// RAII wrapper around one page-aligned region of memory that currently
// holds `payload`'s bytes as executable code. Move-only (the OS mapping
// has a single owner).
class ExecutableMemoryRegion {
 public:
  static std::optional<ExecutableMemoryRegion> Create(const std::uint8_t* payload,
                                                        std::size_t payload_len,
                                                        LoadError* out_error);

  ~ExecutableMemoryRegion();

  ExecutableMemoryRegion(const ExecutableMemoryRegion&) = delete;
  ExecutableMemoryRegion& operator=(const ExecutableMemoryRegion&) = delete;
  ExecutableMemoryRegion(ExecutableMemoryRegion&& other) noexcept;
  ExecutableMemoryRegion& operator=(ExecutableMemoryRegion&& other) noexcept;

  struct CallResult {
    bool faulted = false;    // true if the call raised a hardware fault
                              // (SIGSEGV/SIGBUS/SIGILL on the POSIX test
                              // harness; see the .cpp for the Windows SEH
                              // equivalent, documented but untested here)
    std::int64_t value = 0;  // meaningful only when faulted == false
  };

  // Invokes the loaded code as `int64_t fn(int64_t)`, matching
  // native_payload.h's one supported signature. Wrapped in fault isolation
  // so a crash in the executed code is reported as CallResult::faulted
  // rather than terminating the calling process -- this is the runtime
  // analogue of Phase 1-4's "fail closed, don't crash uncontrolled" design
  // principle, applied to a kind of failure (a hardware fault from
  // executing corrupted or unexpected machine code) that none of the
  // earlier phases needed to handle, because none of them executed native
  // code the project didn't fully control the shape of ahead of time.
  //
  // THREAD-SAFETY: on the POSIX test-harness path, concurrent calls to
  // Call() (on this or any other ExecutableMemoryRegion instance) are
  // serialized internally via a mutex guarding the process-wide signal
  // handler install/restore sequence -- see executable_memory.cpp's
  // g_signal_handler_mutex comment for the exact race this closes.
  // Concurrent calls are therefore safe but NOT concurrent (a second
  // thread's Call() blocks until the first's signal-handler
  // install/call/restore sequence completes); this is a real, deliberate
  // throughput cost traded for correctness, appropriate for an
  // experimental module that was not designed for a hot, highly
  // concurrent call path in the first place.
  CallResult Call(std::int64_t arg) const;

 private:
  ExecutableMemoryRegion(void* mem, std::size_t size);

  // Frees the underlying OS mapping (if any) and resets this object to
  // the empty state, WITHOUT ending the object's lifetime -- unlike
  // calling the destructor directly (which the move-assignment operator
  // used to do; see executable_memory.cpp's comment on why that was
  // fixed). Called from both the destructor and move-assignment, so
  // there is exactly one place that frees this object's resource, used
  // consistently from every path that needs to.
  void ReleaseResources();

  void* mem_ = nullptr;
  std::size_t size_ = 0;
};

}  // namespace rtprotect::runtime
