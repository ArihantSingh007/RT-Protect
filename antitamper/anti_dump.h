// antitamper/anti_dump.h
//
// In-Memory Anti-Dumping and Ephemeral Code Protection.
//
// Protects decrypted routines and in-memory executable structures against
// process dumping tools (Scylla, ProcDump, Cheat Engine, MiniDumpWriteDump)
// and memory scanning probes.
//
// Features:
// 1. Memory Dumper Detection: detects dbghelp.dll / MiniDumpWriteDump probes
//    and suspicious memory-dumping modules.
// 2. Memory Probing Detection: detects inline hooks on memory query functions.
// 3. Process Header Erasure: wipes PE DOS/NT headers in memory at runtime to
//    prevent automatic section rebuilding by dumping tools.
// 4. Ephemeral Execution Guard: guarantees decrypted code memory is zeroed
//    with OPENSSL_cleanse and deallocated immediately upon routine completion.

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <vector>

namespace rtprotect::antitamper {

// Detects if a known memory dumper module (e.g. dbghelp.dll / MiniDumpWriteDump,
// Scylla, Cheat Engine, ProcDump) is currently present or loaded in the process.
bool DetectMemoryDumper();

// Detects if memory scanning APIs (e.g. VirtualQuery) have been hooked or probed.
bool DetectMemoryProbing();

// Erases the process PE DOS and NT headers in memory to prevent reconstruction
// of PE sections and entry points by dumping tools.
// Returns true if headers were successfully scrubbed.
bool EraseProcessHeaders();

// RAII Guard that manages an ephemeral executable memory buffer.
// The code is decrypted / loaded into temporary memory, executed, and
// instantly scrubbed with OPENSSL_cleanse upon destruction.
class EphemeralExecutionGuard {
 public:
  EphemeralExecutionGuard();
  ~EphemeralExecutionGuard();

  EphemeralExecutionGuard(const EphemeralExecutionGuard&) = delete;
  EphemeralExecutionGuard& operator=(const EphemeralExecutionGuard&) = delete;
  EphemeralExecutionGuard(EphemeralExecutionGuard&& other) noexcept;
  EphemeralExecutionGuard& operator=(EphemeralExecutionGuard&& other) noexcept;

  // Allocates an ephemeral page, copies payload bytes, transitions to RX,
  // invokes the callable function, and immediately cleanses the buffer.
  // Returns the 64-bit integer return value of the function.
  bool ExecuteEphemeral(const std::uint8_t* code_bytes,
                        std::size_t code_size,
                        std::int64_t arg,
                        std::int64_t* out_result);

  bool IsAllocated() const { return memory_ != nullptr; }

 private:
  void Cleanup();

  void* memory_ = nullptr;
  std::size_t allocated_size_ = 0;
};

}  // namespace rtprotect::antitamper
