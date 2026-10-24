// antitamper/section_protector.h
//
// Runtime Binary-Level In-Memory Section Decryption & Initialization Engine.
// Executes before application entry point (or during early startup) to dynamically
// decrypt code sections encrypted by PeProtector, using hashed API resolution
// to eliminate static imports for memory protection primitives.

#pragma once

#include <cstddef>
#include <cstdint>

#include "tooling/pe_protector.h"

namespace rtprotect::antitamper {

// Locates the embedded PeProtectedSectionHeader in the loaded module
const tooling::PeProtectedSectionHeader* FindProtectedSectionHeader(const void* module_base = nullptr);

// In-memory runtime section decryption
// Calls VirtualProtect via hashed dynamic resolution, authenticates/decrypts section data via AES-256-GCM,
// verifies integrity checksum, restores memory protection, and cleanses key material.
bool DecryptProtectedSectionInMemory(const tooling::PeProtectedSectionHeader& header, void* module_base = nullptr);

// In-memory runtime section re-encryption and protection revocation.
// Re-encrypts code in RAM and sets memory page protection to PAGE_NOACCESS when execution is idle.
bool EncryptProtectedSectionInMemory(const tooling::PeProtectedSectionHeader& header, void* module_base = nullptr);

// Anti-Dump Scoped Section Execution:
// Dynamically decrypts protected section code upon scope entry,
// maintains a thread-safe reference count across concurrent calling threads,
// and automatically re-encrypts and revokes execution permissions when the scope exits.
class ScopedSectionExecution {
 public:
  explicit ScopedSectionExecution(const tooling::PeProtectedSectionHeader* header = nullptr, void* module_base = nullptr);
  ~ScopedSectionExecution();

  bool IsValid() const { return active_; }

  ScopedSectionExecution(const ScopedSectionExecution&) = delete;
  ScopedSectionExecution& operator=(const ScopedSectionExecution&) = delete;

  ScopedSectionExecution(ScopedSectionExecution&& other) noexcept;
  ScopedSectionExecution& operator=(ScopedSectionExecution&& other) noexcept;

 private:
  const tooling::PeProtectedSectionHeader* header_ = nullptr;
  void* module_base_ = nullptr;
  bool active_ = false;
};

// Complete runtime initialization: finds header and decrypts all protected sections
bool InitializeProtectedBinary(void* module_base = nullptr);

}  // namespace rtprotect::antitamper
