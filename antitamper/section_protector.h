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
// Calls VirtualProtect via hashed dynamic resolution, decrypts section data via AES-256-CTR,
// verifies integrity checksum, restores memory protection, and cleanses key material.
bool DecryptProtectedSectionInMemory(const tooling::PeProtectedSectionHeader& header, void* module_base = nullptr);

// Complete runtime initialization: finds header and decrypts all protected sections
bool InitializeProtectedBinary(void* module_base = nullptr);

}  // namespace rtprotect::antitamper
