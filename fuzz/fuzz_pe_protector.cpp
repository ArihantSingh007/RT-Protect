// fuzz/fuzz_pe_protector.cpp
//
// libFuzzer harness for tooling::PeProtector, the entry point for
// parsing, validating, and transforming PE64 executables.
//
// What a finding here would mean: any crash, hang, integer overflow, or
// out-of-bounds read/write discovered by running this harness represents a
// parser flaw in handling malformed PE headers or corrupted binary payloads.

#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <vector>

#include "tooling/pe_protector.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size == 0 || size > 16 * 1024 * 1024) {
    return 0; // Cap to 16MB to prevent out-of-memory in fuzz runner
  }

  std::vector<std::uint8_t> buffer(data, data + size);

  // 1. Fuzz PE validity inspection
  bool valid = rtprotect::tooling::PeProtector::IsValidPe64(buffer);

  // 2. Fuzz memory protection transformations
  rtprotect::tooling::PeProtectionOptions options;
  options.target_section = ".text";
  options.encrypt_section = true;
  options.obfuscate_imports = true;

  rtprotect::tooling::PeProtectionResult result;
  rtprotect::tooling::PeProtector::ProtectMemory(buffer, options, &result);

  // Invariant: if IsValidPe64 rejected the buffer, ProtectMemory must not succeed
  if (!valid && result.success) {
    std::abort();
  }

  return 0;
}
