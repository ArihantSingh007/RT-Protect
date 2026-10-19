// fuzz/fuzz_manifest_deserialize.cpp
//
// libFuzzer harness for integrity::DeserializeManifest(), the entry point
// for untrusted bytes becoming a Manifest -- exactly the function an
// attacker-controlled manifest file would be parsed with. See this
// directory's README.md for build instructions, and for why these
// harnesses have NOT been executed in this project's current development
// environment (no clang/libFuzzer available here -- see that file for the
// exact gap and what running this for real would need).
//
// What a finding here would mean: any crash, hang, or sanitizer report
// found by running this harness represents a way a malicious or corrupted
// manifest file could crash or hang a process that calls
// DeserializeManifest() on untrusted input -- which is exactly how this
// function is used (see integrity/verifier.h's VerifyAndCheckResource()).

#include <cstdint>
#include <cstddef>

#include "integrity/manifest.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  auto result = rtprotect::integrity::DeserializeManifest(data, size);
  // No further action needed -- DeserializeManifest() either returns a
  // parsed Manifest or std::nullopt; libFuzzer's instrumentation (ASan/
  // UBSan, if built with -fsanitize=fuzzer,address,undefined per this
  // directory's README) is what would catch a crash, hang, or sanitizer
  // violation during the call itself.
  (void)result;
  return 0;
}
