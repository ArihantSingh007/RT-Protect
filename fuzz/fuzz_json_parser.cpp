// fuzz/fuzz_json_parser.cpp
//
// libFuzzer harness for tooling::JsonValue::Parse(), parsing untrusted JSON inputs.
//
// What a finding here would mean: any crash, hang, stack overflow, or memory
// corruption during JSON deserialization (used for Clang AST analysis and
// integration journal processing) represents an untrusted-input parser flaw.

#include <cstdint>
#include <cstddef>
#include <string_view>

#include "tooling/simple_json.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size > 1024 * 1024) return 0; // Cap to 1MB

  std::string_view sv(reinterpret_cast<const char*>(data), size);
  auto parsed = rtprotect::tooling::JsonValue::Parse(sv);
  (void)parsed;
  return 0;
}
