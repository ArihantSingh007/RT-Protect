// fuzz/fuzz_source_scanner.cpp
//
// libFuzzer harness for tooling::TransformSourceFile(), the lexical and AST
// source transformation scanner that parses and virtualizes user source code.
// Tests robustness against malformed strings, unmatched braces, weird macros,
// raw string literals, and adversarial syntax patterns.

#include <cstdint>
#include <cstddef>
#include <array>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "tooling/integration_engine.h"
#include "integrity/keys.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  // Cap max source size for fast fuzz iterations
  if (size > 65536) return 0;

  auto temp_dir = std::filesystem::temp_directory_path();
  auto temp_file = temp_dir / ("rtprotect_fuzz_src_" + std::to_string(reinterpret_cast<std::uintptr_t>(data)) + ".cpp");

  {
    std::ofstream out(temp_file, std::ios::binary);
    if (!out) return 0;
    out.write(reinterpret_cast<const char*>(data), size);
  }

  std::array<std::uint8_t, 32> vm_root{};
  rtprotect::integrity::Ed25519PublicKey pubkey{};
  std::vector<std::string> virtualized;
  std::size_t obf_count = 0;
  std::size_t scatt_count = 0;

  rtprotect::tooling::TransformSourceFile(
      temp_file,
      rtprotect::tooling::ProtectionProfile::kMaximum,
      1337,
      vm_root,
      pubkey,
      "fuzz_test_product",
      virtualized,
      obf_count,
      scatt_count);

  std::error_code ec;
  std::filesystem::remove(temp_file, ec);

  return 0;
}
