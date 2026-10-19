// bytecode_vm/program.h
//
// A Program is the unit of data this VM executes: a byte-code stream plus
// its constant pool and declared local-variable count. Programs are small
// and fully self-contained (no imports, no external calls) by design --
// see opcode.h's design goals.

#pragma once

#include <cstdint>
#include <vector>

namespace rtprotect::vm {

inline constexpr std::size_t kMaxLocals = 32;
inline constexpr std::size_t kMaxConstants = 1024;
inline constexpr std::size_t kMaxCodeBytes = 8192;
// Declared here (not in vm.h, where this constant conceptually "belongs"
// as a VM runtime limit) specifically so bytecode_vm/verifier.cpp can use
// it for the static stack-depth-overflow check without creating a
// circular header dependency: vm.h already includes verifier.h (to call
// VerifyProgram), so verifier.cpp including vm.h back would invert that
// layering. program.h sits below both and both already include it.
inline constexpr std::size_t kMaxStackDepth = 64;

struct Program {
  std::vector<std::uint8_t> code;
  std::vector<std::int64_t> constants;
  std::uint8_t num_locals = 0;  // locals[0..num_locals) are valid indices
};

}  // namespace rtprotect::vm
