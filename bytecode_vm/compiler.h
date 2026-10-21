// bytecode_vm/compiler.h
//
// Lightweight C-subset to RTProtect Bytecode VM compiler.
//
// Translates C functions with arithmetic, bitwise operators, local variables,
// memory indexing (load/store), conditionals (if/else), loops (while), and
// return statements into an authenticated, verified Program instance.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "bytecode_vm/opcode_map.h"
#include "bytecode_vm/program.h"

namespace rtprotect::vm {

struct CompilerOptions {
  std::uint8_t max_locals = 32;
  bool optimize = true;
  const OpcodeMap* opcode_map = nullptr;
};

// Compiles a single C-subset function or statement block into a Program.
//
// Supported syntax:
//   - Functions: int64_t name(int64_t a, int64_t b, ...) { ... }
//   - Variable declarations: int64_t x = <expr>;
//   - Assignments: x = <expr>;
//   - Control flow: if (cond) { ... } else { ... }, while (cond) { ... }
//   - Memory accesses: load8(addr), store8(addr, val), load64(addr), store64(addr, val)
//   - Expressions: +, -, *, /, %, &, |, ^, ~, ==, !=, <, <=, >, >=, &&, ||, ()
//   - Return: return <expr>;
//
// Returns std::nullopt on syntax error and populates out_error if non-null.
std::optional<Program> CompileCSubset(const std::string& source,
                                      std::string* out_error = nullptr,
                                      const CompilerOptions& options = {});

}  // namespace rtprotect::vm
