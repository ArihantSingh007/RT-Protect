// bytecode_vm/program_registry.h
//
// Registry for cross-function inter-program calls within the bytecode VM.
// Allows virtualized Program instances to invoke other virtualized Programs
// directly on the VM stack without crossing native call boundaries.

#pragma once

#include <cstdint>
#include <mutex>
#include <unordered_map>

#include "bytecode_vm/program.h"

namespace rtprotect::vm {

class ProgramRegistry {
 public:
  static void Register(std::uint16_t id, Program program);
  static const Program* Get(std::uint16_t id);
  static void Clear();
};

}  // namespace rtprotect::vm
