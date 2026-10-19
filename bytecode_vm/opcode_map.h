// bytecode_vm/opcode_map.h
//
// Build-seeded and profile-configurable opcode permutation tables.
//
// Decouples physical bytecode representation from logical Opcode semantics.
// A distinct per-build seed scrambles the byte mapping, forcing an adversary
// to reverse the substitution table independently for each protected application build.

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

#include "bytecode_vm/opcode.h"

namespace rtprotect::vm {

class OpcodeMap {
 public:
  // Constructs the default (canonical identity) mapping.
  OpcodeMap();

  // Constructs a deterministic pseudo-random permutation from a 32-bit build seed.
  static OpcodeMap FromSeed(std::uint32_t seed);

  // Encodes a logical Opcode into its physical byte.
  std::uint8_t Encode(Opcode op) const;

  // Decodes a physical byte back to its logical Opcode. Returns nullopt if byte is unrecognized.
  std::optional<Opcode> Decode(std::uint8_t byte) const;

  // Returns true if the byte is valid in this mapping.
  bool IsValidByte(std::uint8_t byte) const;

  // Returns the operand byte length for the given physical byte. Returns -1 if invalid.
  int OperandBytes(std::uint8_t byte) const;

 private:
  std::array<std::uint8_t, 256> opcode_to_byte_{};
  std::array<std::int16_t, 256> byte_to_opcode_{};  // -1 if unmapped
};

}  // namespace rtprotect::vm
