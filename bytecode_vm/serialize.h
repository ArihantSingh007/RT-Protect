// bytecode_vm/serialize.h
//
// Turns a Program into a flat byte buffer (and back) so it can be
// encrypted at rest with crypto::Encrypt and decrypted immediately before
// execution. Deserialize() performs only structural/length validation
// (enough to avoid reading out of bounds while parsing) -- it does NOT
// replace bytecode_vm::VerifyProgram, which callers must still run on the
// result before executing it. Treat anything that came through
// Deserialize() as untrusted input until VerifyProgram has accepted it.

#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "bytecode_vm/program.h"

namespace rtprotect::vm {

std::vector<std::uint8_t> Serialize(const Program& program);

std::optional<Program> Deserialize(const std::uint8_t* data, std::size_t len);

}  // namespace rtprotect::vm
