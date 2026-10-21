// bytecode_vm/opcode_map.cpp

#include "bytecode_vm/opcode_map.h"

#include <numeric>
#include <vector>

namespace rtprotect::vm {

namespace {

const std::vector<Opcode>& AllOpcodes() {
  static const std::vector<Opcode> opcodes = {
    Opcode::kPushConst,
    Opcode::kPushLocal,
    Opcode::kStoreLocal,
    Opcode::kDup,
    Opcode::kPop,
    Opcode::kAdd,
    Opcode::kSub,
    Opcode::kMul,
    Opcode::kDiv,
    Opcode::kMod,
    Opcode::kAnd,
    Opcode::kOr,
    Opcode::kXor,
    Opcode::kNot,
    Opcode::kCmpEq,
    Opcode::kCmpLt,
    Opcode::kCmpGt,
    Opcode::kJmp,
    Opcode::kJz,
    Opcode::kJnz,
    Opcode::kRet,
    Opcode::kLoadMem8,
    Opcode::kStoreMem8,
    Opcode::kLoadMem64,
    Opcode::kStoreMem64,
    Opcode::kCall,
    Opcode::kRetSub
  };
  return opcodes;
}

}  // namespace

OpcodeMap::OpcodeMap() {
  byte_to_opcode_.fill(-1);
  for (Opcode op : AllOpcodes()) {
    std::uint8_t default_byte = static_cast<std::uint8_t>(op);
    opcode_to_byte_[default_byte] = default_byte;
    byte_to_opcode_[default_byte] = static_cast<std::int16_t>(default_byte);
  }
}

OpcodeMap OpcodeMap::FromSeed(std::uint32_t seed) {
  OpcodeMap map;
  map.byte_to_opcode_.fill(-1);

  // Deterministic LCG
  auto next_rand = [&seed]() -> std::uint32_t {
    seed = seed * 1664525u + 1013904223u;
    return seed;
  };

  const auto& opcodes = AllOpcodes();
  std::vector<std::uint8_t> pool(250);
  for (std::size_t i = 0; i < pool.size(); ++i) {
    pool[i] = static_cast<std::uint8_t>(i + 1); // 1..250
  }

  // Fisher-Yates shuffle
  for (std::size_t i = pool.size() - 1; i > 0; --i) {
    std::size_t j = next_rand() % (i + 1);
    std::swap(pool[i], pool[j]);
  }

  for (std::size_t i = 0; i < opcodes.size(); ++i) {
    Opcode op = opcodes[i];
    std::uint8_t permuted_byte = pool[i];
    std::uint8_t op_index = static_cast<std::uint8_t>(op);

    map.opcode_to_byte_[op_index] = permuted_byte;
    map.byte_to_opcode_[permuted_byte] = static_cast<std::int16_t>(op_index);
  }

  return map;
}

std::uint8_t OpcodeMap::Encode(Opcode op) const {
  std::uint8_t idx = static_cast<std::uint8_t>(op);
  return opcode_to_byte_[idx];
}

std::optional<Opcode> OpcodeMap::Decode(std::uint8_t byte) const {
  std::int16_t op_val = byte_to_opcode_[byte];
  if (op_val < 0) return std::nullopt;
  return static_cast<Opcode>(op_val);
}

bool OpcodeMap::IsValidByte(std::uint8_t byte) const {
  return byte_to_opcode_[byte] >= 0;
}

int OpcodeMap::OperandBytes(std::uint8_t byte) const {
  auto op = Decode(byte);
  if (!op.has_value()) return -1;
  return rtprotect::vm::OperandBytes(*op);
}

std::optional<Program> RemapProgramOpcodes(const Program& prog,
                                           const OpcodeMap& src_map,
                                           const OpcodeMap& dst_map) {
  Program out = prog;
  out.code.clear();
  std::size_t pc = 0;
  while (pc < prog.code.size()) {
    std::uint8_t src_byte = prog.code[pc];
    auto op = src_map.Decode(src_byte);
    if (!op.has_value()) return std::nullopt;
    out.code.push_back(dst_map.Encode(*op));
    int operand_len = src_map.OperandBytes(src_byte);
    if (operand_len < 0 || pc + 1 + static_cast<std::size_t>(operand_len) > prog.code.size()) {
      return std::nullopt;
    }
    for (int i = 0; i < operand_len; ++i) {
      out.code.push_back(prog.code[pc + 1 + i]);
    }
    pc += 1 + operand_len;
  }
  return out;
}

}  // namespace rtprotect::vm
