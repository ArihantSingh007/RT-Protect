// bytecode_vm/builder.h
//
// A small fluent builder for constructing bytecode_vm::Program instances in
// C++ source instead of hand-encoding raw bytes. This is NOT a compiler --
// there is no parser, no source language. It exists because Phase 3's scope
// is "protect one demonstrative function" and hand-encoding that function's
// bytecode as a raw byte array would be unreadable and error-prone to
// review. A real front-end (parsing a small expression language, or a
// compiler pass emitting this bytecode from existing C++) is explicitly
// future work -- see docs/ARCHITECTURE.md.
//
// Label-based jumps: call Label() to get a forward-reference token, Mark()
// to bind it to the current position, and Jmp/Jz/Jnz with the token. Build()
// patches all jump operands after the full instruction stream is known.

#pragma once

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <unordered_map>
#include <vector>

#include "bytecode_vm/opcode.h"
#include "bytecode_vm/opcode_map.h"
#include "bytecode_vm/program.h"

namespace rtprotect::vm {

class ProgramBuilder {
 public:
  explicit ProgramBuilder(std::uint8_t num_locals, const OpcodeMap* opcode_map = nullptr)
      : num_locals_(num_locals), opcode_map_(opcode_map) {}

  using Label = int;

  Label NewLabel() {
    labels_.push_back(Position::kUnbound);
    return static_cast<Label>(labels_.size() - 1);
  }

  void Mark(Label l) { labels_[l] = code_.size(); }

  std::uint16_t AddConstant(std::int64_t v) {
    constants_.push_back(v);
    if (constants_.size() > kMaxConstants) {
      throw std::length_error("ProgramBuilder: too many constants");
    }
    return static_cast<std::uint16_t>(constants_.size() - 1);
  }

  void PushConst(std::int64_t v) { EmitU16(Opcode::kPushConst, AddConstant(v)); }
  void PushLocal(std::uint8_t idx) { EmitU8(Opcode::kPushLocal, idx); }
  void StoreLocal(std::uint8_t idx) { EmitU8(Opcode::kStoreLocal, idx); }
  void Dup() { EmitNoOperand(Opcode::kDup); }
  void Pop() { EmitNoOperand(Opcode::kPop); }

  void Add() { EmitNoOperand(Opcode::kAdd); }
  void Sub() { EmitNoOperand(Opcode::kSub); }
  void Mul() { EmitNoOperand(Opcode::kMul); }
  void Div() { EmitNoOperand(Opcode::kDiv); }
  void Mod() { EmitNoOperand(Opcode::kMod); }
  void BitAnd() { EmitNoOperand(Opcode::kAnd); }
  void BitOr() { EmitNoOperand(Opcode::kOr); }
  void BitXor() { EmitNoOperand(Opcode::kXor); }
  void BitNot() { EmitNoOperand(Opcode::kNot); }
  void CmpEq() { EmitNoOperand(Opcode::kCmpEq); }
  void CmpLt() { EmitNoOperand(Opcode::kCmpLt); }
  void CmpGt() { EmitNoOperand(Opcode::kCmpGt); }

  void Jmp(Label l) { EmitJumpPlaceholder(Opcode::kJmp, l); }
  void Jz(Label l) { EmitJumpPlaceholder(Opcode::kJz, l); }
  void Jnz(Label l) { EmitJumpPlaceholder(Opcode::kJnz, l); }
  void Ret() { EmitNoOperand(Opcode::kRet); }

  void LoadMem8() { EmitNoOperand(Opcode::kLoadMem8); }
  void StoreMem8() { EmitNoOperand(Opcode::kStoreMem8); }
  void LoadMem64() { EmitNoOperand(Opcode::kLoadMem64); }
  void StoreMem64() { EmitNoOperand(Opcode::kStoreMem64); }
  void Call(Label l) { EmitJumpPlaceholder(Opcode::kCall, l); }
  void RetSub() { EmitNoOperand(Opcode::kRetSub); }

  void FAdd() { EmitNoOperand(Opcode::kFAdd); }
  void FSub() { EmitNoOperand(Opcode::kFSub); }
  void FMul() { EmitNoOperand(Opcode::kFMul); }
  void FDiv() { EmitNoOperand(Opcode::kFDiv); }
  void FCmpEq() { EmitNoOperand(Opcode::kFCmpEq); }
  void FCmpLt() { EmitNoOperand(Opcode::kFCmpLt); }
  void FCmpGt() { EmitNoOperand(Opcode::kFCmpGt); }
  void IntToFloat() { EmitNoOperand(Opcode::kIntToFloat); }
  void FloatToInt() { EmitNoOperand(Opcode::kFloatToInt); }
  void PushFloat(double d) {
    std::uint64_t bits = 0;
    std::memcpy(&bits, &d, sizeof(bits));
    PushConst(static_cast<std::int64_t>(bits));
  }
  void CallProgram(std::uint16_t program_id) {
    EmitU16(Opcode::kCallProgram, program_id);
  }
  void CallNative(std::uint16_t native_id) {
    EmitU16(Opcode::kCallNative, native_id);
  }
  void InertNop1() { EmitNoOperand(Opcode::kInertNop1); }
  void InertNop2() { EmitNoOperand(Opcode::kInertNop2); }
  void InertNop3() { EmitNoOperand(Opcode::kInertNop3); }

  Program Build() {
    // Patch every jump placeholder now that all labels are bound.
    for (const auto& [code_offset, label] : jump_fixups_) {
      std::size_t target = labels_[label];
      if (target == Position::kUnbound) {
        throw std::logic_error("ProgramBuilder: jump to unbound label");
      }
      code_[code_offset] = static_cast<std::uint8_t>(target & 0xFF);
      code_[code_offset + 1] = static_cast<std::uint8_t>((target >> 8) & 0xFF);
    }
    Program p;
    p.code = code_;
    p.constants = constants_;
    p.num_locals = num_locals_;
    return p;
  }

 private:
  struct Position { static constexpr std::size_t kUnbound = SIZE_MAX; };

  std::uint8_t EncodeOp(Opcode op) const {
    return opcode_map_ ? opcode_map_->Encode(op) : static_cast<std::uint8_t>(op);
  }

  void EmitNoOperand(Opcode op) { code_.push_back(EncodeOp(op)); }

  void EmitU8(Opcode op, std::uint8_t operand) {
    code_.push_back(EncodeOp(op));
    code_.push_back(operand);
  }

  void EmitU16(Opcode op, std::uint16_t operand) {
    code_.push_back(EncodeOp(op));
    code_.push_back(static_cast<std::uint8_t>(operand & 0xFF));
    code_.push_back(static_cast<std::uint8_t>((operand >> 8) & 0xFF));
  }

  void EmitJumpPlaceholder(Opcode op, Label l) {
    code_.push_back(EncodeOp(op));
    jump_fixups_.push_back({code_.size(), l});
    code_.push_back(0);  // patched in Build()
    code_.push_back(0);
  }

  std::uint8_t num_locals_;
  const OpcodeMap* opcode_map_ = nullptr;
  std::vector<std::uint8_t> code_;
  std::vector<std::int64_t> constants_;
  std::vector<std::size_t> labels_;  // label -> bound position, or kUnbound
  std::vector<std::pair<std::size_t, Label>> jump_fixups_;  // (operand offset, label)
};

}  // namespace rtprotect::vm
