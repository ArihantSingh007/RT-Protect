// bytecode_vm/opcode.h
//
// Instruction set for the rtprotect bytecode VM (Phase 3).
//
// Design goals (see docs/ARCHITECTURE.md Phase 3 section for rationale):
//   - Small, closed, explicitly enumerated instruction set -- no "escape
//     hatch" opcode that calls arbitrary native code or memory addresses.
//   - Fixed-width operands per opcode, decoded by a verifier pass before
//     any execution (bytecode_vm/verifier.h) so the interpreter itself
//     never needs to re-validate during a hot loop.
//   - 64-bit signed integer as the only value type. This VM is scoped to
//     protecting small numeric/logic functions (e.g. license/entitlement
//     checks, checksum-style validation) -- it is explicitly NOT a
//     general-purpose language VM. See docs/THREAT_MODEL.md for what
//     "protecting" a function in this VM does and does not achieve.
//
// Encoding: one opcode byte, followed by zero or more operand bytes
// (little-endian), per the table below.

#pragma once

#include <cstdint>

namespace rtprotect::vm {

enum class Opcode : std::uint8_t {
  // --- stack manipulation ---
  kPushConst = 0x01,  // operand: u16 constant-pool index. Pushes constants[idx].
  kPushLocal = 0x02,  // operand: u8 local index. Pushes locals[idx].
  kStoreLocal = 0x03, // operand: u8 local index. Pops top, stores into locals[idx].
  kDup = 0x04,        // no operand. Duplicates top of stack.
  kPop = 0x05,        // no operand. Discards top of stack.

  // --- arithmetic (pop b, pop a, push a OP b) ---
  kAdd = 0x10,
  kSub = 0x11,
  kMul = 0x12,
  kDiv = 0x13,  // integer division; division by zero is a runtime fault (see VmError)
  kMod = 0x14,  // modulo by zero is a runtime fault

  // --- bitwise (pop b, pop a, push a OP b) ---
  kAnd = 0x20,
  kOr = 0x21,
  kXor = 0x22,
  kNot = 0x23,  // unary: pop a, push ~a

  // --- comparison (pop b, pop a, push 1 or 0) ---
  kCmpEq = 0x30,
  kCmpLt = 0x31,
  kCmpGt = 0x32,

  // --- control flow ---
  kJmp = 0x40,  // operand: u16 absolute byte offset into code. Unconditional jump.
  kJz = 0x41,   // operand: u16 absolute byte offset. Pop a; jump if a == 0.
  kJnz = 0x42,  // operand: u16 absolute byte offset. Pop a; jump if a != 0.

  // --- termination ---
  kRet = 0x50,  // no operand. Pop a, halt execution, a is the function's result.

  // --- memory operations ---
  kLoadMem8 = 0x60,   // no operand. Pop addr; push (uint64_t)memory[addr].
  kStoreMem8 = 0x61,  // no operand. Pop val, pop addr; memory[addr] = (uint8_t)val.
  kLoadMem64 = 0x62,  // no operand. Pop addr; push 64-bit int from memory[addr..addr+7].
  kStoreMem64 = 0x63, // no operand. Pop val, pop addr; memory[addr..addr+7] = (uint64_t)val.

  // --- subroutines & cross-function calls ---
  kCall = 0x70,         // operand: u16 absolute byte offset. Push return_pc to call_stack; jump to target.
  kRetSub = 0x71,       // no operand. Pop return_pc from call_stack; jump to return_pc.
  kCallProgram = 0x72,  // operand: u16 program ID in ProgramRegistry. Invoke registered Program.
  kCallNative = 0x73,   // operand: u16 native function ID in NativeFunctionTable. Safe FFI boundary.

  // --- floating point (IEEE-754 64-bit double precision) ---
  kFAdd = 0x80,        // pop b, pop a, push (double)a + (double)b
  kFSub = 0x81,        // pop b, pop a, push (double)a - (double)b
  kFMul = 0x82,        // pop b, pop a, push (double)a * (double)b
  kFDiv = 0x83,        // pop b, pop a, push (double)a / (double)b
  kFCmpEq = 0x84,      // pop b, pop a, push (double)a == (double)b ? 1 : 0
  kFCmpLt = 0x85,      // pop b, pop a, push (double)a < (double)b ? 1 : 0
  kFCmpGt = 0x86,      // pop b, pop a, push (double)a > (double)b ? 1 : 0
  kIntToFloat = 0x87,  // pop int64_t a, push (double)a bitcast
  kFloatToInt = 0x88,  // pop (double)a bitcast, push (int64_t)a

  // --- polymorphic inert opcodes (per-build inert operations) ---
  kInertNop1 = 0x90,   // no operand. Inert NOP specific to current opcode permutation.
  kInertNop2 = 0x91,   // no operand. Inert NOP.
  kInertNop3 = 0x92,   // no operand. Inert NOP.
};

// Returns the number of operand bytes following the opcode byte (0, 1, or 2).
// Returns -1 for a byte that is not a recognized opcode, which the verifier
// treats as a hard rejection (see verifier.h: kInvalidOpcode).
inline int OperandBytes(Opcode op) {
  switch (op) {
    case Opcode::kPushConst:
    case Opcode::kJmp:
    case Opcode::kJz:
    case Opcode::kJnz:
    case Opcode::kCall:
    case Opcode::kCallProgram:
    case Opcode::kCallNative:
      return 2;
    case Opcode::kPushLocal:
    case Opcode::kStoreLocal:
      return 1;
    case Opcode::kDup:
    case Opcode::kPop:
    case Opcode::kAdd:
    case Opcode::kSub:
    case Opcode::kMul:
    case Opcode::kDiv:
    case Opcode::kMod:
    case Opcode::kAnd:
    case Opcode::kOr:
    case Opcode::kXor:
    case Opcode::kNot:
    case Opcode::kCmpEq:
    case Opcode::kCmpLt:
    case Opcode::kCmpGt:
    case Opcode::kRet:
    case Opcode::kLoadMem8:
    case Opcode::kStoreMem8:
    case Opcode::kLoadMem64:
    case Opcode::kStoreMem64:
    case Opcode::kRetSub:
    case Opcode::kFAdd:
    case Opcode::kFSub:
    case Opcode::kFMul:
    case Opcode::kFDiv:
    case Opcode::kFCmpEq:
    case Opcode::kFCmpLt:
    case Opcode::kFCmpGt:
    case Opcode::kIntToFloat:
    case Opcode::kFloatToInt:
    case Opcode::kInertNop1:
    case Opcode::kInertNop2:
    case Opcode::kInertNop3:
      return 0;
  }
  return -1;
}

inline bool IsValidOpcode(std::uint8_t byte) {
  switch (static_cast<Opcode>(byte)) {
    case Opcode::kPushConst: case Opcode::kPushLocal: case Opcode::kStoreLocal:
    case Opcode::kDup: case Opcode::kPop:
    case Opcode::kAdd: case Opcode::kSub: case Opcode::kMul: case Opcode::kDiv: case Opcode::kMod:
    case Opcode::kAnd: case Opcode::kOr: case Opcode::kXor: case Opcode::kNot:
    case Opcode::kCmpEq: case Opcode::kCmpLt: case Opcode::kCmpGt:
    case Opcode::kJmp: case Opcode::kJz: case Opcode::kJnz:
    case Opcode::kRet:
    case Opcode::kLoadMem8: case Opcode::kStoreMem8:
    case Opcode::kLoadMem64: case Opcode::kStoreMem64:
    case Opcode::kCall: case Opcode::kRetSub: case Opcode::kCallProgram: case Opcode::kCallNative:
    case Opcode::kFAdd: case Opcode::kFSub: case Opcode::kFMul: case Opcode::kFDiv:
    case Opcode::kFCmpEq: case Opcode::kFCmpLt: case Opcode::kFCmpGt:
    case Opcode::kIntToFloat: case Opcode::kFloatToInt:
    case Opcode::kInertNop1: case Opcode::kInertNop2: case Opcode::kInertNop3:
      return true;
  }
  return false;
}

}  // namespace rtprotect::vm
