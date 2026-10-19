// examples/checksum_program.h
//
// Constructs the bytecode_vm::Program that implements the same algorithm as
// checksum_reference.h's NativeChecksum, using bytecode_vm::ProgramBuilder.
// This is the actual "protected function" for Phase 3: its logic is only
// ever present as bytecode (optionally encrypted at rest -- see
// protected_checksum.h), never as native machine code implementing the
// checksum itself.
//
// Locals: [0] = x (argument, mutated as a loop counter)
//         [1] = acc (running checksum)
//         [2] = digit (scratch)

#pragma once

#include "bytecode_vm/builder.h"
#include "bytecode_vm/program.h"

namespace rtprotect::examples {

inline rtprotect::vm::Program BuildChecksumProgram() {
  using rtprotect::vm::ProgramBuilder;

  ProgramBuilder b(/*num_locals=*/3);
  auto loop = b.NewLabel();
  auto end = b.NewLabel();

  b.Mark(loop);
  b.PushLocal(0);        // x
  b.Jz(end);              // if (x == 0) goto end;  (pops x)

  b.PushLocal(0);        // x
  b.PushConst(10);
  b.Mod();                // x % 10
  b.StoreLocal(2);        // digit = x % 10

  b.PushLocal(1);        // acc
  b.PushConst(31);
  b.Mul();                // acc * 31
  b.PushLocal(2);        // digit
  b.Add();                // acc * 31 + digit
  b.PushConst(1000000007);
  b.Mod();                // (acc * 31 + digit) % 1000000007
  b.StoreLocal(1);        // acc = ...

  b.PushLocal(0);        // x
  b.PushConst(10);
  b.Div();                // x / 10
  b.StoreLocal(0);        // x = x / 10

  b.Jmp(loop);

  b.Mark(end);
  b.PushLocal(1);        // acc
  b.Ret();

  return b.Build();
}

}  // namespace rtprotect::examples
