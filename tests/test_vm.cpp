#include "bytecode_vm/builder.h"
#include "bytecode_vm/compiler.h"
#include "bytecode_vm/serialize.h"
#include "bytecode_vm/vm.h"

#include "tests/micro_test.h"

using namespace rtprotect::vm;

namespace {

// Builds the smallest-possible valid program: push a constant, return it.
Program TrivialReturn(std::int64_t v) {
  ProgramBuilder b(0);
  b.PushConst(v);
  b.Ret();
  return b.Build();
}

}  // namespace

// ---------------------------------------------------------------------
// Arithmetic / stack correctness
// ---------------------------------------------------------------------

MT_TEST(Vm_TrivialReturnValue) {
  auto p = TrivialReturn(42);
  auto r = Run(p, {});
  MT_CHECK(r.error == VmError::kNone);
  MT_CHECK(r.value == 42);
}

MT_TEST(Vm_Arithmetic_AddSubMulDivMod) {
  ProgramBuilder b(0);
  b.PushConst(7);
  b.PushConst(3);
  b.Add();          // 10
  b.PushConst(4);
  b.Sub();          // 6
  b.PushConst(5);
  b.Mul();          // 30
  b.PushConst(4);
  b.Div();          // 7
  b.PushConst(3);
  b.Mod();          // 1
  b.Ret();
  auto r = Run(b.Build(), {});
  MT_CHECK(r.error == VmError::kNone);
  MT_CHECK(r.value == 1);
}

MT_TEST(Vm_Bitwise_AndOrXorNot) {
  ProgramBuilder b(0);
  b.PushConst(0b1100);
  b.PushConst(0b1010);
  b.BitAnd();       // 0b1000
  b.PushConst(0b0001);
  b.BitOr();        // 0b1001
  b.PushConst(0b1111);
  b.BitXor();       // 0b0110
  b.BitNot();       // ~6
  b.Ret();
  auto r = Run(b.Build(), {});
  MT_CHECK(r.error == VmError::kNone);
  MT_CHECK(r.value == ~static_cast<std::int64_t>(6));
}

MT_TEST(Vm_Comparisons) {
  ProgramBuilder b(0);
  b.PushConst(5);
  b.PushConst(5);
  b.CmpEq();  // 1
  b.PushConst(3);
  b.PushConst(5);
  b.CmpLt();  // 1
  b.Add();    // 2
  b.PushConst(9);
  b.PushConst(1);
  b.CmpGt();  // 1
  b.Add();    // 3
  b.Ret();
  auto r = Run(b.Build(), {});
  MT_CHECK(r.error == VmError::kNone);
  MT_CHECK(r.value == 3);
}

MT_TEST(Vm_LocalsAndArgs) {
  ProgramBuilder b(2);  // locals[0] = arg, locals[1] = scratch
  b.PushLocal(0);
  b.PushConst(100);
  b.Add();
  b.StoreLocal(1);
  b.PushLocal(1);
  b.Ret();
  auto r = Run(b.Build(), {7});
  MT_CHECK(r.error == VmError::kNone);
  MT_CHECK(r.value == 107);
}

MT_TEST(Vm_DupAndPop) {
  ProgramBuilder b(0);
  b.PushConst(9);
  b.Dup();
  b.Add();  // 18
  b.PushConst(100);
  b.Pop();  // discard the 100
  b.Ret();
  auto r = Run(b.Build(), {});
  MT_CHECK(r.error == VmError::kNone);
  MT_CHECK(r.value == 18);
}

MT_TEST(Vm_LoopWithJmpAndJz_SumOneToN) {
  // locals[0] = n (counter, counts down), locals[1] = acc
  ProgramBuilder b(2);
  auto loop = b.NewLabel();
  auto end = b.NewLabel();

  b.Mark(loop);
  b.PushLocal(0);
  b.Jz(end);
  b.PushLocal(1);
  b.PushLocal(0);
  b.Add();
  b.StoreLocal(1);
  b.PushLocal(0);
  b.PushConst(1);
  b.Sub();
  b.StoreLocal(0);
  b.Jmp(loop);
  b.Mark(end);
  b.PushLocal(1);
  b.Ret();

  auto r = Run(b.Build(), {10});  // sum 1..10 = 55
  MT_CHECK(r.error == VmError::kNone);
  MT_CHECK(r.value == 55);
}

// ---------------------------------------------------------------------
// Runtime fault handling
// ---------------------------------------------------------------------

MT_TEST(Vm_DivisionByZero_IsReportedNotUB) {
  ProgramBuilder b(0);
  b.PushConst(10);
  b.PushConst(0);
  b.Div();
  b.Ret();
  auto r = Run(b.Build(), {});
  MT_CHECK(r.error == VmError::kDivisionByZero);
}

MT_TEST(Vm_ModuloByZero_IsReported) {
  ProgramBuilder b(0);
  b.PushConst(10);
  b.PushConst(0);
  b.Mod();
  b.Ret();
  auto r = Run(b.Build(), {});
  MT_CHECK(r.error == VmError::kDivisionByZero);
}

MT_TEST(Vm_InfiniteLoop_HitsInstructionBudget) {
  // A Jmp-to-itself program with no Ret anywhere. This used to be rejected
  // by an earlier, narrower static check (the old kDoesNotEndInReturn
  // heuristic: "the textually last byte in the code stream must be a
  // Ret"), which happened to catch this specific trivial case but wasn't
  // actually analyzing reachability or control flow -- see
  // verifier.h's kControlFlowFallsOffEnd comment for the full story of
  // why that heuristic was replaced with a real reachability-based
  // analysis (Phase 2 of this project's hardening review, Section 5).
  //
  // Under that real analysis, THIS PROGRAM NOW PASSES STATIC VERIFICATION:
  // there is nothing structurally unsafe about a Jmp whose target is
  // itself -- the stack depth is consistent (0, every time control
  // returns to the same instruction), nothing underflows or overflows,
  // and control flow never runs off the end of the code array. What's
  // "wrong" with this program is that it never terminates -- a RUNTIME
  // property, not a static one, and proving non-termination in general is
  // undecidable for a language with backward jumps (the same principle
  // already documented for Vm_RuntimeInfiniteLoop_HitsInstructionBudget
  // below, which this test's expectation now matches exactly, where it
  // used to be a special case with a different, static-rejection
  // expectation).
  ProgramBuilder b(0);
  auto top = b.NewLabel();
  b.Mark(top);
  b.Jmp(top);
  auto r = Run(b.Build(), {});
  MT_CHECK(r.error == VmError::kInstructionBudgetExceeded);
}

MT_TEST(Vm_RuntimeInfiniteLoop_HitsInstructionBudget) {
  // A loop that decrements a local starting from a negative number never
  // reaches exactly zero (it keeps going more negative forever) -- this
  // program passes static verification (it does contain a reachable RET,
  // as the verifier's narrow check requires) but never actually reaches it
  // for this particular input. The runtime instruction budget is exactly
  // the backstop for this case; see vm.h's design note on
  // kInstructionBudgetExceeded. The RET below is dead code at runtime for
  // this input, present only so the program satisfies static verification.
  ProgramBuilder b(1);
  auto top = b.NewLabel();
  auto end = b.NewLabel();
  b.Mark(top);
  b.PushLocal(0);
  b.Jz(end);         // only exit: x == 0 exactly -- never true for a
                      // negative-starting countdown that only decrements
  b.PushLocal(0);
  b.PushConst(1);
  b.Sub();
  b.StoreLocal(0);
  b.Jmp(top);
  b.Mark(end);
  b.PushConst(0);
  b.Ret();            // statically present and reachable in principle;
                       // never reached at runtime for input -5
  auto r = Run(b.Build(), {-5});
  MT_CHECK(r.error == VmError::kInstructionBudgetExceeded);
}

MT_TEST(Vm_WrongNumberOfArgs_ExceedsLocals) {
  ProgramBuilder b(1);
  b.PushLocal(0);
  b.Ret();
  auto r = Run(b.Build(), {1, 2, 3});  // 3 args, only 1 local declared
  MT_CHECK(r.error == VmError::kWrongNumberOfArgs);
}

// ---------------------------------------------------------------------
// Verifier rejection of malformed/malicious bytecode
// (constructed as raw Program structs, bypassing the builder, since the
//  builder itself cannot emit invalid bytecode -- these tests simulate a
//  corrupted or maliciously crafted blob reaching VerifyProgram directly.)
// ---------------------------------------------------------------------

MT_TEST(Verify_RejectsInvalidOpcodeByte) {
  Program p;
  p.code = {0xEE};  // not a valid Opcode
  p.num_locals = 0;
  VerifyError err = VerifyError::kNone;
  auto ok = VerifyProgram(p, &err);
  MT_CHECK(!ok.has_value());
  MT_CHECK(err == VerifyError::kInvalidOpcode);
}

MT_TEST(Verify_RejectsTruncatedOperand) {
  Program p;
  // kPushConst (0x01) needs 2 operand bytes; give it zero.
  p.code = {0x01};
  VerifyError err = VerifyError::kNone;
  auto ok = VerifyProgram(p, &err);
  MT_CHECK(!ok.has_value());
  MT_CHECK(err == VerifyError::kTruncatedOperand);
}

MT_TEST(Verify_RejectsOutOfRangeConstantIndex) {
  Program p;
  p.code = {0x01, 0x05, 0x00, 0x50};  // PUSH_CONST idx=5, RET -- no constants defined
  p.constants = {};
  VerifyError err = VerifyError::kNone;
  auto ok = VerifyProgram(p, &err);
  MT_CHECK(!ok.has_value());
  MT_CHECK(err == VerifyError::kConstantIndexOutOfRange);
}

MT_TEST(Verify_RejectsOutOfRangeLocalIndex) {
  Program p;
  p.code = {0x02, 0x03, 0x50};  // PUSH_LOCAL idx=3, RET -- num_locals=0
  p.num_locals = 0;
  VerifyError err = VerifyError::kNone;
  auto ok = VerifyProgram(p, &err);
  MT_CHECK(!ok.has_value());
  MT_CHECK(err == VerifyError::kLocalIndexOutOfRange);
}

MT_TEST(Verify_RejectsJumpTargetBeyondCodeBounds) {
  Program p;
  // JMP (0x40) to offset 9999, which is far beyond this 3-byte program.
  p.code = {0x40, 0x0F, 0x27};  // 0x270F = 9999
  VerifyError err = VerifyError::kNone;
  auto ok = VerifyProgram(p, &err);
  MT_CHECK(!ok.has_value());
  MT_CHECK(err == VerifyError::kJumpTargetOutOfRange);
}

MT_TEST(Verify_RejectsJumpTargetMisaligned) {
  Program p;
  // JMP (0x40) to offset 2, which is the middle of the JMP instruction's own
  // operand bytes -- in range, but not an instruction boundary.
  p.code = {0x40, 0x02, 0x00, 0x50};  // JMP 2; byte[2] is mid-operand, RET at [3]
  VerifyError err = VerifyError::kNone;
  auto ok = VerifyProgram(p, &err);
  MT_CHECK(!ok.has_value());
  MT_CHECK(err == VerifyError::kJumpTargetMisaligned);
}

MT_TEST(Verify_RejectsControlFlowFallingOffEnd) {
  // PUSH_CONST (3 bytes total: opcode + u16 index), no RET, nothing after
  // it -- the reachable fallthrough from this single instruction would be
  // offset 3, which equals code.size(), i.e. past the end of the array.
  Program p;
  p.code = {0x01, 0x00, 0x00};
  p.constants = {1};
  VerifyError err = VerifyError::kNone;
  auto ok = VerifyProgram(p, &err);
  MT_CHECK(!ok.has_value());
  MT_CHECK(err == VerifyError::kControlFlowFallsOffEnd);
}

MT_TEST(Verify_RejectsEmptyProgram) {
  Program p;
  VerifyError err = VerifyError::kNone;
  auto ok = VerifyProgram(p, &err);
  MT_CHECK(!ok.has_value());
  MT_CHECK(err == VerifyError::kEmptyProgram);
}

MT_TEST(Verify_RejectsStackDepthConflictAtMergePoint) {
  // Hand-crafted: a Jz that, when taken, skips a PushConst that the
  // not-taken (fallthrough) path executes. Both paths converge on the
  // same instruction (the final Ret) with DIFFERENT stack depths (1 via
  // the jump, 2 via fallthrough) -- exactly the control-flow merge
  // inconsistency kStackDepthConflict exists to catch. Built from raw
  // bytes (not ProgramBuilder, which cannot itself construct an
  // inconsistent program) to simulate a corrupted or adversarially
  // crafted bytecode blob reaching the verifier directly.
  //
  //   0: PushConst #0        (01 00 00)       -- condition value
  //   3: Jz 11                (41 0b 00)       -- jump to offset 11 if zero
  //   6: PushConst #1         (01 01 00)       -- only on fallthrough path
  //   9: Jmp 11               Wait -- need offset 9 to fall through
  //         naturally into offset 11 for the conflict; use a direct
  //         fallthrough instead of an explicit Jmp so the two paths
  //         actually converge via different routes, not both via Jmp.
  //  (See inline construction below for the exact, verified byte layout.)
  Program p;
  p.constants = {0, 42};
  // offset 0: PUSH_CONST idx=0   -> 01 00 00   (3 bytes)
  // offset 3: JZ target=9        -> 41 09 00   (3 bytes) -- jump taken:
  //           stack depth after Jz pop = 0, lands at offset 9 with depth 0
  // offset 6: PUSH_CONST idx=1   -> 01 01 00   (3 bytes) -- fallthrough
  //           path: after Jz (depth 0), push -> depth 1, falls through to
  //           offset 9 with depth 1
  // offset 9: RET                -> 50          (1 byte) -- reached with
  //           depth 0 via the jump, depth 1 via fallthrough: CONFLICT
  p.code = {
      0x01, 0x00, 0x00,  // 0: PUSH_CONST 0
      0x41, 0x09, 0x00,  // 3: JZ 9
      0x01, 0x01, 0x00,  // 6: PUSH_CONST 1
      0x50,              // 9: RET
  };
  VerifyError err = VerifyError::kNone;
  auto ok = VerifyProgram(p, &err);
  MT_CHECK(!ok.has_value());
  MT_CHECK(err == VerifyError::kStackDepthConflict);
}

MT_TEST(Verify_AcceptsConsistentStackDepthAtMergePoint) {
  // Same shape as the conflict test above, but both paths push the same
  // number of values before converging -- confirms the merge-point check
  // doesn't over-reject a legitimately consistent diamond-shaped control
  // flow (if/else that both sides leave the stack the same depth).
  Program p;
  p.constants = {0, 42, 99};
  p.code = {
      0x01, 0x00, 0x00,  // 0: PUSH_CONST 0 (condition)
      0x41, 0x0c, 0x00,  // 3: JZ 12
      0x01, 0x01, 0x00,  // 6: PUSH_CONST 1 (then-branch value)
      0x40, 0x0f, 0x00,  // 9: JMP 15 (skip the else-branch push)
      0x01, 0x02, 0x00,  // 12: PUSH_CONST 2 (else-branch value)
      0x50,              // 15: RET -- reached with depth 1 from EITHER
                         //     branch: consistent
  };
  VerifyError err = VerifyError::kNone;
  auto ok = VerifyProgram(p, &err);
  MT_CHECK(ok.has_value());
  MT_CHECK(err == VerifyError::kNone);
}

MT_TEST(Verify_AcceptsValidJumpToInstructionBoundary) {
  // Sanity check that the misalignment logic doesn't over-reject: a jump
  // landing exactly on a later instruction's start byte must be accepted.
  ProgramBuilder b(0);
  auto target = b.NewLabel();
  b.Jmp(target);
  b.PushConst(999);  // skipped
  b.Pop();
  b.Mark(target);
  b.PushConst(1);
  b.Ret();
  VerifyError err = VerifyError::kNone;
  auto ok = VerifyProgram(b.Build(), &err);
  MT_CHECK(ok.has_value());
  MT_CHECK(err == VerifyError::kNone);
}

// ---------------------------------------------------------------------
// Operand-stack bounds
// ---------------------------------------------------------------------

MT_TEST(Verify_RejectsStaticStackUnderflow) {
  // POP on an empty stack (depth 0 at entry, POP requires depth >= 1).
  // Before this project's verifier gained static stack-depth analysis
  // (see verifier.h's kStaticStackUnderflow comment), this exact program
  // passed VerifyProgram() and was only caught at RUNTIME by vm.cpp's
  // VmError::kStackUnderflow check (see
  // Vm_RuntimeStackUnderflow_StillCaughtAsDefenseInDepth below for why
  // that runtime check still exists and still matters, even though it's
  // now unreachable for any input that passes static verification).
  Program p;
  p.code = {0x05, 0x50};  // POP, RET
  VerifyError verr = VerifyError::kNone;
  auto ok = VerifyProgram(p, &verr);
  MT_CHECK(!ok.has_value());
  MT_CHECK(verr == VerifyError::kStaticStackUnderflow);
}

MT_TEST(Verify_RejectsStaticStackOverflow) {
  // Same story as the underflow test above, for the opposite boundary:
  // pushing more values than kMaxStackDepth allows is now caught
  // statically rather than only at runtime.
  ProgramBuilder b(0);
  for (std::size_t i = 0; i < kMaxStackDepth + 1; ++i) {
    b.PushConst(static_cast<std::int64_t>(i));
  }
  b.Ret();
  VerifyError verr = VerifyError::kNone;
  auto ok = VerifyProgram(b.Build(), &verr);
  MT_CHECK(!ok.has_value());
  MT_CHECK(verr == VerifyError::kStaticStackOverflow);
}

// NOTE on vm.cpp's runtime pop()/push() bounds checks (VmError::
// kStackUnderflow / kStackOverflow): the task behind this hardening pass
// was explicit that runtime checks must be RETAINED even after adding
// static verification, and they were -- vm.cpp's checks are unchanged.
// What changed is reachability: Run() always verifies internally before
// executing (see vm.h's design note on why there's no "skip
// verification" path), so for any program that reaches the runtime
// pop()/push() checks at all, static verification already proved those
// exact checks cannot fail. This makes them defense-in-depth against a
// bug in the static analysis itself, not independently exercisable
// through the public API for a program that ALSO fails static
// verification -- there is no test here pretending otherwise. This is a
// deliberate, correct outcome of adding a sound static analysis, not a
// gap: a hand-written regression test cannot demonstrate "this runtime
// check still runs" any more precisely than "every call to Run() reaches
// vm.cpp's pop()/push() functions, which still contain their bounds
// checks, unchanged" -- which is a code-reading fact, not a
// test-observable one.

// ---------------------------------------------------------------------
// Checked arithmetic: boundary values that previously crashed the process
// (INT64_MIN / -1, INT64_MIN % -1) or silently overflowed (ADD/SUB/MUL at
// INT64_MAX/INT64_MIN), now must return VmError::kArithmeticOverflow --
// not a crash, not UB, not a wrapped value. See
// bytecode_vm/checked_arith.h's header comment for the empirical
// reproduction of the crash this closes.
// ---------------------------------------------------------------------

namespace {

// Builds a 2-local program: PushLocal(0), PushLocal(1), <op>, Ret.
Program TwoArgBinaryOpProgram(void (ProgramBuilder::*op)()) {
  ProgramBuilder b(2);
  b.PushLocal(0);
  b.PushLocal(1);
  (b.*op)();
  b.Ret();
  return b.Build();
}

}  // namespace

MT_TEST(Vm_Div_Int64MinByNegOne_ReportsOverflowNotCrash) {
  // This exact input, through the VM's previous unchecked `a / b`, caused
  // a real SIGFPE crash on x86-64 -- see checked_arith.h. The test
  // actually running to completion and observing a clean VmError (rather
  // than the test process itself dying) IS the regression test here.
  auto program = TwoArgBinaryOpProgram(&ProgramBuilder::Div);
  auto r = Run(program, {INT64_MIN, -1});
  MT_CHECK(r.error == VmError::kArithmeticOverflow);
}

MT_TEST(Vm_Mod_Int64MinByNegOne_ReportsOverflowNotCrash) {
  auto program = TwoArgBinaryOpProgram(&ProgramBuilder::Mod);
  auto r = Run(program, {INT64_MIN, -1});
  MT_CHECK(r.error == VmError::kArithmeticOverflow);
}

MT_TEST(Vm_Div_RegularValues_StillWorkCorrectly) {
  // Checked arithmetic must not change results for the overwhelming
  // majority of inputs that don't overflow -- only reject the narrow
  // boundary case.
  auto program = TwoArgBinaryOpProgram(&ProgramBuilder::Div);
  auto r = Run(program, {100, 7});
  MT_CHECK(r.error == VmError::kNone);
  MT_CHECK(r.value == 100 / 7);
}

MT_TEST(Vm_Mod_RegularValues_StillWorkCorrectly) {
  auto program = TwoArgBinaryOpProgram(&ProgramBuilder::Mod);
  auto r = Run(program, {100, 7});
  MT_CHECK(r.error == VmError::kNone);
  MT_CHECK(r.value == 100 % 7);
}

MT_TEST(Vm_Add_Int64MaxPlusOne_ReportsOverflow) {
  auto program = TwoArgBinaryOpProgram(&ProgramBuilder::Add);
  auto r = Run(program, {INT64_MAX, 1});
  MT_CHECK(r.error == VmError::kArithmeticOverflow);
}

MT_TEST(Vm_Add_RegularValues_StillWorkCorrectly) {
  auto program = TwoArgBinaryOpProgram(&ProgramBuilder::Add);
  auto r = Run(program, {1000, 2000});
  MT_CHECK(r.error == VmError::kNone);
  MT_CHECK(r.value == 3000);
}

MT_TEST(Vm_Sub_Int64MinMinusOne_ReportsOverflow) {
  auto program = TwoArgBinaryOpProgram(&ProgramBuilder::Sub);
  auto r = Run(program, {INT64_MIN, 1});
  MT_CHECK(r.error == VmError::kArithmeticOverflow);
}

MT_TEST(Vm_Sub_RegularValues_StillWorkCorrectly) {
  auto program = TwoArgBinaryOpProgram(&ProgramBuilder::Sub);
  auto r = Run(program, {5000, 3000});
  MT_CHECK(r.error == VmError::kNone);
  MT_CHECK(r.value == 2000);
}

MT_TEST(Vm_Mul_Int64MinTimesNegOne_ReportsOverflow) {
  auto program = TwoArgBinaryOpProgram(&ProgramBuilder::Mul);
  auto r = Run(program, {INT64_MIN, -1});
  MT_CHECK(r.error == VmError::kArithmeticOverflow);
}

MT_TEST(Vm_Mul_LargeValuesThatOverflow_ReportsOverflow) {
  // 4,000,000,000 * 4,000,000,000 = 16,000,000,000,000,000,000, which
  // exceeds INT64_MAX (9,223,372,036,854,775,807) -- verified with real
  // arithmetic before writing this test, since 3,000,000,000 squared
  // (9e18) was tried first and is actually still UNDER INT64_MAX, which
  // would have made this test assert an incorrect expectation rather than
  // catch a real regression. Caught by checking the arithmetic, not by
  // assuming "a big-looking number" overflows.
  auto program = TwoArgBinaryOpProgram(&ProgramBuilder::Mul);
  auto r = Run(program, {4000000000LL, 4000000000LL});
  MT_CHECK(r.error == VmError::kArithmeticOverflow);
}

MT_TEST(Vm_Mul_RegularValues_StillWorkCorrectly) {
  auto program = TwoArgBinaryOpProgram(&ProgramBuilder::Mul);
  auto r = Run(program, {123, 456});
  MT_CHECK(r.error == VmError::kNone);
  MT_CHECK(r.value == 123 * 456);
}

MT_TEST(Vm_Div_ByZero_StillReportsDivisionByZeroNotOverflow) {
  // Division-by-zero and arithmetic-overflow are deliberately distinct
  // VmErrors (see vm.cpp's comment on this) -- confirm b==0 is still
  // caught as kDivisionByZero, not accidentally folded into the new
  // overflow path.
  auto program = TwoArgBinaryOpProgram(&ProgramBuilder::Div);
  auto r = Run(program, {10, 0});
  MT_CHECK(r.error == VmError::kDivisionByZero);
}

MT_TEST(Vm_Deserialize_MalformedInput_HandledSafely) {
  // 1. Null data with non-zero length
  MT_CHECK(!Deserialize(nullptr, 16).has_value());
  MT_CHECK(!Deserialize(nullptr, 0).has_value());

  // 2. Truncated buffer (< 5 bytes)
  std::uint8_t short_buf[4] = {0, 0, 0, 0};
  MT_CHECK(!Deserialize(short_buf, sizeof(short_buf)).has_value());

  // 3. Claimed code length exceeds buffer
  std::uint8_t bad_len[5] = {0, 0xFF, 0xFF, 0, 0};
  MT_CHECK(!Deserialize(bad_len, sizeof(bad_len)).has_value());

  // 4. Valid serialization round-trips cleanly
  auto p = TrivialReturn(12345);
  auto serialized = Serialize(p);
  auto deserialized = Deserialize(serialized.data(), serialized.size());
  MT_CHECK(deserialized.has_value());
  MT_CHECK(deserialized->constants.size() == 1);
  MT_CHECK(deserialized->constants[0] == 12345);

  // 5. Trailing garbage is rejected
  serialized.push_back(0x99);
  MT_CHECK(!Deserialize(serialized.data(), serialized.size()).has_value());
}

// ---------------------------------------------------------------------
// Memory operations & Subroutines (Track C VM Expansion)
// ---------------------------------------------------------------------

MT_TEST(Vm_Memory_LoadAndStore8) {
  ProgramBuilder b(0);
  // store8(addr=16, val=0xAB)
  b.PushConst(16);
  b.PushConst(0xAB);
  b.StoreMem8();
  // load8(addr=16)
  b.PushConst(16);
  b.LoadMem8();
  b.Ret();

  MemoryContext mem(256);
  auto r = Run(b.Build(), {}, nullptr, &mem);
  MT_CHECK(r.error == VmError::kNone);
  MT_CHECK(r.value == 0xAB);
  MT_CHECK(mem.data[16] == 0xAB);
}

MT_TEST(Vm_Memory_LoadAndStore64) {
  ProgramBuilder b(0);
  // store64(addr=32, val=0x1122334455667788LL)
  b.PushConst(32);
  b.PushConst(0x1122334455667788LL);
  b.StoreMem64();
  // load64(addr=32)
  b.PushConst(32);
  b.LoadMem64();
  b.Ret();

  MemoryContext mem(256);
  auto r = Run(b.Build(), {}, nullptr, &mem);
  MT_CHECK(r.error == VmError::kNone);
  MT_CHECK(r.value == 0x1122334455667788LL);
}

MT_TEST(Vm_Memory_OutOfBounds_FaultsSafely) {
  ProgramBuilder b(0);
  b.PushConst(300); // Beyond 256 bytes
  b.LoadMem8();
  b.Ret();

  MemoryContext mem(256);
  auto r = Run(b.Build(), {}, nullptr, &mem);
  MT_CHECK(r.error == VmError::kMemoryAccessOutOfBounds);
}

MT_TEST(Vm_Subroutine_CallAndRetSub) {
  ProgramBuilder b(1); // 1 local
  auto sub_lbl = b.NewLabel();

  b.PushConst(10);
  b.Call(sub_lbl);     // sub adds 5 to top of stack
  b.StoreLocal(0);     // store 15 in local 0
  b.PushLocal(0);
  b.Ret();             // return 15

  // Subroutine:
  b.Mark(sub_lbl);
  b.PushConst(5);
  b.Add();
  b.RetSub();

  auto r = Run(b.Build(), {});
  MT_CHECK(r.error == VmError::kNone);
  MT_CHECK(r.value == 15);
}

// ---------------------------------------------------------------------
// C-Subset Compiler
// ---------------------------------------------------------------------

MT_TEST(Vm_Compiler_BasicArithmetic) {
  const std::string src =
      "int64_t compute(int64_t a, int64_t b) {\n"
      "    int64_t sum = a + b;\n"
      "    return sum * 3;\n"
      "}\n";

  std::string err;
  auto prog = CompileCSubset(src, &err);
  MT_CHECK(prog.has_value());

  auto r = Run(*prog, {4, 6});
  MT_CHECK(r.error == VmError::kNone);
  MT_CHECK(r.value == 30);
}

MT_TEST(Vm_Compiler_WhileLoop_Factorial) {
  const std::string src =
      "int64_t fact(int64_t n) {\n"
      "    int64_t res = 1;\n"
      "    while (n > 1) {\n"
      "        res = res * n;\n"
      "        n = n - 1;\n"
      "    }\n"
      "    return res;\n"
      "}\n";

  std::string err;
  auto prog = CompileCSubset(src, &err);
  MT_CHECK(prog.has_value());

  auto r = Run(*prog, {5});
  MT_CHECK(r.error == VmError::kNone);
  MT_CHECK(r.value == 120); // 5! = 120
}

MT_TEST(Vm_Compiler_IfElse_Branches) {
  const std::string src =
      "int64_t clamp(int64_t x) {\n"
      "    if (x < 0) {\n"
      "        return 0;\n"
      "    } else {\n"
      "        if (x > 100) {\n"
      "            return 100;\n"
      "        }\n"
      "    }\n"
      "    return x;\n"
      "}\n";

  std::string err;
  auto prog = CompileCSubset(src, &err);
  MT_CHECK(prog.has_value());

  MT_CHECK(Run(*prog, {-15}).value == 0);
  MT_CHECK(Run(*prog, {55}).value == 55);
  MT_CHECK(Run(*prog, {250}).value == 100);
}

MT_TEST(Vm_Compiler_MemoryOperations) {
  const std::string src =
      "int64_t test_mem(int64_t base) {\n"
      "    store8(base, 0xFE);\n"
      "    store64(base + 8, 0x123456789ABCDEF0);\n"
      "    int64_t v8 = load8(base);\n"
      "    int64_t v64 = load64(base + 8);\n"
      "    if (v8 == 0xFE) {\n"
      "        return v64;\n"
      "    }\n"
      "    return 0;\n"
      "}\n";

  std::string err;
  auto prog = CompileCSubset(src, &err);
  MT_CHECK(prog.has_value());

  MemoryContext mem(512);
  auto r = Run(*prog, {32}, nullptr, &mem);
  MT_CHECK(r.error == VmError::kNone);
  MT_CHECK(r.value == static_cast<std::int64_t>(0x123456789ABCDEF0ULL));
}

MT_MAIN()
