// bytecode_vm/vm.h
//
// Interprets a Program that has passed bytecode_vm::VerifyProgram. Run()
// always verifies internally before executing -- there is deliberately no
// "trust me, it's already verified" fast path exposed in the public API,
// because that would be exactly the kind of footgun that turns into a real
// vulnerability the first time a caller gets it wrong. (A future
// performance pass could cache verification results keyed by a hash of the
// program if re-verification cost ever matters; not needed at this scale.)

#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "bytecode_vm/program.h"
#include "bytecode_vm/verifier.h"

namespace rtprotect::vm {

// kMaxStackDepth now lives in program.h -- see that file's comment on why
// (verifier.cpp needs it too, and including vm.h from verifier.cpp would
// be circular since vm.h already includes verifier.h).
inline constexpr std::uint64_t kMaxExecutedInstructions = 100000;

enum class VmError {
  kNone = 0,
  kVerificationFailed,   // see VerifyError via RunResult::verify_error
  kStackOverflow,
  kStackUnderflow,
  kDivisionByZero,
  kArithmeticOverflow,  // ADD/SUB/MUL/DIV/MOD would overflow int64_t's
                        // representable range -- see
                        // bytecode_vm/checked_arith.h. Distinct from
                        // kDivisionByZero: this covers INT64_MIN/-1 (and
                        // INT64_MIN%-1) specifically, plus any ADD/SUB/MUL
                        // whose mathematical result doesn't fit in int64_t.
  kInstructionBudgetExceeded,  // runaway loop protection -- see design note below
  kWrongNumberOfArgs,
};

const char* ToString(VmError error);

struct RunResult {
  VmError error = VmError::kNone;
  // Populated only when error == kVerificationFailed.
  VerifyError verify_error = VerifyError::kNone;
  // Populated only when error == kNone: the value popped by the program's
  // kRet instruction.
  std::int64_t value = 0;
  // Number of instructions actually executed, for diagnostics/benchmarking
  // (populated regardless of success/failure, best-effort up to the point
  // of failure).
  std::uint64_t instructions_executed = 0;
};

// Runs `program` with `args` bound to locals[0..args.size()) and the
// remaining declared locals (if any) zero-initialized. Returns a RunResult
// describing either the returned value or the specific failure.
//
// Design note on kInstructionBudgetExceeded: the verifier (Phase 3 scope)
// checks static structure -- valid opcodes, in-range operands, jump targets
// landing on instruction boundaries -- but does NOT prove termination
// (that's undecidable in general for a language with backward jumps). A
// hard instruction-count budget is the runtime backstop against an
// accidentally or deliberately non-terminating program denying service to
// whatever embeds this VM. kMaxExecutedInstructions is generous for the
// small numeric functions this VM targets (see opcode.h's scope note).
RunResult Run(const Program& program, const std::vector<std::int64_t>& args);

}  // namespace rtprotect::vm
