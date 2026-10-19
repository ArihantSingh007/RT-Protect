#include "bytecode_vm/vm.h"

#include "bytecode_vm/checked_arith.h"
#include "bytecode_vm/opcode.h"

namespace rtprotect::vm {

const char* ToString(VmError error) {
  switch (error) {
    case VmError::kNone: return "none";
    case VmError::kVerificationFailed: return "program failed verification";
    case VmError::kStackOverflow: return "operand stack overflow";
    case VmError::kStackUnderflow: return "operand stack underflow";
    case VmError::kDivisionByZero: return "division or modulo by zero";
    case VmError::kArithmeticOverflow: return "arithmetic operation would overflow int64_t";
    case VmError::kInstructionBudgetExceeded: return "instruction budget exceeded (possible infinite loop)";
    case VmError::kWrongNumberOfArgs: return "argument count exceeds declared locals";
  }
  return "unknown VmError";
}

namespace {

std::uint16_t ReadU16(const std::uint8_t* p) {
  return static_cast<std::uint16_t>(p[0]) | (static_cast<std::uint16_t>(p[1]) << 8);
}

}  // namespace

RunResult Run(const Program& program, const std::vector<std::int64_t>& args) {
  RunResult result;

  VerifyError verr = VerifyError::kNone;
  auto instruction_starts = VerifyProgram(program, &verr);
  if (!instruction_starts.has_value()) {
    result.error = VmError::kVerificationFailed;
    result.verify_error = verr;
    return result;
  }
  // Only used in debug assertions below; the verifier already guarantees
  // every jump target is a member of this set, so the interpreter doesn't
  // need to re-check membership on every jump -- just bounds.
  (void)instruction_starts;

  if (args.size() > program.num_locals) {
    result.error = VmError::kWrongNumberOfArgs;
    return result;
  }

  std::vector<std::int64_t> locals(program.num_locals, 0);
  for (std::size_t k = 0; k < args.size(); ++k) locals[k] = args[k];

  std::int64_t stack[kMaxStackDepth];
  std::size_t sp = 0;  // next free slot

  auto push = [&](std::int64_t v) -> bool {
    if (sp >= kMaxStackDepth) return false;
    stack[sp++] = v;
    return true;
  };
  auto pop = [&](std::int64_t* out) -> bool {
    if (sp == 0) return false;
    *out = stack[--sp];
    return true;
  };

  const auto& code = program.code;
  std::size_t pc = 0;
  std::uint64_t executed = 0;

  while (true) {
    if (executed >= kMaxExecutedInstructions) {
      result.error = VmError::kInstructionBudgetExceeded;
      result.instructions_executed = executed;
      return result;
    }
    ++executed;

    Opcode op = static_cast<Opcode>(code[pc]);
    const std::uint8_t* operand = (pc + 1 < code.size()) ? &code[pc + 1] : nullptr;
    int operand_len = OperandBytes(op);
    std::size_t next_pc = pc + 1 + static_cast<std::size_t>(operand_len);

    std::int64_t a, b;

    switch (op) {
      case Opcode::kPushConst: {
        std::uint16_t idx = ReadU16(operand);
        if (!push(program.constants[idx])) {
          result.error = VmError::kStackOverflow;
          result.instructions_executed = executed;
          return result;
        }
        break;
      }
      case Opcode::kPushLocal: {
        std::uint8_t idx = operand[0];
        if (!push(locals[idx])) {
          result.error = VmError::kStackOverflow;
          result.instructions_executed = executed;
          return result;
        }
        break;
      }
      case Opcode::kStoreLocal: {
        std::uint8_t idx = operand[0];
        if (!pop(&a)) {
          result.error = VmError::kStackUnderflow;
          result.instructions_executed = executed;
          return result;
        }
        locals[idx] = a;
        break;
      }
      case Opcode::kDup: {
        if (sp == 0) {
          result.error = VmError::kStackUnderflow;
          result.instructions_executed = executed;
          return result;
        }
        if (!push(stack[sp - 1])) {
          result.error = VmError::kStackOverflow;
          result.instructions_executed = executed;
          return result;
        }
        break;
      }
      case Opcode::kPop: {
        if (!pop(&a)) {
          result.error = VmError::kStackUnderflow;
          result.instructions_executed = executed;
          return result;
        }
        break;
      }

#define BINARY_OP(EXPR)                                                 \
  do {                                                                  \
    if (!pop(&b) || !pop(&a)) {                                         \
      result.error = VmError::kStackUnderflow;                          \
      result.instructions_executed = executed;                         \
      return result;                                                   \
    }                                                                   \
    if (!push(EXPR)) {                                                  \
      result.error = VmError::kStackOverflow;                           \
      result.instructions_executed = executed;                         \
      return result;                                                   \
    }                                                                   \
  } while (0)

      // Checked arithmetic (bytecode_vm/checked_arith.h): ADD/SUB/MUL/DIV/
      // MOD all go through overflow-checked helpers rather than raw
      // operators. This is not a theoretical precaution -- a program
      // computing INT64_MIN / -1 (or INT64_MIN % -1) through the
      // previous, unchecked `a / b` / `a % b` triggered a real hardware
      // #DE trap (SIGFPE) on x86-64, crashing the host process; see
      // checked_arith.h's header comment for the exact reproduction. A
      // verified bytecode program reaching that exact operand pair was
      // possible before this fix (the verifier checks structure -- valid
      // opcodes, in-range indices, jump targets -- not the runtime values
      // flowing through arithmetic ops, which can't be known until
      // execution for a program with inputs/branches). Malformed or
      // adversarial *values* at runtime must fail the same way malformed
      // *structure* fails statically: a defined VmError, never a crash.
#define CHECKED_BINARY_OP(CHECKED_FN)                                   \
  do {                                                                  \
    if (!pop(&b) || !pop(&a)) {                                         \
      result.error = VmError::kStackUnderflow;                          \
      result.instructions_executed = executed;                         \
      return result;                                                   \
    }                                                                   \
    auto checked_result = CHECKED_FN(a, b);                             \
    if (!checked_result.has_value()) {                                 \
      result.error = VmError::kArithmeticOverflow;                      \
      result.instructions_executed = executed;                         \
      return result;                                                   \
    }                                                                   \
    if (!push(*checked_result)) {                                       \
      result.error = VmError::kStackOverflow;                           \
      result.instructions_executed = executed;                         \
      return result;                                                   \
    }                                                                   \
  } while (0)

      case Opcode::kAdd: CHECKED_BINARY_OP(CheckedAdd); break;
      case Opcode::kSub: CHECKED_BINARY_OP(CheckedSub); break;
      case Opcode::kMul: CHECKED_BINARY_OP(CheckedMul); break;
      case Opcode::kDiv: {
        if (!pop(&b) || !pop(&a)) {
          result.error = VmError::kStackUnderflow;
          result.instructions_executed = executed;
          return result;
        }
        if (b == 0) {
          // Checked BEFORE calling CheckedDiv: division by zero and
          // "INT64_MIN / -1 overflows" are reported as distinct VmErrors
          // (kDivisionByZero vs kArithmeticOverflow) because they're
          // distinct, useful-to-distinguish conditions for a caller
          // debugging a protected function, even though both ultimately
          // originate from the same underlying hardware trap avoidance.
          result.error = VmError::kDivisionByZero;
          result.instructions_executed = executed;
          return result;
        }
        auto checked_result = CheckedDiv(a, b);
        if (!checked_result.has_value()) {
          result.error = VmError::kArithmeticOverflow;
          result.instructions_executed = executed;
          return result;
        }
        if (!push(*checked_result)) {
          result.error = VmError::kStackOverflow;
          result.instructions_executed = executed;
          return result;
        }
        break;
      }
      case Opcode::kMod: {
        if (!pop(&b) || !pop(&a)) {
          result.error = VmError::kStackUnderflow;
          result.instructions_executed = executed;
          return result;
        }
        if (b == 0) {
          result.error = VmError::kDivisionByZero;
          result.instructions_executed = executed;
          return result;
        }
        auto checked_result = CheckedMod(a, b);
        if (!checked_result.has_value()) {
          result.error = VmError::kArithmeticOverflow;
          result.instructions_executed = executed;
          return result;
        }
        if (!push(*checked_result)) {
          result.error = VmError::kStackOverflow;
          result.instructions_executed = executed;
          return result;
        }
        break;
      }
      case Opcode::kAnd: BINARY_OP(a & b); break;
      case Opcode::kOr:  BINARY_OP(a | b); break;
      case Opcode::kXor: BINARY_OP(a ^ b); break;
      case Opcode::kNot: {
        if (!pop(&a)) {
          result.error = VmError::kStackUnderflow;
          result.instructions_executed = executed;
          return result;
        }
        if (!push(~a)) {
          result.error = VmError::kStackOverflow;
          result.instructions_executed = executed;
          return result;
        }
        break;
      }
      case Opcode::kCmpEq: BINARY_OP(a == b ? 1 : 0); break;
      case Opcode::kCmpLt: BINARY_OP(a < b ? 1 : 0); break;
      case Opcode::kCmpGt: BINARY_OP(a > b ? 1 : 0); break;

#undef BINARY_OP
#undef CHECKED_BINARY_OP

      case Opcode::kJmp: {
        next_pc = ReadU16(operand);
        break;
      }
      case Opcode::kJz: {
        if (!pop(&a)) {
          result.error = VmError::kStackUnderflow;
          result.instructions_executed = executed;
          return result;
        }
        if (a == 0) next_pc = ReadU16(operand);
        break;
      }
      case Opcode::kJnz: {
        if (!pop(&a)) {
          result.error = VmError::kStackUnderflow;
          result.instructions_executed = executed;
          return result;
        }
        if (a != 0) next_pc = ReadU16(operand);
        break;
      }
      case Opcode::kRet: {
        if (!pop(&a)) {
          result.error = VmError::kStackUnderflow;
          result.instructions_executed = executed;
          return result;
        }
        result.error = VmError::kNone;
        result.value = a;
        result.instructions_executed = executed;
        return result;
      }
    }

    pc = next_pc;
    // The verifier guarantees every jump target is a valid instruction
    // start and every non-jump next_pc is <= code.size() by construction
    // (it's how the verifier itself walked the code), so no bounds check is
    // needed here -- this is precisely the work verification front-loaded.
  }
}

}  // namespace rtprotect::vm
