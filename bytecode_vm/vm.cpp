#include "bytecode_vm/vm.h"

#include <array>
#include <cmath>
#include <cstring>
#include <memory>
#include "bytecode_vm/checked_arith.h"
#include "bytecode_vm/opcode.h"
#include "bytecode_vm/opcode_map.h"
#include "bytecode_vm/program_registry.h"

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
    case VmError::kMemoryAccessOutOfBounds: return "memory access out of bounds";
    case VmError::kCallStackOverflow: return "subroutine call stack overflow";
    case VmError::kCallStackUnderflow: return "return from subroutine without call frame";
  }
  return "unknown VmError";
}

namespace {

std::uint16_t ReadU16(const std::uint8_t* p) {
  return static_cast<std::uint16_t>(p[0]) | (static_cast<std::uint16_t>(p[1]) << 8);
}

inline std::uint64_t DoubleToBits(double d) {
  std::uint64_t bits = 0;
  std::memcpy(&bits, &d, sizeof(bits));
  return bits;
}

inline double BitsToDouble(std::uint64_t bits) {
  double d = 0.0;
  std::memcpy(&d, &bits, sizeof(d));
  return d;
}

inline bool SafeDoubleToInt64(double d, std::int64_t* out) {
  if (!std::isfinite(d)) {
    return false;
  }
  constexpr double kMinInt64 = -9223372036854775808.0;
  constexpr double kMaxInt64PlusOne = 9223372036854775808.0;
  if (d < kMinInt64 || d >= kMaxInt64PlusOne) {
    return false;
  }
  *out = static_cast<std::int64_t>(d);
  return true;
}

}  // namespace

RunResult Run(const Program& program,
              const std::vector<std::int64_t>& args,
              const OpcodeMap* opcode_map,
              MemoryContext* mem_ctx,
              VmEngineFlavor flavor,
              std::size_t recursion_depth) {
  if (flavor == VmEngineFlavor::kRegisterThreaded) {
    return RunRegisterThreaded(program, args, opcode_map, mem_ctx, recursion_depth);
  }
  if (flavor == VmEngineFlavor::kDirectThreadedTable) {
    return RunDirectThreadedTable(program, args, opcode_map, mem_ctx, recursion_depth);
  }

  RunResult result;
  if (recursion_depth >= kMaxProgramRecursionDepth) {
    result.error = VmError::kCallStackOverflow;
    return result;
  }

  VerifyError verr = VerifyError::kNone;
  auto instruction_starts = VerifyProgram(program, &verr, opcode_map);
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

  static const OpcodeMap kDefaultOpcodeMap;
  const OpcodeMap& map = opcode_map ? *opcode_map : kDefaultOpcodeMap;

  const auto& code = program.code;
  std::size_t pc = 0;
  std::uint64_t executed = 0;
  std::vector<std::size_t> call_stack;

  while (true) {
    if (executed >= kMaxExecutedInstructions) {
      result.error = VmError::kInstructionBudgetExceeded;
      result.instructions_executed = executed;
      return result;
    }
    ++executed;

    auto decoded_op = map.Decode(code[pc]);
    Opcode op = *decoded_op;
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
      case Opcode::kLoadMem8: {
        if (!pop(&a)) {
          result.error = VmError::kStackUnderflow;
          result.instructions_executed = executed;
          return result;
        }
        if (!mem_ctx || a < 0 || static_cast<std::size_t>(a) >= mem_ctx->data.size()) {
          result.error = VmError::kMemoryAccessOutOfBounds;
          result.instructions_executed = executed;
          return result;
        }
        std::uint8_t byte_val = mem_ctx->data[static_cast<std::size_t>(a)];
        if (!push(static_cast<std::int64_t>(byte_val))) {
          result.error = VmError::kStackOverflow;
          result.instructions_executed = executed;
          return result;
        }
        break;
      }
      case Opcode::kStoreMem8: {
        if (!pop(&b) || !pop(&a)) {
          result.error = VmError::kStackUnderflow;
          result.instructions_executed = executed;
          return result;
        }
        // b = val, a = addr
        if (!mem_ctx || a < 0 || static_cast<std::size_t>(a) >= mem_ctx->data.size()) {
          result.error = VmError::kMemoryAccessOutOfBounds;
          result.instructions_executed = executed;
          return result;
        }
        mem_ctx->data[static_cast<std::size_t>(a)] = static_cast<std::uint8_t>(b & 0xFF);
        break;
      }
      case Opcode::kLoadMem64: {
        if (!pop(&a)) {
          result.error = VmError::kStackUnderflow;
          result.instructions_executed = executed;
          return result;
        }
        if (!mem_ctx || a < 0 || static_cast<std::size_t>(a) + 8 > mem_ctx->data.size()) {
          result.error = VmError::kMemoryAccessOutOfBounds;
          result.instructions_executed = executed;
          return result;
        }
        std::uint64_t uval = 0;
        const std::uint8_t* p = &mem_ctx->data[static_cast<std::size_t>(a)];
        for (int k = 0; k < 8; ++k) {
          uval |= (static_cast<std::uint64_t>(p[k]) << (k * 8));
        }
        std::int64_t val = static_cast<std::int64_t>(uval);
        if (!push(val)) {
          result.error = VmError::kStackOverflow;
          result.instructions_executed = executed;
          return result;
        }
        break;
      }
      case Opcode::kStoreMem64: {
        if (!pop(&b) || !pop(&a)) {
          result.error = VmError::kStackUnderflow;
          result.instructions_executed = executed;
          return result;
        }
        // b = val, a = addr
        if (!mem_ctx || a < 0 || static_cast<std::size_t>(a) + 8 > mem_ctx->data.size()) {
          result.error = VmError::kMemoryAccessOutOfBounds;
          result.instructions_executed = executed;
          return result;
        }
        std::uint64_t uval = static_cast<std::uint64_t>(b);
        std::uint8_t* p = &mem_ctx->data[static_cast<std::size_t>(a)];
        for (int k = 0; k < 8; ++k) {
          p[k] = static_cast<std::uint8_t>((uval >> (k * 8)) & 0xFF);
        }
        break;
      }
      case Opcode::kCall: {
        if (call_stack.size() >= 64) {
          result.error = VmError::kCallStackOverflow;
          result.instructions_executed = executed;
          return result;
        }
        call_stack.push_back(next_pc);
        next_pc = ReadU16(operand);
        break;
      }
      case Opcode::kRetSub: {
        if (call_stack.empty()) {
          result.error = VmError::kCallStackUnderflow;
          result.instructions_executed = executed;
          return result;
        }
        next_pc = call_stack.back();
        call_stack.pop_back();
        break;
      }
      case Opcode::kCallProgram: {
        if (recursion_depth >= kMaxProgramRecursionDepth) {
          result.error = VmError::kCallStackOverflow;
          result.instructions_executed = executed;
          return result;
        }
        std::uint16_t prog_id = ReadU16(operand);
        std::shared_ptr<const Program> callee = ProgramRegistry::Get(prog_id);
        if (!callee) {
          result.error = VmError::kVerificationFailed;
          result.instructions_executed = executed;
          return result;
        }
        std::vector<std::int64_t> callee_args(callee->num_locals, 0);
        for (int k = static_cast<int>(callee->num_locals) - 1; k >= 0; --k) {
          std::int64_t arg_val = 0;
          if (!pop(&arg_val)) {
            result.error = VmError::kStackUnderflow;
            result.instructions_executed = executed;
            return result;
          }
          callee_args[k] = arg_val;
        }
        auto sub_res = Run(*callee, callee_args, opcode_map, mem_ctx, flavor, recursion_depth + 1);
        if (sub_res.error != VmError::kNone) {
          result.error = sub_res.error;
          result.instructions_executed = executed + sub_res.instructions_executed;
          return result;
        }
        executed += sub_res.instructions_executed;
        if (!push(sub_res.value)) {
          result.error = VmError::kStackOverflow;
          result.instructions_executed = executed;
          return result;
        }
        break;
      }
      case Opcode::kFAdd: {
        if (!pop(&b) || !pop(&a)) {
          result.error = VmError::kStackUnderflow;
          result.instructions_executed = executed;
          return result;
        }
        double da = BitsToDouble(static_cast<std::uint64_t>(a));
        double db = BitsToDouble(static_cast<std::uint64_t>(b));
        double res = da + db;
        if (!std::isfinite(res)) {
          result.error = VmError::kArithmeticOverflow;
          result.instructions_executed = executed;
          return result;
        }
        if (!push(static_cast<std::int64_t>(DoubleToBits(res)))) {
          result.error = VmError::kStackOverflow;
          result.instructions_executed = executed;
          return result;
        }
        break;
      }
      case Opcode::kFSub: {
        if (!pop(&b) || !pop(&a)) {
          result.error = VmError::kStackUnderflow;
          result.instructions_executed = executed;
          return result;
        }
        double da = BitsToDouble(static_cast<std::uint64_t>(a));
        double db = BitsToDouble(static_cast<std::uint64_t>(b));
        double res = da - db;
        if (!std::isfinite(res)) {
          result.error = VmError::kArithmeticOverflow;
          result.instructions_executed = executed;
          return result;
        }
        if (!push(static_cast<std::int64_t>(DoubleToBits(res)))) {
          result.error = VmError::kStackOverflow;
          result.instructions_executed = executed;
          return result;
        }
        break;
      }
      case Opcode::kFMul: {
        if (!pop(&b) || !pop(&a)) {
          result.error = VmError::kStackUnderflow;
          result.instructions_executed = executed;
          return result;
        }
        double da = BitsToDouble(static_cast<std::uint64_t>(a));
        double db = BitsToDouble(static_cast<std::uint64_t>(b));
        double res = da * db;
        if (!std::isfinite(res)) {
          result.error = VmError::kArithmeticOverflow;
          result.instructions_executed = executed;
          return result;
        }
        if (!push(static_cast<std::int64_t>(DoubleToBits(res)))) {
          result.error = VmError::kStackOverflow;
          result.instructions_executed = executed;
          return result;
        }
        break;
      }
      case Opcode::kFDiv: {
        if (!pop(&b) || !pop(&a)) {
          result.error = VmError::kStackUnderflow;
          result.instructions_executed = executed;
          return result;
        }
        double da = BitsToDouble(static_cast<std::uint64_t>(a));
        double db = BitsToDouble(static_cast<std::uint64_t>(b));
        if (db == 0.0) {
          result.error = VmError::kDivisionByZero;
          result.instructions_executed = executed;
          return result;
        }
        double res = da / db;
        if (!std::isfinite(res)) {
          result.error = VmError::kArithmeticOverflow;
          result.instructions_executed = executed;
          return result;
        }
        if (!push(static_cast<std::int64_t>(DoubleToBits(res)))) {
          result.error = VmError::kStackOverflow;
          result.instructions_executed = executed;
          return result;
        }
        break;
      }
      case Opcode::kFCmpEq: {
        if (!pop(&b) || !pop(&a)) {
          result.error = VmError::kStackUnderflow;
          result.instructions_executed = executed;
          return result;
        }
        double da = BitsToDouble(static_cast<std::uint64_t>(a));
        double db = BitsToDouble(static_cast<std::uint64_t>(b));
        if (!push(da == db ? 1 : 0)) {
          result.error = VmError::kStackOverflow;
          result.instructions_executed = executed;
          return result;
        }
        break;
      }
      case Opcode::kFCmpLt: {
        if (!pop(&b) || !pop(&a)) {
          result.error = VmError::kStackUnderflow;
          result.instructions_executed = executed;
          return result;
        }
        double da = BitsToDouble(static_cast<std::uint64_t>(a));
        double db = BitsToDouble(static_cast<std::uint64_t>(b));
        if (!push(da < db ? 1 : 0)) {
          result.error = VmError::kStackOverflow;
          result.instructions_executed = executed;
          return result;
        }
        break;
      }
      case Opcode::kFCmpGt: {
        if (!pop(&b) || !pop(&a)) {
          result.error = VmError::kStackUnderflow;
          result.instructions_executed = executed;
          return result;
        }
        double da = BitsToDouble(static_cast<std::uint64_t>(a));
        double db = BitsToDouble(static_cast<std::uint64_t>(b));
        if (!push(da > db ? 1 : 0)) {
          result.error = VmError::kStackOverflow;
          result.instructions_executed = executed;
          return result;
        }
        break;
      }
      case Opcode::kIntToFloat: {
        if (!pop(&a)) {
          result.error = VmError::kStackUnderflow;
          result.instructions_executed = executed;
          return result;
        }
        double da = static_cast<double>(a);
        if (!push(static_cast<std::int64_t>(DoubleToBits(da)))) {
          result.error = VmError::kStackOverflow;
          result.instructions_executed = executed;
          return result;
        }
        break;
      }
      case Opcode::kFloatToInt: {
        if (!pop(&a)) {
          result.error = VmError::kStackUnderflow;
          result.instructions_executed = executed;
          return result;
        }
        double da = BitsToDouble(static_cast<std::uint64_t>(a));
        std::int64_t converted = 0;
        if (!SafeDoubleToInt64(da, &converted)) {
          result.error = VmError::kArithmeticOverflow;
          result.instructions_executed = executed;
          return result;
        }
        if (!push(converted)) {
          result.error = VmError::kStackOverflow;
          result.instructions_executed = executed;
          return result;
        }
        break;
      }
    }

    pc = next_pc;
  }
}

RunResult RunRegisterThreaded(const Program& program,
                              const std::vector<std::int64_t>& args,
                              const OpcodeMap* opcode_map,
                              MemoryContext* mem_ctx,
                              std::size_t recursion_depth) {
  // Register-Threaded Engine (Flavor 2):
  // Uses an internal 8-slot register window (R0..R7) and accumulator (acc)
  // with threaded execution semantics, creating completely different
  // execution traces and memory signatures from the stack engine.
  RunResult result;
  if (recursion_depth >= kMaxProgramRecursionDepth) {
    result.error = VmError::kCallStackOverflow;
    return result;
  }

  VerifyError verr = VerifyError::kNone;
  auto instruction_starts = VerifyProgram(program, &verr, opcode_map);
  if (!instruction_starts.has_value()) {
    result.error = VmError::kVerificationFailed;
    result.verify_error = verr;
    return result;
  }

  if (args.size() > program.num_locals) {
    result.error = VmError::kWrongNumberOfArgs;
    return result;
  }

  std::vector<std::int64_t> locals(program.num_locals, 0);
  for (std::size_t k = 0; k < args.size(); ++k) locals[k] = args[k];

  // Register window: R0 through R7
  std::int64_t regs[8] = {0};
  std::int64_t acc = 0;
  std::int64_t aux_stack[kMaxStackDepth];
  std::size_t aux_sp = 0;

  auto reg_push = [&](std::int64_t v) -> bool {
    if (aux_sp >= kMaxStackDepth) return false;
    aux_stack[aux_sp++] = acc;
    acc = v;
    regs[aux_sp % 8] = v;
    return true;
  };

  auto reg_pop = [&](std::int64_t* out) -> bool {
    if (aux_sp == 0) return false;
    *out = acc;
    acc = aux_stack[--aux_sp];
    return true;
  };

  static const OpcodeMap kDefaultOpcodeMap;
  const OpcodeMap& map = opcode_map ? *opcode_map : kDefaultOpcodeMap;

  const auto& code = program.code;
  std::size_t pc = 0;
  std::uint64_t executed = 0;
  std::vector<std::size_t> call_stack;

  while (true) {
    if (executed >= kMaxExecutedInstructions) {
      result.error = VmError::kInstructionBudgetExceeded;
      result.instructions_executed = executed;
      return result;
    }
    ++executed;

    auto decoded_op = map.Decode(code[pc]);
    Opcode op = *decoded_op;
    const std::uint8_t* operand = (pc + 1 < code.size()) ? &code[pc + 1] : nullptr;
    int operand_len = OperandBytes(op);
    std::size_t next_pc = pc + 1 + static_cast<std::size_t>(operand_len);

    std::int64_t a = 0, b = 0;

    switch (op) {
      case Opcode::kPushConst: {
        std::uint16_t idx = ReadU16(operand);
        if (!reg_push(program.constants[idx])) {
          result.error = VmError::kStackOverflow;
          result.instructions_executed = executed;
          return result;
        }
        break;
      }
      case Opcode::kPushLocal: {
        std::uint8_t idx = operand[0];
        if (!reg_push(locals[idx])) {
          result.error = VmError::kStackOverflow;
          result.instructions_executed = executed;
          return result;
        }
        break;
      }
      case Opcode::kStoreLocal: {
        std::uint8_t idx = operand[0];
        if (!reg_pop(&a)) {
          result.error = VmError::kStackUnderflow;
          result.instructions_executed = executed;
          return result;
        }
        locals[idx] = a;
        break;
      }
      case Opcode::kDup: {
        if (aux_sp == 0) {
          result.error = VmError::kStackUnderflow;
          result.instructions_executed = executed;
          return result;
        }
        if (!reg_push(acc)) {
          result.error = VmError::kStackOverflow;
          result.instructions_executed = executed;
          return result;
        }
        break;
      }
      case Opcode::kPop: {
        if (!reg_pop(&a)) {
          result.error = VmError::kStackUnderflow;
          result.instructions_executed = executed;
          return result;
        }
        break;
      }
      case Opcode::kAdd: {
        if (!reg_pop(&b) || !reg_pop(&a)) {
          result.error = VmError::kStackUnderflow;
          result.instructions_executed = executed;
          return result;
        }
        auto r = CheckedAdd(a, b);
        if (!r) { result.error = VmError::kArithmeticOverflow; result.instructions_executed = executed; return result; }
        if (!reg_push(*r)) { result.error = VmError::kStackOverflow; result.instructions_executed = executed; return result; }
        break;
      }
      case Opcode::kSub: {
        if (!reg_pop(&b) || !reg_pop(&a)) {
          result.error = VmError::kStackUnderflow;
          result.instructions_executed = executed;
          return result;
        }
        auto r = CheckedSub(a, b);
        if (!r) { result.error = VmError::kArithmeticOverflow; result.instructions_executed = executed; return result; }
        if (!reg_push(*r)) { result.error = VmError::kStackOverflow; result.instructions_executed = executed; return result; }
        break;
      }
      case Opcode::kMul: {
        if (!reg_pop(&b) || !reg_pop(&a)) {
          result.error = VmError::kStackUnderflow;
          result.instructions_executed = executed;
          return result;
        }
        auto r = CheckedMul(a, b);
        if (!r) { result.error = VmError::kArithmeticOverflow; result.instructions_executed = executed; return result; }
        if (!reg_push(*r)) { result.error = VmError::kStackOverflow; result.instructions_executed = executed; return result; }
        break;
      }
      case Opcode::kDiv: {
        if (!reg_pop(&b) || !reg_pop(&a)) {
          result.error = VmError::kStackUnderflow;
          result.instructions_executed = executed;
          return result;
        }
        if (b == 0) { result.error = VmError::kDivisionByZero; result.instructions_executed = executed; return result; }
        auto r = CheckedDiv(a, b);
        if (!r) { result.error = VmError::kArithmeticOverflow; result.instructions_executed = executed; return result; }
        if (!reg_push(*r)) { result.error = VmError::kStackOverflow; result.instructions_executed = executed; return result; }
        break;
      }
      case Opcode::kMod: {
        if (!reg_pop(&b) || !reg_pop(&a)) {
          result.error = VmError::kStackUnderflow;
          result.instructions_executed = executed;
          return result;
        }
        if (b == 0) { result.error = VmError::kDivisionByZero; result.instructions_executed = executed; return result; }
        auto r = CheckedMod(a, b);
        if (!r) { result.error = VmError::kArithmeticOverflow; result.instructions_executed = executed; return result; }
        if (!reg_push(*r)) { result.error = VmError::kStackOverflow; result.instructions_executed = executed; return result; }
        break;
      }
      case Opcode::kAnd: {
        if (!reg_pop(&b) || !reg_pop(&a)) { result.error = VmError::kStackUnderflow; result.instructions_executed = executed; return result; }
        if (!reg_push(a & b)) { result.error = VmError::kStackOverflow; result.instructions_executed = executed; return result; }
        break;
      }
      case Opcode::kOr: {
        if (!reg_pop(&b) || !reg_pop(&a)) { result.error = VmError::kStackUnderflow; result.instructions_executed = executed; return result; }
        if (!reg_push(a | b)) { result.error = VmError::kStackOverflow; result.instructions_executed = executed; return result; }
        break;
      }
      case Opcode::kXor: {
        if (!reg_pop(&b) || !reg_pop(&a)) { result.error = VmError::kStackUnderflow; result.instructions_executed = executed; return result; }
        if (!reg_push(a ^ b)) { result.error = VmError::kStackOverflow; result.instructions_executed = executed; return result; }
        break;
      }
      case Opcode::kNot: {
        if (!reg_pop(&a)) { result.error = VmError::kStackUnderflow; result.instructions_executed = executed; return result; }
        if (!reg_push(~a)) { result.error = VmError::kStackOverflow; result.instructions_executed = executed; return result; }
        break;
      }
      case Opcode::kCmpEq: {
        if (!reg_pop(&b) || !reg_pop(&a)) { result.error = VmError::kStackUnderflow; result.instructions_executed = executed; return result; }
        if (!reg_push(a == b ? 1 : 0)) { result.error = VmError::kStackOverflow; result.instructions_executed = executed; return result; }
        break;
      }
      case Opcode::kCmpLt: {
        if (!reg_pop(&b) || !reg_pop(&a)) { result.error = VmError::kStackUnderflow; result.instructions_executed = executed; return result; }
        if (!reg_push(a < b ? 1 : 0)) { result.error = VmError::kStackOverflow; result.instructions_executed = executed; return result; }
        break;
      }
      case Opcode::kCmpGt: {
        if (!reg_pop(&b) || !reg_pop(&a)) { result.error = VmError::kStackUnderflow; result.instructions_executed = executed; return result; }
        if (!reg_push(a > b ? 1 : 0)) { result.error = VmError::kStackOverflow; result.instructions_executed = executed; return result; }
        break;
      }
      case Opcode::kJmp: {
        next_pc = ReadU16(operand);
        break;
      }
      case Opcode::kJz: {
        if (!reg_pop(&a)) { result.error = VmError::kStackUnderflow; result.instructions_executed = executed; return result; }
        if (a == 0) next_pc = ReadU16(operand);
        break;
      }
      case Opcode::kJnz: {
        if (!reg_pop(&a)) { result.error = VmError::kStackUnderflow; result.instructions_executed = executed; return result; }
        if (a != 0) next_pc = ReadU16(operand);
        break;
      }
      case Opcode::kRet: {
        if (!reg_pop(&a)) { result.error = VmError::kStackUnderflow; result.instructions_executed = executed; return result; }
        result.error = VmError::kNone;
        result.value = a;
        result.instructions_executed = executed;
        return result;
      }
      case Opcode::kLoadMem8: {
        if (!reg_pop(&a)) { result.error = VmError::kStackUnderflow; result.instructions_executed = executed; return result; }
        if (!mem_ctx || a < 0 || static_cast<std::size_t>(a) >= mem_ctx->data.size()) {
          result.error = VmError::kMemoryAccessOutOfBounds;
          result.instructions_executed = executed;
          return result;
        }
        if (!reg_push(static_cast<std::int64_t>(mem_ctx->data[static_cast<std::size_t>(a)]))) {
          result.error = VmError::kStackOverflow;
          result.instructions_executed = executed;
          return result;
        }
        break;
      }
      case Opcode::kStoreMem8: {
        if (!reg_pop(&b) || !reg_pop(&a)) { result.error = VmError::kStackUnderflow; result.instructions_executed = executed; return result; }
        if (!mem_ctx || a < 0 || static_cast<std::size_t>(a) >= mem_ctx->data.size()) {
          result.error = VmError::kMemoryAccessOutOfBounds;
          result.instructions_executed = executed;
          return result;
        }
        mem_ctx->data[static_cast<std::size_t>(a)] = static_cast<std::uint8_t>(b & 0xFF);
        break;
      }
      case Opcode::kLoadMem64: {
        if (!reg_pop(&a)) { result.error = VmError::kStackUnderflow; result.instructions_executed = executed; return result; }
        if (!mem_ctx || a < 0 || static_cast<std::size_t>(a) + 8 > mem_ctx->data.size()) {
          result.error = VmError::kMemoryAccessOutOfBounds;
          result.instructions_executed = executed;
          return result;
        }
        std::uint64_t uval = 0;
        const std::uint8_t* p = &mem_ctx->data[static_cast<std::size_t>(a)];
        for (int k = 0; k < 8; ++k) uval |= (static_cast<std::uint64_t>(p[k]) << (k * 8));
        if (!reg_push(static_cast<std::int64_t>(uval))) {
          result.error = VmError::kStackOverflow;
          result.instructions_executed = executed;
          return result;
        }
        break;
      }
      case Opcode::kStoreMem64: {
        if (!reg_pop(&b) || !reg_pop(&a)) { result.error = VmError::kStackUnderflow; result.instructions_executed = executed; return result; }
        if (!mem_ctx || a < 0 || static_cast<std::size_t>(a) + 8 > mem_ctx->data.size()) {
          result.error = VmError::kMemoryAccessOutOfBounds;
          result.instructions_executed = executed;
          return result;
        }
        std::uint64_t uval = static_cast<std::uint64_t>(b);
        std::uint8_t* p = &mem_ctx->data[static_cast<std::size_t>(a)];
        for (int k = 0; k < 8; ++k) p[k] = static_cast<std::uint8_t>((uval >> (k * 8)) & 0xFF);
        break;
      }
      case Opcode::kCall: {
        if (call_stack.size() >= 64) {
          result.error = VmError::kCallStackOverflow;
          result.instructions_executed = executed;
          return result;
        }
        call_stack.push_back(next_pc);
        next_pc = ReadU16(operand);
        break;
      }
      case Opcode::kRetSub: {
        if (call_stack.empty()) {
          result.error = VmError::kCallStackUnderflow;
          result.instructions_executed = executed;
          return result;
        }
        next_pc = call_stack.back();
        call_stack.pop_back();
        break;
      }
      case Opcode::kCallProgram: {
        if (recursion_depth >= kMaxProgramRecursionDepth) {
          result.error = VmError::kCallStackOverflow;
          result.instructions_executed = executed;
          return result;
        }
        std::uint16_t prog_id = ReadU16(operand);
        std::shared_ptr<const Program> callee = ProgramRegistry::Get(prog_id);
        if (!callee) {
          result.error = VmError::kVerificationFailed;
          result.instructions_executed = executed;
          return result;
        }
        std::vector<std::int64_t> callee_args(callee->num_locals, 0);
        for (int k = static_cast<int>(callee->num_locals) - 1; k >= 0; --k) {
          std::int64_t arg_val = 0;
          if (!reg_pop(&arg_val)) {
            result.error = VmError::kStackUnderflow;
            result.instructions_executed = executed;
            return result;
          }
          callee_args[k] = arg_val;
        }
        auto sub_res = RunRegisterThreaded(*callee, callee_args, opcode_map, mem_ctx, recursion_depth + 1);
        if (sub_res.error != VmError::kNone) {
          result.error = sub_res.error;
          result.instructions_executed = executed + sub_res.instructions_executed;
          return result;
        }
        executed += sub_res.instructions_executed;
        if (!reg_push(sub_res.value)) {
          result.error = VmError::kStackOverflow;
          result.instructions_executed = executed;
          return result;
        }
        break;
      }
      case Opcode::kFAdd: {
        if (!reg_pop(&b) || !reg_pop(&a)) { result.error = VmError::kStackUnderflow; result.instructions_executed = executed; return result; }
        double da = BitsToDouble(static_cast<std::uint64_t>(a));
        double db = BitsToDouble(static_cast<std::uint64_t>(b));
        double res = da + db;
        if (!std::isfinite(res)) { result.error = VmError::kArithmeticOverflow; result.instructions_executed = executed; return result; }
        if (!reg_push(static_cast<std::int64_t>(DoubleToBits(res)))) {
          result.error = VmError::kStackOverflow; result.instructions_executed = executed; return result;
        }
        break;
      }
      case Opcode::kFSub: {
        if (!reg_pop(&b) || !reg_pop(&a)) { result.error = VmError::kStackUnderflow; result.instructions_executed = executed; return result; }
        double da = BitsToDouble(static_cast<std::uint64_t>(a));
        double db = BitsToDouble(static_cast<std::uint64_t>(b));
        double res = da - db;
        if (!std::isfinite(res)) { result.error = VmError::kArithmeticOverflow; result.instructions_executed = executed; return result; }
        if (!reg_push(static_cast<std::int64_t>(DoubleToBits(res)))) {
          result.error = VmError::kStackOverflow; result.instructions_executed = executed; return result;
        }
        break;
      }
      case Opcode::kFMul: {
        if (!reg_pop(&b) || !reg_pop(&a)) { result.error = VmError::kStackUnderflow; result.instructions_executed = executed; return result; }
        double da = BitsToDouble(static_cast<std::uint64_t>(a));
        double db = BitsToDouble(static_cast<std::uint64_t>(b));
        double res = da * db;
        if (!std::isfinite(res)) { result.error = VmError::kArithmeticOverflow; result.instructions_executed = executed; return result; }
        if (!reg_push(static_cast<std::int64_t>(DoubleToBits(res)))) {
          result.error = VmError::kStackOverflow; result.instructions_executed = executed; return result;
        }
        break;
      }
      case Opcode::kFDiv: {
        if (!reg_pop(&b) || !reg_pop(&a)) { result.error = VmError::kStackUnderflow; result.instructions_executed = executed; return result; }
        double da = BitsToDouble(static_cast<std::uint64_t>(a));
        double db = BitsToDouble(static_cast<std::uint64_t>(b));
        if (db == 0.0) { result.error = VmError::kDivisionByZero; result.instructions_executed = executed; return result; }
        double res = da / db;
        if (!std::isfinite(res)) { result.error = VmError::kArithmeticOverflow; result.instructions_executed = executed; return result; }
        if (!reg_push(static_cast<std::int64_t>(DoubleToBits(res)))) {
          result.error = VmError::kStackOverflow; result.instructions_executed = executed; return result;
        }
        break;
      }
      case Opcode::kFCmpEq: {
        if (!reg_pop(&b) || !reg_pop(&a)) { result.error = VmError::kStackUnderflow; result.instructions_executed = executed; return result; }
        double da = BitsToDouble(static_cast<std::uint64_t>(a));
        double db = BitsToDouble(static_cast<std::uint64_t>(b));
        if (!reg_push(da == db ? 1 : 0)) { result.error = VmError::kStackOverflow; result.instructions_executed = executed; return result; }
        break;
      }
      case Opcode::kFCmpLt: {
        if (!reg_pop(&b) || !reg_pop(&a)) { result.error = VmError::kStackUnderflow; result.instructions_executed = executed; return result; }
        double da = BitsToDouble(static_cast<std::uint64_t>(a));
        double db = BitsToDouble(static_cast<std::uint64_t>(b));
        if (!reg_push(da < db ? 1 : 0)) { result.error = VmError::kStackOverflow; result.instructions_executed = executed; return result; }
        break;
      }
      case Opcode::kFCmpGt: {
        if (!reg_pop(&b) || !reg_pop(&a)) { result.error = VmError::kStackUnderflow; result.instructions_executed = executed; return result; }
        double da = BitsToDouble(static_cast<std::uint64_t>(a));
        double db = BitsToDouble(static_cast<std::uint64_t>(b));
        if (!reg_push(da > db ? 1 : 0)) { result.error = VmError::kStackOverflow; result.instructions_executed = executed; return result; }
        break;
      }
      case Opcode::kIntToFloat: {
        if (!reg_pop(&a)) { result.error = VmError::kStackUnderflow; result.instructions_executed = executed; return result; }
        double da = static_cast<double>(a);
        if (!reg_push(static_cast<std::int64_t>(DoubleToBits(da)))) { result.error = VmError::kStackOverflow; result.instructions_executed = executed; return result; }
        break;
      }
      case Opcode::kFloatToInt: {
        if (!reg_pop(&a)) { result.error = VmError::kStackUnderflow; result.instructions_executed = executed; return result; }
        double da = BitsToDouble(static_cast<std::uint64_t>(a));
        std::int64_t converted = 0;
        if (!SafeDoubleToInt64(da, &converted)) {
          result.error = VmError::kArithmeticOverflow;
          result.instructions_executed = executed;
          return result;
        }
        if (!reg_push(converted)) { result.error = VmError::kStackOverflow; result.instructions_executed = executed; return result; }
        break;
      }
    }

    pc = next_pc;
  }
}

namespace {

struct TableContext {
  std::int64_t stack[kMaxStackDepth];
  std::size_t sp = 0;
  std::vector<std::int64_t> locals;
  std::vector<std::size_t> call_stack;
  const Program& program;
  const OpcodeMap& map;
  MemoryContext* mem_ctx = nullptr;
  std::size_t recursion_depth = 0;
  std::uint64_t executed = 0;
  bool halted = false;
  std::int64_t return_val = 0;

  bool push(std::int64_t v) {
    if (sp >= kMaxStackDepth) return false;
    stack[sp++] = v;
    return true;
  }
  bool pop(std::int64_t* out) {
    if (sp == 0) return false;
    *out = stack[--sp];
    return true;
  }
};

using TableOpcodeHandler = VmError (*)(TableContext& ctx, const std::uint8_t* operand, std::size_t& next_pc);

VmError H_PushConst(TableContext& ctx, const std::uint8_t* operand, std::size_t&) {
  std::uint16_t idx = ReadU16(operand);
  if (!ctx.push(ctx.program.constants[idx])) return VmError::kStackOverflow;
  return VmError::kNone;
}

VmError H_PushLocal(TableContext& ctx, const std::uint8_t* operand, std::size_t&) {
  std::uint8_t idx = operand[0];
  if (!ctx.push(ctx.locals[idx])) return VmError::kStackOverflow;
  return VmError::kNone;
}

VmError H_StoreLocal(TableContext& ctx, const std::uint8_t* operand, std::size_t&) {
  std::uint8_t idx = operand[0];
  std::int64_t v = 0;
  if (!ctx.pop(&v)) return VmError::kStackUnderflow;
  ctx.locals[idx] = v;
  return VmError::kNone;
}

VmError H_Dup(TableContext& ctx, const std::uint8_t*, std::size_t&) {
  std::int64_t v = 0;
  if (!ctx.pop(&v)) return VmError::kStackUnderflow;
  if (!ctx.push(v) || !ctx.push(v)) return VmError::kStackOverflow;
  return VmError::kNone;
}

VmError H_Pop(TableContext& ctx, const std::uint8_t*, std::size_t&) {
  std::int64_t v = 0;
  if (!ctx.pop(&v)) return VmError::kStackUnderflow;
  return VmError::kNone;
}

VmError H_Add(TableContext& ctx, const std::uint8_t*, std::size_t&) {
  std::int64_t a = 0, b = 0;
  if (!ctx.pop(&b) || !ctx.pop(&a)) return VmError::kStackUnderflow;
  auto r = CheckedAdd(a, b);
  if (!r) return VmError::kArithmeticOverflow;
  if (!ctx.push(*r)) return VmError::kStackOverflow;
  return VmError::kNone;
}

VmError H_Sub(TableContext& ctx, const std::uint8_t*, std::size_t&) {
  std::int64_t a = 0, b = 0;
  if (!ctx.pop(&b) || !ctx.pop(&a)) return VmError::kStackUnderflow;
  auto r = CheckedSub(a, b);
  if (!r) return VmError::kArithmeticOverflow;
  if (!ctx.push(*r)) return VmError::kStackOverflow;
  return VmError::kNone;
}

VmError H_Mul(TableContext& ctx, const std::uint8_t*, std::size_t&) {
  std::int64_t a = 0, b = 0;
  if (!ctx.pop(&b) || !ctx.pop(&a)) return VmError::kStackUnderflow;
  auto r = CheckedMul(a, b);
  if (!r) return VmError::kArithmeticOverflow;
  if (!ctx.push(*r)) return VmError::kStackOverflow;
  return VmError::kNone;
}

VmError H_Div(TableContext& ctx, const std::uint8_t*, std::size_t&) {
  std::int64_t a = 0, b = 0;
  if (!ctx.pop(&b) || !ctx.pop(&a)) return VmError::kStackUnderflow;
  if (b == 0) return VmError::kDivisionByZero;
  auto r = CheckedDiv(a, b);
  if (!r) return VmError::kArithmeticOverflow;
  if (!ctx.push(*r)) return VmError::kStackOverflow;
  return VmError::kNone;
}

VmError H_Mod(TableContext& ctx, const std::uint8_t*, std::size_t&) {
  std::int64_t a = 0, b = 0;
  if (!ctx.pop(&b) || !ctx.pop(&a)) return VmError::kStackUnderflow;
  if (b == 0) return VmError::kDivisionByZero;
  auto r = CheckedMod(a, b);
  if (!r) return VmError::kArithmeticOverflow;
  if (!ctx.push(*r)) return VmError::kStackOverflow;
  return VmError::kNone;
}

VmError H_And(TableContext& ctx, const std::uint8_t*, std::size_t&) {
  std::int64_t a = 0, b = 0;
  if (!ctx.pop(&b) || !ctx.pop(&a)) return VmError::kStackUnderflow;
  if (!ctx.push(a & b)) return VmError::kStackOverflow;
  return VmError::kNone;
}

VmError H_Or(TableContext& ctx, const std::uint8_t*, std::size_t&) {
  std::int64_t a = 0, b = 0;
  if (!ctx.pop(&b) || !ctx.pop(&a)) return VmError::kStackUnderflow;
  if (!ctx.push(a | b)) return VmError::kStackOverflow;
  return VmError::kNone;
}

VmError H_Xor(TableContext& ctx, const std::uint8_t*, std::size_t&) {
  std::int64_t a = 0, b = 0;
  if (!ctx.pop(&b) || !ctx.pop(&a)) return VmError::kStackUnderflow;
  if (!ctx.push(a ^ b)) return VmError::kStackOverflow;
  return VmError::kNone;
}

VmError H_Not(TableContext& ctx, const std::uint8_t*, std::size_t&) {
  std::int64_t a = 0;
  if (!ctx.pop(&a)) return VmError::kStackUnderflow;
  if (!ctx.push(~a)) return VmError::kStackOverflow;
  return VmError::kNone;
}

VmError H_CmpEq(TableContext& ctx, const std::uint8_t*, std::size_t&) {
  std::int64_t a = 0, b = 0;
  if (!ctx.pop(&b) || !ctx.pop(&a)) return VmError::kStackUnderflow;
  if (!ctx.push(a == b ? 1 : 0)) return VmError::kStackOverflow;
  return VmError::kNone;
}

VmError H_CmpLt(TableContext& ctx, const std::uint8_t*, std::size_t&) {
  std::int64_t a = 0, b = 0;
  if (!ctx.pop(&b) || !ctx.pop(&a)) return VmError::kStackUnderflow;
  if (!ctx.push(a < b ? 1 : 0)) return VmError::kStackOverflow;
  return VmError::kNone;
}

VmError H_CmpGt(TableContext& ctx, const std::uint8_t*, std::size_t&) {
  std::int64_t a = 0, b = 0;
  if (!ctx.pop(&b) || !ctx.pop(&a)) return VmError::kStackUnderflow;
  if (!ctx.push(a > b ? 1 : 0)) return VmError::kStackOverflow;
  return VmError::kNone;
}

VmError H_Jmp(TableContext&, const std::uint8_t* operand, std::size_t& next_pc) {
  next_pc = ReadU16(operand);
  return VmError::kNone;
}

VmError H_Jz(TableContext& ctx, const std::uint8_t* operand, std::size_t& next_pc) {
  std::int64_t a = 0;
  if (!ctx.pop(&a)) return VmError::kStackUnderflow;
  if (a == 0) next_pc = ReadU16(operand);
  return VmError::kNone;
}

VmError H_Jnz(TableContext& ctx, const std::uint8_t* operand, std::size_t& next_pc) {
  std::int64_t a = 0;
  if (!ctx.pop(&a)) return VmError::kStackUnderflow;
  if (a != 0) next_pc = ReadU16(operand);
  return VmError::kNone;
}

VmError H_Ret(TableContext& ctx, const std::uint8_t*, std::size_t&) {
  std::int64_t a = 0;
  if (!ctx.pop(&a)) return VmError::kStackUnderflow;
  ctx.return_val = a;
  ctx.halted = true;
  return VmError::kNone;
}

VmError H_LoadMem8(TableContext& ctx, const std::uint8_t*, std::size_t&) {
  std::int64_t a = 0;
  if (!ctx.pop(&a)) return VmError::kStackUnderflow;
  if (!ctx.mem_ctx || a < 0 || static_cast<std::size_t>(a) >= ctx.mem_ctx->data.size()) {
    return VmError::kMemoryAccessOutOfBounds;
  }
  std::uint8_t byte_val = ctx.mem_ctx->data[static_cast<std::size_t>(a)];
  if (!ctx.push(static_cast<std::int64_t>(byte_val))) return VmError::kStackOverflow;
  return VmError::kNone;
}

VmError H_StoreMem8(TableContext& ctx, const std::uint8_t*, std::size_t&) {
  std::int64_t a = 0, b = 0;
  if (!ctx.pop(&b) || !ctx.pop(&a)) return VmError::kStackUnderflow;
  if (!ctx.mem_ctx || a < 0 || static_cast<std::size_t>(a) >= ctx.mem_ctx->data.size()) {
    return VmError::kMemoryAccessOutOfBounds;
  }
  ctx.mem_ctx->data[static_cast<std::size_t>(a)] = static_cast<std::uint8_t>(b & 0xFF);
  return VmError::kNone;
}

VmError H_LoadMem64(TableContext& ctx, const std::uint8_t*, std::size_t&) {
  std::int64_t a = 0;
  if (!ctx.pop(&a)) return VmError::kStackUnderflow;
  if (!ctx.mem_ctx || a < 0 || static_cast<std::size_t>(a) + 8 > ctx.mem_ctx->data.size()) {
    return VmError::kMemoryAccessOutOfBounds;
  }
  std::uint64_t uval = 0;
  const std::uint8_t* p = &ctx.mem_ctx->data[static_cast<std::size_t>(a)];
  for (int k = 0; k < 8; ++k) uval |= (static_cast<std::uint64_t>(p[k]) << (k * 8));
  if (!ctx.push(static_cast<std::int64_t>(uval))) return VmError::kStackOverflow;
  return VmError::kNone;
}

VmError H_StoreMem64(TableContext& ctx, const std::uint8_t*, std::size_t&) {
  std::int64_t a = 0, b = 0;
  if (!ctx.pop(&b) || !ctx.pop(&a)) return VmError::kStackUnderflow;
  if (!ctx.mem_ctx || a < 0 || static_cast<std::size_t>(a) + 8 > ctx.mem_ctx->data.size()) {
    return VmError::kMemoryAccessOutOfBounds;
  }
  std::uint64_t uval = static_cast<std::uint64_t>(b);
  std::uint8_t* p = &ctx.mem_ctx->data[static_cast<std::size_t>(a)];
  for (int k = 0; k < 8; ++k) p[k] = static_cast<std::uint8_t>((uval >> (k * 8)) & 0xFF);
  return VmError::kNone;
}

VmError H_Call(TableContext& ctx, const std::uint8_t* operand, std::size_t& next_pc) {
  if (ctx.call_stack.size() >= 64) return VmError::kCallStackOverflow;
  ctx.call_stack.push_back(next_pc);
  next_pc = ReadU16(operand);
  return VmError::kNone;
}

VmError H_RetSub(TableContext& ctx, const std::uint8_t*, std::size_t& next_pc) {
  if (ctx.call_stack.empty()) return VmError::kCallStackUnderflow;
  next_pc = ctx.call_stack.back();
  ctx.call_stack.pop_back();
  return VmError::kNone;
}

VmError H_CallProgram(TableContext& ctx, const std::uint8_t* operand, std::size_t&) {
  if (ctx.recursion_depth >= kMaxProgramRecursionDepth) return VmError::kCallStackOverflow;
  std::uint16_t prog_id = ReadU16(operand);
  std::shared_ptr<const Program> callee = ProgramRegistry::Get(prog_id);
  if (!callee) return VmError::kVerificationFailed;
  std::vector<std::int64_t> callee_args(callee->num_locals, 0);
  for (int k = static_cast<int>(callee->num_locals) - 1; k >= 0; --k) {
    std::int64_t arg_val = 0;
    if (!ctx.pop(&arg_val)) return VmError::kStackUnderflow;
    callee_args[k] = arg_val;
  }
  auto sub_res = RunDirectThreadedTable(*callee, callee_args, &ctx.map, ctx.mem_ctx, ctx.recursion_depth + 1);
  if (sub_res.error != VmError::kNone) return sub_res.error;
  ctx.executed += sub_res.instructions_executed;
  if (!ctx.push(sub_res.value)) return VmError::kStackOverflow;
  return VmError::kNone;
}

VmError H_FAdd(TableContext& ctx, const std::uint8_t*, std::size_t&) {
  std::int64_t a = 0, b = 0;
  if (!ctx.pop(&b) || !ctx.pop(&a)) return VmError::kStackUnderflow;
  double da = BitsToDouble(static_cast<std::uint64_t>(a));
  double db = BitsToDouble(static_cast<std::uint64_t>(b));
  double res = da + db;
  if (!std::isfinite(res)) return VmError::kArithmeticOverflow;
  if (!ctx.push(static_cast<std::int64_t>(DoubleToBits(res)))) return VmError::kStackOverflow;
  return VmError::kNone;
}

VmError H_FSub(TableContext& ctx, const std::uint8_t*, std::size_t&) {
  std::int64_t a = 0, b = 0;
  if (!ctx.pop(&b) || !ctx.pop(&a)) return VmError::kStackUnderflow;
  double da = BitsToDouble(static_cast<std::uint64_t>(a));
  double db = BitsToDouble(static_cast<std::uint64_t>(b));
  double res = da - db;
  if (!std::isfinite(res)) return VmError::kArithmeticOverflow;
  if (!ctx.push(static_cast<std::int64_t>(DoubleToBits(res)))) return VmError::kStackOverflow;
  return VmError::kNone;
}

VmError H_FMul(TableContext& ctx, const std::uint8_t*, std::size_t&) {
  std::int64_t a = 0, b = 0;
  if (!ctx.pop(&b) || !ctx.pop(&a)) return VmError::kStackUnderflow;
  double da = BitsToDouble(static_cast<std::uint64_t>(a));
  double db = BitsToDouble(static_cast<std::uint64_t>(b));
  double res = da * db;
  if (!std::isfinite(res)) return VmError::kArithmeticOverflow;
  if (!ctx.push(static_cast<std::int64_t>(DoubleToBits(res)))) return VmError::kStackOverflow;
  return VmError::kNone;
}

VmError H_FDiv(TableContext& ctx, const std::uint8_t*, std::size_t&) {
  std::int64_t a = 0, b = 0;
  if (!ctx.pop(&b) || !ctx.pop(&a)) return VmError::kStackUnderflow;
  double da = BitsToDouble(static_cast<std::uint64_t>(a));
  double db = BitsToDouble(static_cast<std::uint64_t>(b));
  if (db == 0.0) return VmError::kDivisionByZero;
  double res = da / db;
  if (!std::isfinite(res)) return VmError::kArithmeticOverflow;
  if (!ctx.push(static_cast<std::int64_t>(DoubleToBits(res)))) return VmError::kStackOverflow;
  return VmError::kNone;
}

VmError H_FCmpEq(TableContext& ctx, const std::uint8_t*, std::size_t&) {
  std::int64_t a = 0, b = 0;
  if (!ctx.pop(&b) || !ctx.pop(&a)) return VmError::kStackUnderflow;
  double da = BitsToDouble(static_cast<std::uint64_t>(a));
  double db = BitsToDouble(static_cast<std::uint64_t>(b));
  if (!ctx.push(da == db ? 1 : 0)) return VmError::kStackOverflow;
  return VmError::kNone;
}

VmError H_FCmpLt(TableContext& ctx, const std::uint8_t*, std::size_t&) {
  std::int64_t a = 0, b = 0;
  if (!ctx.pop(&b) || !ctx.pop(&a)) return VmError::kStackUnderflow;
  double da = BitsToDouble(static_cast<std::uint64_t>(a));
  double db = BitsToDouble(static_cast<std::uint64_t>(b));
  if (!ctx.push(da < db ? 1 : 0)) return VmError::kStackOverflow;
  return VmError::kNone;
}

VmError H_FCmpGt(TableContext& ctx, const std::uint8_t*, std::size_t&) {
  std::int64_t a = 0, b = 0;
  if (!ctx.pop(&b) || !ctx.pop(&a)) return VmError::kStackUnderflow;
  double da = BitsToDouble(static_cast<std::uint64_t>(a));
  double db = BitsToDouble(static_cast<std::uint64_t>(b));
  if (!ctx.push(da > db ? 1 : 0)) return VmError::kStackOverflow;
  return VmError::kNone;
}

VmError H_IntToFloat(TableContext& ctx, const std::uint8_t*, std::size_t&) {
  std::int64_t a = 0;
  if (!ctx.pop(&a)) return VmError::kStackUnderflow;
  double da = static_cast<double>(a);
  if (!ctx.push(static_cast<std::int64_t>(DoubleToBits(da)))) return VmError::kStackOverflow;
  return VmError::kNone;
}

VmError H_FloatToInt(TableContext& ctx, const std::uint8_t*, std::size_t&) {
  std::int64_t a = 0;
  if (!ctx.pop(&a)) return VmError::kStackUnderflow;
  double da = BitsToDouble(static_cast<std::uint64_t>(a));
  std::int64_t converted = 0;
  if (!SafeDoubleToInt64(da, &converted)) return VmError::kArithmeticOverflow;
  if (!ctx.push(converted)) return VmError::kStackOverflow;
  return VmError::kNone;
}

const TableOpcodeHandler* GetDirectThreadedDispatchTable() {
  static const auto table = []() {
    std::array<TableOpcodeHandler, 256> t{};
    t[static_cast<std::uint8_t>(Opcode::kPushConst)] = H_PushConst;
    t[static_cast<std::uint8_t>(Opcode::kPushLocal)] = H_PushLocal;
    t[static_cast<std::uint8_t>(Opcode::kStoreLocal)] = H_StoreLocal;
    t[static_cast<std::uint8_t>(Opcode::kDup)] = H_Dup;
    t[static_cast<std::uint8_t>(Opcode::kPop)] = H_Pop;
    t[static_cast<std::uint8_t>(Opcode::kAdd)] = H_Add;
    t[static_cast<std::uint8_t>(Opcode::kSub)] = H_Sub;
    t[static_cast<std::uint8_t>(Opcode::kMul)] = H_Mul;
    t[static_cast<std::uint8_t>(Opcode::kDiv)] = H_Div;
    t[static_cast<std::uint8_t>(Opcode::kMod)] = H_Mod;
    t[static_cast<std::uint8_t>(Opcode::kAnd)] = H_And;
    t[static_cast<std::uint8_t>(Opcode::kOr)] = H_Or;
    t[static_cast<std::uint8_t>(Opcode::kXor)] = H_Xor;
    t[static_cast<std::uint8_t>(Opcode::kNot)] = H_Not;
    t[static_cast<std::uint8_t>(Opcode::kCmpEq)] = H_CmpEq;
    t[static_cast<std::uint8_t>(Opcode::kCmpLt)] = H_CmpLt;
    t[static_cast<std::uint8_t>(Opcode::kCmpGt)] = H_CmpGt;
    t[static_cast<std::uint8_t>(Opcode::kJmp)] = H_Jmp;
    t[static_cast<std::uint8_t>(Opcode::kJz)] = H_Jz;
    t[static_cast<std::uint8_t>(Opcode::kJnz)] = H_Jnz;
    t[static_cast<std::uint8_t>(Opcode::kRet)] = H_Ret;
    t[static_cast<std::uint8_t>(Opcode::kLoadMem8)] = H_LoadMem8;
    t[static_cast<std::uint8_t>(Opcode::kStoreMem8)] = H_StoreMem8;
    t[static_cast<std::uint8_t>(Opcode::kLoadMem64)] = H_LoadMem64;
    t[static_cast<std::uint8_t>(Opcode::kStoreMem64)] = H_StoreMem64;
    t[static_cast<std::uint8_t>(Opcode::kCall)] = H_Call;
    t[static_cast<std::uint8_t>(Opcode::kRetSub)] = H_RetSub;
    t[static_cast<std::uint8_t>(Opcode::kCallProgram)] = H_CallProgram;
    t[static_cast<std::uint8_t>(Opcode::kFAdd)] = H_FAdd;
    t[static_cast<std::uint8_t>(Opcode::kFSub)] = H_FSub;
    t[static_cast<std::uint8_t>(Opcode::kFMul)] = H_FMul;
    t[static_cast<std::uint8_t>(Opcode::kFDiv)] = H_FDiv;
    t[static_cast<std::uint8_t>(Opcode::kFCmpEq)] = H_FCmpEq;
    t[static_cast<std::uint8_t>(Opcode::kFCmpLt)] = H_FCmpLt;
    t[static_cast<std::uint8_t>(Opcode::kFCmpGt)] = H_FCmpGt;
    t[static_cast<std::uint8_t>(Opcode::kIntToFloat)] = H_IntToFloat;
    t[static_cast<std::uint8_t>(Opcode::kFloatToInt)] = H_FloatToInt;
    return t;
  }();
  return table.data();
}

}  // namespace

RunResult RunDirectThreadedTable(const Program& program,
                                 const std::vector<std::int64_t>& args,
                                 const OpcodeMap* opcode_map,
                                 MemoryContext* mem_ctx,
                                 std::size_t recursion_depth) {
  // Direct-Threaded Jump-Table Engine (Flavor 3):
  // Eliminates compiler-generated central switch tables and monolithic loops.
  // Instead, individual opcode handlers are directly dispatched via a table of
  // function pointers, creating a completely different decompiler control-flow
  // structure that resists automated deobfuscation scripts.
  RunResult result;
  if (recursion_depth >= kMaxProgramRecursionDepth) {
    result.error = VmError::kCallStackOverflow;
    return result;
  }

  VerifyError verr = VerifyError::kNone;
  auto instruction_starts = VerifyProgram(program, &verr, opcode_map);
  if (!instruction_starts.has_value()) {
    result.error = VmError::kVerificationFailed;
    result.verify_error = verr;
    return result;
  }

  if (args.size() > program.num_locals) {
    result.error = VmError::kWrongNumberOfArgs;
    return result;
  }

  static const OpcodeMap kDefaultOpcodeMap;
  const OpcodeMap& map = opcode_map ? *opcode_map : kDefaultOpcodeMap;
  const TableOpcodeHandler* dispatch_table = GetDirectThreadedDispatchTable();

  TableContext ctx{
      {},
      0,
      std::vector<std::int64_t>(program.num_locals, 0),
      {},
      program,
      map,
      mem_ctx,
      recursion_depth,
      0,
      false,
      0};

  for (std::size_t k = 0; k < args.size(); ++k) ctx.locals[k] = args[k];

  const auto& code = program.code;
  std::size_t pc = 0;

  while (!ctx.halted) {
    if (ctx.executed >= kMaxExecutedInstructions) {
      result.error = VmError::kInstructionBudgetExceeded;
      result.instructions_executed = ctx.executed;
      return result;
    }
    ++ctx.executed;

    auto decoded_op = map.Decode(code[pc]);
    Opcode op = *decoded_op;
    const std::uint8_t* operand = (pc + 1 < code.size()) ? &code[pc + 1] : nullptr;
    int operand_len = OperandBytes(op);
    std::size_t next_pc = pc + 1 + static_cast<std::size_t>(operand_len);

    TableOpcodeHandler handler = dispatch_table[static_cast<std::uint8_t>(op)];
    if (!handler) {
      result.error = VmError::kVerificationFailed;
      result.instructions_executed = ctx.executed;
      return result;
    }

    VmError err = handler(ctx, operand, next_pc);
    if (err != VmError::kNone) {
      result.error = err;
      result.instructions_executed = ctx.executed;
      return result;
    }

    pc = next_pc;
  }

  result.error = VmError::kNone;
  result.value = ctx.return_val;
  result.instructions_executed = ctx.executed;
  return result;
}

}  // namespace rtprotect::vm
