#include "bytecode_vm/verifier.h"

#include <unordered_map>
#include <vector>

#include "bytecode_vm/opcode.h"

namespace rtprotect::vm {

const char* ToString(VerifyError error) {
  switch (error) {
    case VerifyError::kNone: return "none";
    case VerifyError::kEmptyProgram: return "program has no code";
    case VerifyError::kCodeTooLarge: return "code exceeds kMaxCodeBytes";
    case VerifyError::kTooManyConstants: return "constant pool exceeds kMaxConstants";
    case VerifyError::kTooManyLocals: return "num_locals exceeds kMaxLocals";
    case VerifyError::kInvalidOpcode: return "unrecognized opcode byte";
    case VerifyError::kTruncatedOperand: return "operand runs past end of code";
    case VerifyError::kConstantIndexOutOfRange: return "PUSH_CONST index out of range";
    case VerifyError::kLocalIndexOutOfRange: return "local variable index out of range";
    case VerifyError::kJumpTargetOutOfRange: return "jump target beyond code bounds";
    case VerifyError::kJumpTargetMisaligned: return "jump target is not an instruction boundary";
    case VerifyError::kControlFlowFallsOffEnd:
      return "reachable control flow would execute past the end of the code array";
    case VerifyError::kStackDepthConflict:
      return "two reachable paths reach the same instruction with different stack depths";
    case VerifyError::kStaticStackUnderflow:
      return "an instruction's operands exceed what is provably on the stack";
    case VerifyError::kStaticStackOverflow:
      return "statically-computed stack depth would exceed kMaxStackDepth";
  }
  return "unknown VerifyError";
}

namespace {

std::uint16_t ReadU16(const std::uint8_t* p) {
  return static_cast<std::uint16_t>(p[0]) | (static_cast<std::uint16_t>(p[1]) << 8);
}

// How many values an opcode requires already on the stack (`required`,
// used for the static-underflow check) and the NET stack-depth change it
// causes (`net_change`, which can be negative). kDup is notable: it
// requires 1 (it peeks the top) but its net change is +1 (it then pushes
// a copy) -- distinct from a simple "pops N, pushes M" pair because the
// peeked value isn't consumed.
struct StackEffect {
  int required;
  int net_change;
};

StackEffect GetStackEffect(Opcode op) {
  switch (op) {
    case Opcode::kPushConst:
    case Opcode::kPushLocal:
      return {0, 1};
    case Opcode::kStoreLocal:
      return {1, -1};
    case Opcode::kDup:
      return {1, 1};
    case Opcode::kPop:
      return {1, -1};
    case Opcode::kAdd:
    case Opcode::kSub:
    case Opcode::kMul:
    case Opcode::kDiv:
    case Opcode::kMod:
    case Opcode::kAnd:
    case Opcode::kOr:
    case Opcode::kXor:
    case Opcode::kCmpEq:
    case Opcode::kCmpLt:
    case Opcode::kCmpGt:
      return {2, -1};
    case Opcode::kNot:
      return {1, 0};
    case Opcode::kJmp:
      return {0, 0};
    case Opcode::kJz:
    case Opcode::kJnz:
      return {1, -1};
    case Opcode::kRet:
      return {1, -1};
  }
  return {0, 0};  // unreachable: every Opcode value is handled above, and
                   // IsValidOpcode() already rejected anything that isn't
                   // a valid Opcode before this function is ever called
}

}  // namespace

std::optional<std::unordered_set<std::uint32_t>> VerifyProgram(const Program& program,
                                                                 VerifyError* out_error) {
  auto fail = [&](VerifyError e) -> std::optional<std::unordered_set<std::uint32_t>> {
    if (out_error) *out_error = e;
    return std::nullopt;
  };

  if (program.code.empty()) return fail(VerifyError::kEmptyProgram);
  if (program.code.size() > kMaxCodeBytes) return fail(VerifyError::kCodeTooLarge);
  if (program.constants.size() > kMaxConstants) return fail(VerifyError::kTooManyConstants);
  if (program.num_locals > kMaxLocals) return fail(VerifyError::kTooManyLocals);

  const auto& code = program.code;
  const std::size_t n = code.size();

  // Pass 1: linear decode. Collect every valid instruction-start offset and
  // validate every opcode/operand is well-formed and every non-jump operand
  // (constant index, local index) is in range. Jump target *values* are
  // collected but validated against instruction-start offsets in pass 2,
  // since a forward jump's target may not have been visited yet.
  std::unordered_set<std::uint32_t> instruction_starts;
  std::vector<std::pair<std::uint32_t, std::uint16_t>> jump_targets;  // (instr offset, target)

  std::size_t i = 0;
  while (i < n) {
    std::uint8_t byte = code[i];
    if (!IsValidOpcode(byte)) return fail(VerifyError::kInvalidOpcode);

    Opcode op = static_cast<Opcode>(byte);
    int operand_len = OperandBytes(op);  // already known valid, so >= 0
    instruction_starts.insert(static_cast<std::uint32_t>(i));

    if (i + 1 + static_cast<std::size_t>(operand_len) > n) {
      return fail(VerifyError::kTruncatedOperand);
    }

    switch (op) {
      case Opcode::kPushConst: {
        std::uint16_t idx = ReadU16(&code[i + 1]);
        if (idx >= program.constants.size()) {
          return fail(VerifyError::kConstantIndexOutOfRange);
        }
        break;
      }
      case Opcode::kPushLocal:
      case Opcode::kStoreLocal: {
        std::uint8_t idx = code[i + 1];
        if (idx >= program.num_locals) {
          return fail(VerifyError::kLocalIndexOutOfRange);
        }
        break;
      }
      case Opcode::kJmp:
      case Opcode::kJz:
      case Opcode::kJnz: {
        std::uint16_t target = ReadU16(&code[i + 1]);
        jump_targets.emplace_back(static_cast<std::uint32_t>(i), target);
        break;
      }
      default:
        break;
    }

    i += 1 + static_cast<std::size_t>(operand_len);
  }
  // i == n exactly here, since every step consumes exactly as many bytes as
  // the opcode declares and we bounds-checked before consuming -- there is
  // no way to land mid-instruction at loop exit.

  // Pass 2: every jump target must land exactly on an instruction start.
  for (const auto& [instr_offset, target] : jump_targets) {
    (void)instr_offset;
    if (target >= n || instruction_starts.find(target) == instruction_starts.end()) {
      return fail(target >= n ? VerifyError::kJumpTargetOutOfRange
                               : VerifyError::kJumpTargetMisaligned);
    }
  }

  // Pass 3: static stack-depth analysis via a worklist traversal starting
  // at offset 0 (every program's single entry point) with depth 0. This
  // simultaneously computes REACHABILITY (an offset is reachable iff this
  // traversal ever visits it) and proves, for every reachable instruction,
  // that: (a) enough values are provably on the stack before it executes
  // (kStaticStackUnderflow if not), (b) the stack never provably exceeds
  // kMaxStackDepth (kStaticStackOverflow if it would), (c) every way of
  // reaching a given instruction agrees on the stack depth at that point
  // (kStackDepthConflict if two paths disagree), and (d) no reachable
  // instruction's fallthrough successor runs past the end of the code
  // array (kControlFlowFallsOffEnd) -- see that error's comment in
  // verifier.h for how this supersedes an earlier, narrower heuristic.
  //
  // This does NOT prove the program terminates -- a reachable Jmp-only
  // loop with no reachable Ret passes this analysis cleanly (nothing
  // about its stack usage or control-flow bounds is unsafe) and is
  // instead caught, if it actually runs forever, by vm.cpp's runtime
  // kMaxExecutedInstructions budget. Proving termination in general is
  // undecidable for a language with backward jumps; this project's
  // position on that (static analysis for safety properties, a runtime
  // budget as the termination backstop) is unchanged by adding this pass
  // -- see bytecode_vm/vm.h's design note on kInstructionBudgetExceeded.
  std::unordered_map<std::uint32_t, int> depth_at;
  std::vector<std::uint32_t> worklist;
  depth_at[0] = 0;
  worklist.push_back(0);

  while (!worklist.empty()) {
    std::uint32_t offset = worklist.back();
    worklist.pop_back();
    int depth = depth_at[offset];

    Opcode op = static_cast<Opcode>(code[offset]);
    int operand_len = OperandBytes(op);
    StackEffect effect = GetStackEffect(op);

    if (depth < effect.required) {
      return fail(VerifyError::kStaticStackUnderflow);
    }
    int new_depth = depth + effect.net_change;
    if (static_cast<std::size_t>(new_depth) > kMaxStackDepth) {
      return fail(VerifyError::kStaticStackOverflow);
    }

    // Returns true on success; on a depth conflict, sets *error and
    // returns false. Does not re-enqueue an offset already visited with a
    // consistent depth (the traversal has already covered everything
    // reachable from it).
    auto propagate = [&](std::uint32_t succ, VerifyError* error) -> bool {
      auto it = depth_at.find(succ);
      if (it != depth_at.end()) {
        if (it->second != new_depth) {
          *error = VerifyError::kStackDepthConflict;
          return false;
        }
        return true;
      }
      depth_at[succ] = new_depth;
      worklist.push_back(succ);
      return true;
    };

    VerifyError propagate_error = VerifyError::kNone;
    if (op == Opcode::kRet) {
      // Terminal: no successor to propagate to.
    } else if (op == Opcode::kJmp) {
      std::uint16_t target = ReadU16(&code[offset + 1]);
      if (!propagate(target, &propagate_error)) return fail(propagate_error);
    } else if (op == Opcode::kJz || op == Opcode::kJnz) {
      std::uint16_t target = ReadU16(&code[offset + 1]);
      if (!propagate(target, &propagate_error)) return fail(propagate_error);
      std::uint32_t fallthrough = static_cast<std::uint32_t>(offset + 1 + operand_len);
      if (fallthrough >= n) return fail(VerifyError::kControlFlowFallsOffEnd);
      if (!propagate(fallthrough, &propagate_error)) return fail(propagate_error);
    } else {
      std::uint32_t fallthrough = static_cast<std::uint32_t>(offset + 1 + operand_len);
      if (fallthrough >= n) return fail(VerifyError::kControlFlowFallsOffEnd);
      if (!propagate(fallthrough, &propagate_error)) return fail(propagate_error);
    }
  }

  if (out_error) *out_error = VerifyError::kNone;
  return instruction_starts;
}

}  // namespace rtprotect::vm
