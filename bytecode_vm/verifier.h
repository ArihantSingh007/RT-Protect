// bytecode_vm/verifier.h
//
// Validates a Program BEFORE it is ever executed. The interpreter
// (bytecode_vm/vm.h) trusts a verified program completely and performs no
// redundant bounds checks in its hot loop -- all safety is established
// here, once, statically. This mirrors how real bytecode VMs (JVM, CLR)
// separate "verification" from "execution" rather than re-checking safety
// invariants on every instruction dispatch.
//
// A program that fails verification is never run, full stop -- there is no
// "best effort" execution of a program this verifier rejects.

#pragma once

#include <cstdint>
#include <optional>
#include <unordered_set>

#include "bytecode_vm/program.h"

namespace rtprotect::vm {

enum class VerifyError {
  kNone = 0,
  kEmptyProgram,
  kCodeTooLarge,
  kTooManyConstants,
  kTooManyLocals,
  kInvalidOpcode,          // a byte that doesn't decode to a known Opcode
  kTruncatedOperand,       // an opcode's operand bytes run past end of code
  kConstantIndexOutOfRange,
  kLocalIndexOutOfRange,
  kJumpTargetOutOfRange,   // jump target >= code.size()
  kJumpTargetMisaligned,   // jump target does not point to an instruction start
  kControlFlowFallsOffEnd,  // a REACHABLE instruction's fallthrough
                            // successor (the next instruction, for any
                            // opcode other than kJmp/kRet; the not-taken
                            // branch, for kJz/kJnz) would be past the end
                            // of the code array. Supersedes an earlier,
                            // narrower heuristic ("the textually last byte
                            // in the stream must be kRet") that both
                            // over-rejected (a program ending in trailing
                            // dead code after a real kRet would fail even
                            // though nothing reachable was actually
                            // unsafe) and under-protected (it said nothing
                            // about whether MID-stream reachable fallthrough
                            // could run off the end, which pass 1's
                            // per-instruction bounds checking already
                            // prevented for every instruction except
                            // reachability of the textually-last one, the
                            // one case the old heuristic happened to
                            // catch). This check is computed as part of
                            // the same worklist traversal that computes
                            // kStackDepthConflict/kStaticStackUnderflow/
                            // kStaticStackOverflow below, over exactly the
                            // set of instructions reachable from offset 0
                            // -- see verifier.cpp's Pass 3.
  kStackDepthConflict,     // two different reachable control-flow paths
                           // arrive at the same instruction with different
                           // statically-known stack depths -- e.g. one
                           // path pushes an extra value before a jump that
                           // another path doesn't take. The VM's runtime
                           // stack bookkeeping assumes a single, consistent
                           // depth at every point in the program; an
                           // inconsistency here would be undetectable
                           // until some specific, maybe-rare runtime path
                           // actually diverges, as either a stack
                           // underflow/overflow far from its real cause or
                           // (if both still happen to fit within bounds) a
                           // VM program silently computing a different
                           // thing than its author intended, depending on
                           // which path happened to run.
  kStaticStackUnderflow,   // an instruction's required operand count
                           // exceeds what's provably on the stack along
                           // some reachable path to it -- the static
                           // counterpart to vm.cpp's runtime
                           // VmError::kStackUnderflow check, catching the
                           // same class of error before execution rather
                           // than only during it.
  kStaticStackOverflow,    // the statically-computed stack depth along
                           // some reachable path would exceed
                           // kMaxStackDepth -- the static counterpart to
                           // vm.cpp's runtime VmError::kStackOverflow.
};

const char* ToString(VerifyError error);

class OpcodeMap;

// On success, returns the set of byte offsets where an instruction begins
// (used internally to validate jump targets, exposed here mainly so tests
// can inspect it). On failure, returns std::nullopt and sets *out_error.
// If opcode_map is non-null, instruction opcodes are decoded through the map.
std::optional<std::unordered_set<std::uint32_t>> VerifyProgram(
    const Program& program, VerifyError* out_error, const OpcodeMap* opcode_map = nullptr);

}  // namespace rtprotect::vm
