// obfuscation/checksum_flattened.h
//
// A control-flow-flattened rewrite of examples::NativeChecksum
// (examples/checksum_reference.h), demonstrating "control-flow
// transformations that preserve semantics" (brief §4) on one concrete
// function rather than as an abstract description.
//
// WHAT FLATTENING IS, HERE: the original function's natural control flow
// (a single `while` loop with an obvious back-edge) is rewritten as one
// dispatch loop plus a `switch` over an explicit state variable. A
// decompiler or a human reading a disassembly no longer sees a simple,
// recognizable loop shape; every "jump" is instead a write to `state`
// followed by a jump back to the same dispatcher, so the control-flow
// graph has one basic block with many incoming/outgoing edges instead of
// several blocks with an obvious loop-back structure.
//
// WHAT THIS DOES NOT ACHIEVE, stated plainly per docs/THREAT_MODEL.md's
// standard: this is a basic, SOURCE-level demonstration of the technique,
// not the kind of flattening a real obfuscator built as an LLVM pass would
// apply (which typically also adds opaque predicates, splits blocks
// further, and obscures the state variable's updates themselves). A
// moderately capable decompiler, or a human spending real time on it, can
// still recover the original loop structure from this -- flattening this
// shallow mainly defeats quick/automated pattern-matching on CFG shape,
// not a dedicated manual analysis. See docs/OBFUSCATION.md's classification
// table for where this sits relative to other techniques.
//
// Semantic equivalence to the original is the whole point and is proven
// by test, not asserted: see tests/test_checksum_flattened.cpp's
// Flattened_MatchesNativeReference test, which runs both implementations
// across the same input set examples/ uses for its own parity tests.

#pragma once

#include <cstdint>

namespace rtprotect::obfuscation {

inline std::int64_t FlattenedChecksum(std::int64_t x) {
  enum State { kCheck, kBody, kDone };
  State state = kCheck;
  std::int64_t acc = 0;

  for (;;) {
    switch (state) {
      case kCheck:
        state = (x != 0) ? kBody : kDone;
        break;
      case kBody: {
        std::int64_t digit = x % 10;
        acc = (acc * 31 + digit) % 1000000007;
        x = x / 10;
        state = kCheck;
        break;
      }
      case kDone:
        return acc;
    }
  }
}

}  // namespace rtprotect::obfuscation
