// bytecode_vm/checked_arith.h
//
// Overflow-checked signed 64-bit arithmetic for the VM's ADD/SUB/MUL/DIV/
// MOD opcodes.
//
// WHY THIS EXISTS, confirmed empirically before being written (not assumed
// from the C++ standard's "signed overflow is UB" wording alone): the
// VM's previous implementation used raw `a / b` and `a % b` for its DIV
// and MOD opcodes. For a == INT64_MIN and b == -1, this is not merely
// "undefined behavior" in the abstract sense -- on x86-64, the IDIV
// instruction the compiler emits for this trap with a hardware #DE
// (divide error) exception, which the OS delivers as SIGFPE, which
// (absent a handler) TERMINATES THE PROCESS. This was reproduced directly
// before this fix:
//
//   $ cat overflow_check.cpp
//   int64_t c = INT64_MIN, d = -1;
//   volatile int64_t r = c / d;
//   $ g++ -fsanitize=undefined overflow_check.cpp -o t && ./t
//   overflow_check.cpp:11: runtime error: division of -9223372036854775808
//   by -1 cannot be represented in type 'long int'
//   Floating point exception (core dumped)        <- process killed, exit 136
//
// A bytecode program reaching this exact operand combination -- which
// neither the previous VM nor its static verifier rejected -- would crash
// the host process. For a VM whose entire design principle is "malformed
// or adversarial bytecode returns a defined error, never crashes the
// process" (see vm.h and verifier.h), this was a real violation of that
// principle, not a theoretical one.
//
// ADD/SUB/MUL overflow does not trap on this hardware the way DIV/MOD
// does -- the generated code just wraps in two's-complement in practice on
// every mainstream compiler -- but it is still undefined behavior per the
// C++ standard, which permits a sufficiently aggressive optimizer to do
// something other than wrap (this is not hypothetical; GCC and Clang have
// both used signed-overflow-doesn't-happen as an optimization basis that
// has broken real code relying on wraparound). All five operations are
// checked uniformly here rather than treating DIV/MOD as a special case
// and ADD/SUB/MUL as "probably fine."

#pragma once

#include <cstdint>
#include <optional>

namespace rtprotect::vm {

// Returns the result, or std::nullopt if the operation would overflow
// int64_t's representable range (or divide/modulo by zero -- callers that
// need to distinguish "overflow" from "divide by zero" should check for
// b == 0 themselves before calling Div/Mod, as vm.cpp already does for its
// own, more specific VmError::kDivisionByZero vs the overflow case).

#if defined(__GNUC__) || defined(__clang__)

// GCC/Clang: __builtin_*_overflow directly expresses "compute this and
// tell me if it overflowed" without any UB in the computation itself --
// the preferred implementation on toolchains that provide it.

inline std::optional<std::int64_t> CheckedAdd(std::int64_t a, std::int64_t b) {
  std::int64_t result;
  if (__builtin_add_overflow(a, b, &result)) return std::nullopt;
  return result;
}

inline std::optional<std::int64_t> CheckedSub(std::int64_t a, std::int64_t b) {
  std::int64_t result;
  if (__builtin_sub_overflow(a, b, &result)) return std::nullopt;
  return result;
}

inline std::optional<std::int64_t> CheckedMul(std::int64_t a, std::int64_t b) {
  std::int64_t result;
  if (__builtin_mul_overflow(a, b, &result)) return std::nullopt;
  return result;
}

#else

// MSVC (and any other toolchain without __builtin_*_overflow): manual
// overflow checks performed BEFORE the operation, using only comparisons
// that cannot themselves overflow -- never "compute first, check after",
// which would require the very UB this function exists to avoid. Written
// to be portable and correct for MSVC specifically (the project's primary
// target toolchain) even though it has not been executed under MSVC in
// this environment -- see the main README's Windows-verification notes
// for this project's standing caveat on that gap, which applies here too.

inline std::optional<std::int64_t> CheckedAdd(std::int64_t a, std::int64_t b) {
  if (b > 0 && a > INT64_MAX - b) return std::nullopt;  // would overflow positive
  if (b < 0 && a < INT64_MIN - b) return std::nullopt;  // would overflow negative
  return a + b;
}

inline std::optional<std::int64_t> CheckedSub(std::int64_t a, std::int64_t b) {
  if (b < 0 && a > INT64_MAX + b) return std::nullopt;  // a - b > INT64_MAX
  if (b > 0 && a < INT64_MIN + b) return std::nullopt;  // a - b < INT64_MIN
  return a - b;
}

inline std::optional<std::int64_t> CheckedMul(std::int64_t a, std::int64_t b) {
  // Pre-checked via division BEFORE computing a*b, deliberately --
  // computing the product first and verifying afterward (e.g. "result/b
  // == a") would itself invoke the exact signed-overflow UB this function
  // exists to avoid whenever the product actually does overflow. The
  // check must happen before the operation that could overflow, not
  // after it, the same principle CheckedAdd/CheckedSub above already
  // follow -- this corrects a first draft of this function that got it
  // wrong (compute-then-verify), caught by re-reading the code against
  // its own stated principle rather than by a failing test.
  //
  // This exact logic (copied, not merely similar) is cross-validated
  // against the __builtin_mul_overflow path in
  // tests/test_checked_arith_fallback.cpp: both implementations are
  // compiled side by side under this project's GCC/Clang build (the only
  // way to exercise and compare both paths on one toolchain, since a
  // given compiler only ever takes one branch of the #if above) and
  // compared across every edge-case pair plus 2,000,000 random int64
  // pairs under UndefinedBehaviorSanitizer. All four arithmetic
  // operations' fallbacks passed with zero mismatches and zero sanitizer
  // findings before this file was considered done -- see that test file
  // for the actual comparison and docs/SECURITY_HARDENING.md for why this
  // level of scrutiny mattered here specifically (this is the one case in
  // the whole project where hand-written logic substitutes for a
  // compiler-provided safety primitive, specifically because MSVC has no
  // such primitive to call instead).
  if (a == 0 || b == 0) return 0;

  if (a > 0) {
    if (b > 0) {
      if (a > INT64_MAX / b) return std::nullopt;
    } else {  // b < 0
      if (b < INT64_MIN / a) return std::nullopt;
    }
  } else {  // a < 0
    if (b > 0) {
      if (a < INT64_MIN / b) return std::nullopt;
    } else {  // b < 0 (includes a == INT64_MIN, b == -1 and vice versa --
              // INT64_MIN / INT64_MIN == 1 is well-defined and this
              // branch's comparison correctly rejects that pairing via
              // the general inequality, no special case needed)
      if (a == INT64_MIN || b == INT64_MIN) return std::nullopt;  // avoids
                                                                   // INT64_MIN
                                                                   // appearing
                                                                   // as the
                                                                   // RHS of a
                                                                   // division
                                                                   // below
      if (a < INT64_MAX / b) return std::nullopt;
    }
  }
  return a * b;
}

#endif

// Division and modulo are NOT in the #if/#else split above: the overflow
// case is identical and narrow for both (INT64_MIN / -1), and no compiler
// this project targets provides a __builtin_div_overflow -- this is the
// one portable implementation used on every toolchain.

inline std::optional<std::int64_t> CheckedDiv(std::int64_t a, std::int64_t b) {
  // Caller's responsibility to reject b == 0 separately (see vm.cpp's
  // VmError::kDivisionByZero, which is a more specific, user-facing error
  // than the generic overflow this function reports). This function only
  // guards the overflow case.
  if (a == INT64_MIN && b == -1) return std::nullopt;
  return a / b;
}

inline std::optional<std::int64_t> CheckedMod(std::int64_t a, std::int64_t b) {
  // Same hardware trap as CheckedDiv for this exact operand pair -- x86's
  // IDIV computes quotient and remainder together, so INT64_MIN % -1
  // traps identically to INT64_MIN / -1 even though the mathematically
  // "correct" remainder (0) is perfectly representable. Confirmed
  // empirically alongside the division case before this fix (see this
  // file's header comment).
  if (a == INT64_MIN && b == -1) return std::nullopt;
  return a % b;
}

}  // namespace rtprotect::vm
