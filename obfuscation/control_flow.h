// obfuscation/control_flow.h
//
// Native-Code Control Flow Obfuscation and Arithmetic Hardening Templates.
// Provides:
// 1. Mixed Boolean-Arithmetic (MBA) algebraic substitutions that obscure arithmetic operations.
// 2. Mathematically invariant opaque predicates that defeat static analysis and symbolic execution.
// 3. Control-flow flattening state machine macros that shatter basic blocks and dispatch loops.

#pragma once

#include <cstdint>
#include <type_traits>

namespace rtprotect::obfuscation {

// 1. Mixed Boolean-Arithmetic (MBA) Substitutions
// Replaces standard ALU operators (+, -, ^, ==) with algebraically equivalent bitwise compositions.

template <typename T>
constexpr T MbaAdd(T x, T y) {
  static_assert(std::is_integral_v<T>, "MBA operations require integral types");
  // Identity: x + y == (x ^ y) + 2 * (x & y) == (x | y) + (x & y)
  return static_cast<T>((x ^ y) + ((x & y) << 1));
}

template <typename T>
constexpr T MbaSub(T x, T y) {
  static_assert(std::is_integral_v<T>, "MBA operations require integral types");
  // Identity: x - y == (x ^ y) - 2 * (~x & y)
  return static_cast<T>((x ^ y) - (((~x) & y) << 1));
}

template <typename T>
constexpr T MbaXor(T x, T y) {
  static_assert(std::is_integral_v<T>, "MBA operations require integral types");
  // Identity: x ^ y == (x | y) - (x & y)
  return static_cast<T>((x | y) - (x & y));
}

template <typename T>
constexpr bool MbaEqual(T x, T y) {
  static_assert(std::is_integral_v<T>, "MBA operations require integral types");
  // Identity: (x == y) <=> ((x ^ y) == 0) <=> ((x | y) == (x & y))
  return ((x | y) - (x & y)) == 0;
}

// 2. Mathematically Invariant Opaque Predicates
// Predicates whose evaluation is invariant (always true or always false)
// due to number theory / algebra, but non-trivial for compilers/decompilers to simplify.

// Invariant: For all integers n, n * (n + 1) is always even (consecutive integers).
// Therefore, (n * (n + 1)) % 2 == 0 is always true.
template <typename T>
constexpr bool OpaquePredicateTrue(T seed) {
  static_assert(std::is_integral_v<T>, "Opaque predicate requires integral type");
  T val = static_cast<T>(seed * (seed + 1));
  return (val & 1) == 0;
}

// Invariant: (n * (n + 1)) % 2 != 0 is always false.
template <typename T>
constexpr bool OpaquePredicateFalse(T seed) {
  return !OpaquePredicateTrue(seed);
}

// Invariant: ((x | y) - (x & y)) == (x ^ y) is always true for any x, y.
template <typename T>
constexpr bool OpaquePredicateEqual(T x, T y) {
  return ((x | y) - (x & y)) == (x ^ y);
}

// 3. Control-Flow Flattening State Machine Dispatcher
// Flattens sequential control flow into an indirect dispatch loop over state variables.

#define RTPROTECT_FLATTEN_BEGIN(state_var, initial_state) \
  do { \
    auto state_var = (initial_state); \
    bool __rtp_flatten_active = true; \
    while (__rtp_flatten_active) { \
      switch (state_var) {

#define RTPROTECT_FLATTEN_CASE(state_val) \
        case (state_val):

#define RTPROTECT_FLATTEN_TRANSITION(state_var, next_state) \
        state_var = (next_state); \
        break;

#define RTPROTECT_FLATTEN_EXIT() \
        __rtp_flatten_active = false; \
        break;

#define RTPROTECT_FLATTEN_END() \
        default: \
          __rtp_flatten_active = false; \
          break; \
      } \
    } \
  } while (0)

}  // namespace rtprotect::obfuscation
