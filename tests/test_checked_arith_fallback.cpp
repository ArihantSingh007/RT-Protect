// tests/test_checked_arith_fallback.cpp
//
// bytecode_vm/checked_arith.h provides two independent implementations of
// each checked arithmetic operation: one using GCC/Clang's
// __builtin_*_overflow (used when compiling with those compilers, which
// is every build this project has actually run), and a manual fallback
// for MSVC (which has no equivalent builtin). Because the #if in that
// header means only ONE of the two implementations is ever compiled on
// any given toolchain, this project's normal test suite -- which only
// ever runs under GCC/Clang in this environment -- exercises the fallback
// NOT AT ALL by just including and using the header normally.
//
// This test closes that gap the only way available without an actual
// MSVC toolchain: it contains a byte-for-byte copy of the fallback
// implementations (see checked_arith.h's CheckedMul comment, which points
// here) and compares their output against the real __builtin-based path,
// compiled together in one binary under GCC. This cannot replace actually
// building and testing bytecode_vm/checked_arith.h's MSVC branch on real
// MSVC -- that remains outstanding, like every other MSVC-specific gap in
// this project (see the main README's Windows-verification notes) -- but
// it is a real, meaningful check of the fallback's LOGIC, independent of
// which toolchain eventually compiles it.

#include <cstdint>
#include <optional>
#include <random>

#include "tests/micro_test.h"

namespace {

// Verbatim copy of bytecode_vm/checked_arith.h's #else (MSVC) branch. Kept
// in sync by hand -- if you change the fallback logic in checked_arith.h,
// change it here too, or this test stops testing what actually ships.
std::optional<std::int64_t> FallbackAdd(std::int64_t a, std::int64_t b) {
  if (b > 0 && a > INT64_MAX - b) return std::nullopt;
  if (b < 0 && a < INT64_MIN - b) return std::nullopt;
  return a + b;
}

std::optional<std::int64_t> FallbackSub(std::int64_t a, std::int64_t b) {
  if (b < 0 && a > INT64_MAX + b) return std::nullopt;
  if (b > 0 && a < INT64_MIN + b) return std::nullopt;
  return a - b;
}

std::optional<std::int64_t> FallbackMul(std::int64_t a, std::int64_t b) {
  if (a == 0 || b == 0) return 0;
  if (a > 0) {
    if (b > 0) {
      if (a > INT64_MAX / b) return std::nullopt;
    } else {
      if (b < INT64_MIN / a) return std::nullopt;
    }
  } else {
    if (b > 0) {
      if (a < INT64_MIN / b) return std::nullopt;
    } else {
      if (a == INT64_MIN || b == INT64_MIN) return std::nullopt;
      if (a < INT64_MAX / b) return std::nullopt;
    }
  }
  return a * b;
}

// Real __builtin-based path -- what checked_arith.h actually compiles to
// on this toolchain, i.e. the ground truth the fallback is compared
// against.
std::optional<std::int64_t> BuiltinAdd(std::int64_t a, std::int64_t b) {
  std::int64_t r;
  if (__builtin_add_overflow(a, b, &r)) return std::nullopt;
  return r;
}
std::optional<std::int64_t> BuiltinSub(std::int64_t a, std::int64_t b) {
  std::int64_t r;
  if (__builtin_sub_overflow(a, b, &r)) return std::nullopt;
  return r;
}
std::optional<std::int64_t> BuiltinMul(std::int64_t a, std::int64_t b) {
  std::int64_t r;
  if (__builtin_mul_overflow(a, b, &r)) return std::nullopt;
  return r;
}

const std::int64_t kEdgeValues[] = {
    0, 1, -1, 2, -2, INT64_MAX, INT64_MIN, INT64_MAX - 1, INT64_MIN + 1,
    1000000000LL, -1000000000LL, INT64_MAX / 2, INT64_MIN / 2, 46341, -46341,
};

template <typename FallbackFn, typename BuiltinFn>
void CompareAcrossEdgeCases(FallbackFn fallback, BuiltinFn builtin) {
  for (std::int64_t a : kEdgeValues) {
    for (std::int64_t b : kEdgeValues) {
      auto fb = fallback(a, b);
      auto bi = builtin(a, b);
      bool match = (fb.has_value() == bi.has_value()) && (!fb.has_value() || *fb == *bi);
      MT_CHECK(match);
    }
  }
}

template <typename FallbackFn, typename BuiltinFn>
void CompareAcrossRandomInputs(FallbackFn fallback, BuiltinFn builtin, std::uint64_t seed,
                                int iterations) {
  // MT_CHECK is called on every iteration, not only on a detected mismatch
  // -- a loop that only asserts when it already knows something is wrong
  // would vacuously "pass" if the comparison logic itself were broken in a
  // way that always reported a match; calling MT_CHECK unconditionally
  // means this test is actually exercising its own pass/fail signal 2
  // million times, not merely hoping to notice a problem if one happens
  // to occur.
  std::mt19937_64 rng(seed);
  int mismatches_reported = 0;
  for (int i = 0; i < iterations; ++i) {
    std::int64_t a = static_cast<std::int64_t>(rng());
    std::int64_t b = static_cast<std::int64_t>(rng());
    auto fb = fallback(a, b);
    auto bi = builtin(a, b);
    bool match = (fb.has_value() == bi.has_value()) && (!fb.has_value() || *fb == *bi);
    // Cap how many individual failures print (a real mismatch would mean
    // a logic bug that likely reproduces on most inputs, not one that
    // needs 2 million individual failure lines to diagnose), but every
    // iteration still counts toward the test's pass/fail result.
    if (match || mismatches_reported < 5) {
      MT_CHECK(match);
      if (!match) ++mismatches_reported;
    } else if (!match) {
      ++micro_test::failures;
    }
  }
}

}  // namespace

MT_TEST(FallbackAdd_MatchesBuiltin_EdgeCases) {
  CompareAcrossEdgeCases(FallbackAdd, BuiltinAdd);
}
MT_TEST(FallbackSub_MatchesBuiltin_EdgeCases) {
  CompareAcrossEdgeCases(FallbackSub, BuiltinSub);
}
MT_TEST(FallbackMul_MatchesBuiltin_EdgeCases) {
  CompareAcrossEdgeCases(FallbackMul, BuiltinMul);
}

MT_TEST(FallbackAdd_MatchesBuiltin_2MillionRandomInputs) {
  CompareAcrossRandomInputs(FallbackAdd, BuiltinAdd, 999, 2000000);
}
MT_TEST(FallbackSub_MatchesBuiltin_2MillionRandomInputs) {
  CompareAcrossRandomInputs(FallbackSub, BuiltinSub, 999, 2000000);
}
MT_TEST(FallbackMul_MatchesBuiltin_2MillionRandomInputs) {
  CompareAcrossRandomInputs(FallbackMul, BuiltinMul, 12345, 2000000);
}

MT_MAIN()
