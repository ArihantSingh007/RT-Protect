#include "obfuscation/checksum_flattened.h"

#include <chrono>
#include <cstdio>

#include "examples/checksum_reference.h"
#include "tests/micro_test.h"

using namespace rtprotect;

MT_TEST(Flattened_MatchesNativeReference) {
  // Same input set used in tests/test_protected_checksum.cpp's VM-vs-native
  // parity test, so all three implementations (native, VM, flattened) are
  // checked against the same cases.
  std::int64_t inputs[] = {
      0, 1, 9, 10, 123, 999999999, 1000000000, 7, 42, 2147483647,
  };
  for (std::int64_t x : inputs) {
    std::int64_t expected = examples::NativeChecksum(x);
    std::int64_t actual = obfuscation::FlattenedChecksum(x);
    MT_CHECK(actual == expected);
  }
}

MT_TEST(Flattened_HandlesZeroAndNegativeInputs) {
  // Edge cases worth calling out explicitly: 0 never enters either
  // implementation's loop body at all, and C++'s truncating-toward-zero
  // integer division/modulo semantics must match identically between the
  // natural-loop and flattened versions for negative inputs (both use the
  // same `%`/`/` operators, but this is exactly the kind of behavior a
  // careless rewrite could silently change).
  std::int64_t inputs[] = {0, -1, -9, -123, -999999999};
  for (std::int64_t x : inputs) {
    MT_CHECK(obfuscation::FlattenedChecksum(x) == examples::NativeChecksum(x));
  }
}

// Not a regression-gated performance test (timing is too noisy in a shared
// CI/sandbox environment to assert a threshold against) -- this prints an
// indicative measurement to stdout so the actual numbers are visible in
// the test log, per the brief's requirement to report real measurements
// rather than invent them. See docs/OBFUSCATION.md for the captured
// numbers from this environment and an explicit note on this methodology's
// limits (no warm-up control, no isolation from other load, single run)
// -- Phase 7 is where a real benchmark methodology belongs.
MT_TEST(Flattened_IndicativeTimingComparison_PrintedNotAsserted) {
  constexpr int kIterations = 200000;
  std::int64_t sink_native = 0, sink_flat = 0;

  auto t0 = std::chrono::steady_clock::now();
  for (int i = 0; i < kIterations; ++i) {
    sink_native += examples::NativeChecksum(123456789 + i);
  }
  auto t1 = std::chrono::steady_clock::now();
  for (int i = 0; i < kIterations; ++i) {
    sink_flat += obfuscation::FlattenedChecksum(123456789 + i);
  }
  auto t2 = std::chrono::steady_clock::now();

  double native_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
  double flat_ms = std::chrono::duration<double, std::milli>(t2 - t1).count();
  std::printf("  [timing] native: %.3f ms, flattened: %.3f ms, over %d iterations (sinks: %lld, %lld)\n",
              native_ms, flat_ms, kIterations, static_cast<long long>(sink_native),
              static_cast<long long>(sink_flat));

  // The only thing actually asserted: both implementations still agree
  // after the timing run (using the sink values forces the compiler to
  // keep the loops from being optimized away entirely).
  MT_CHECK(sink_native == sink_flat);
}

MT_MAIN()
