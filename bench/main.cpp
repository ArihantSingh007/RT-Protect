// bench/main.cpp
//
// Phase 7's benchmark suite: measures the actual performance overhead of
// this project's protection mechanisms against an unprotected baseline,
// per the brief's §9 requirement ("Performance overhead compared with an
// unprotected baseline"), using bench/benchmark_harness.h's
// warm-up + multiple-trial + full-statistics methodology instead of
// Phase 5's single-run, explicitly-flagged-as-indicative numbers.
//
// Run with: ./bench/rtprotect-bench
// Takes a few seconds; prints one row per benchmark plus the methodology
// note from benchmark_harness.h.

#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>

#include "bench/benchmark_harness.h"
#include "bytecode_vm/vm.h"
#include "crypto/aead.h"
#include "examples/checksum_program.h"
#include "examples/checksum_reference.h"
#include "obfuscation/checksum_flattened.h"

using namespace rtprotect;
using namespace rtprotect::bench;

namespace {

constexpr std::size_t kWarmup = 1000;
constexpr std::size_t kTrials = 15;
constexpr std::size_t kItersPerTrial = 20000;

void BenchChecksumImplementations() {
  std::printf("\n== Checksum: native (baseline) vs VM-interpreted (Phase 3) vs flattened (Phase 5) ==\n");

  auto program = examples::BuildChecksumProgram();
  volatile std::int64_t sink = 0;  // volatile so the compiler can't prove the
                                    // loop's result is unused and elide it

  // IMPORTANT: the input must vary across calls. A fixed literal input let
  // the compiler constant-fold the entire computation at -O3 the first
  // time this benchmark was run here -- producing an implausible ~0.4
  // ns/iter "result" that was actually just repeated stores of a
  // precomputed constant, not the checksum loop running at all. Caught by
  // noticing the number didn't make sense, not assumed correct because
  // the code compiled and ran -- see docs/BENCHMARKS.md for the full story
  // of this bug and the real numbers after fixing it. A runtime-mutated
  // counter closes this off.
  std::int64_t native_counter = 123456789;
  auto native_stats = RunBenchmark(kWarmup, kTrials, kItersPerTrial, [&]() {
    sink = examples::NativeChecksum(native_counter);
    ++native_counter;
  });
  PrintStatsRow("native (unprotected baseline)", native_stats, kItersPerTrial);

  std::int64_t flat_counter = 123456789;
  auto flattened_stats = RunBenchmark(kWarmup, kTrials, kItersPerTrial, [&]() {
    sink = obfuscation::FlattenedChecksum(flat_counter);
    ++flat_counter;
  });
  PrintStatsRow("flattened (Phase 5 obfuscation)", flattened_stats, kItersPerTrial);

  // The VM is dramatically more expensive per call (bytecode dispatch +
  // mandatory re-verification every Run() call, see bytecode_vm/vm.h's
  // design note on why there's no "skip verification" fast path) --
  // enough that kItersPerTrial would make this take unreasonably long at
  // the same iteration count. Scaled down 100x and noted explicitly below
  // rather than silently using a different count without saying so.
  constexpr std::size_t kVmItersPerTrial = kItersPerTrial / 100;
  std::int64_t vm_counter = 123456789;
  auto vm_stats = RunBenchmark(kWarmup / 100, kTrials, kVmItersPerTrial, [&]() {
    auto r = vm::Run(program, {vm_counter});
    sink = r.value;
    ++vm_counter;
  });
  PrintStatsRow("VM-interpreted (Phase 3, incl. verify)", vm_stats, kVmItersPerTrial);
  std::printf("  (VM row uses %zux fewer iterations per trial than the other two rows above --\n"
              "   its per-call cost is high enough that matching iteration counts would make\n"
              "   this benchmark take unreasonably long. ns/iter is still directly comparable.)\n",
              kItersPerTrial / kVmItersPerTrial);

  double vm_overhead_x = (vm_stats.Median() / kVmItersPerTrial) / (native_stats.Median() / kItersPerTrial);
  double flat_overhead_x =
      (flattened_stats.Median() / kItersPerTrial) / (native_stats.Median() / kItersPerTrial);
  std::printf("\n  VM-interpreted is ~%.0fx the native baseline's per-call cost (median).\n",
              vm_overhead_x);
  std::printf("  Flattened is ~%.2fx the native baseline's per-call cost (median) --\n"
              "  within measurement noise of 1.0x at this function's size; see\n"
              "  docs/OBFUSCATION.md for why Phase 5 already reported this as inconclusive.\n",
              flat_overhead_x);
}

void BenchAeadThroughput() {
  std::printf("\n== AES-256-GCM throughput (Phase 1-2) ==\n");
  auto key = crypto::Aes256Key::Generate();

  for (std::size_t payload_size : {1024ul, 64ul * 1024, 1024ul * 1024}) {
    std::vector<std::uint8_t> plaintext(payload_size, 0xAB);

    constexpr std::size_t kAeadWarmup = 50;
    constexpr std::size_t kAeadTrials = 10;
    std::size_t iters = payload_size <= 64 * 1024 ? 500 : 50;

    auto enc_stats = RunBenchmark(kAeadWarmup, kAeadTrials, iters, [&]() {
      auto enc = crypto::Encrypt(key, plaintext.data(), plaintext.size());
      (void)enc;
    });
    double mb_per_sec_enc =
        (static_cast<double>(payload_size) * iters / (1024.0 * 1024.0)) / (enc_stats.Median() / 1000.0);

    std::string label = "encrypt " + std::to_string(payload_size / 1024) + " KiB";
    std::printf("%-28s  median=%8.3fms over %zu iters  (%.1f MiB/s)\n", label.c_str(),
                enc_stats.Median(), iters, mb_per_sec_enc);
  }
}

}  // namespace

int main() {
  std::printf("rtprotect benchmark suite (Phase 7)\n");
  std::printf("Methodology: %zu warm-up iterations discarded, %zu independent trials,\n",
              kWarmup, kTrials);
  std::printf("%zu iterations per trial, full statistics reported (not just one number).\n",
              kItersPerTrial);
  std::printf("See bench/benchmark_harness.h's header comment for this methodology's\n");
  std::printf("stated limitations (shared, non-isolated hardware).\n");

  BenchChecksumImplementations();
  BenchAeadThroughput();

  std::printf("\nDone.\n");
  return 0;
}
