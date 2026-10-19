// bench/benchmark_harness.h
//
// A small, honest benchmarking harness: warm-up iterations discarded, N
// independent trials each timed as a whole (not iteration-by-iteration,
// which would be dominated by clock-call overhead for cheap functions),
// and full statistical reporting (min/max/median/mean/stddev) rather than
// a single number -- replacing Phase 5's explicitly-flagged "indicative
// only, single run" methodology with something that at least reports its
// own noise honestly.
//
// METHODOLOGY LIMITATION, stated plainly rather than glossed over: this
// still runs on shared, non-isolated hardware (a sandboxed container, not
// a dedicated benchmarking machine) with no CPU pinning, no governor/
// frequency-scaling control, and no isolation from other load. Reporting
// a full distribution (not just one number) makes that noise visible
// instead of hiding it, but it does not eliminate the noise. Treat the
// relative shape of results (does A consistently sit above B's range, or
// do their ranges overlap) as more trustworthy than any single absolute
// number.

#pragma once

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <string>
#include <vector>

namespace rtprotect::bench {

struct BenchStats {
  std::vector<double> trial_ms;  // one total elapsed time per trial, in milliseconds

  double Min() const { return *std::min_element(trial_ms.begin(), trial_ms.end()); }
  double Max() const { return *std::max_element(trial_ms.begin(), trial_ms.end()); }

  double Mean() const {
    double sum = 0;
    for (double v : trial_ms) sum += v;
    return sum / static_cast<double>(trial_ms.size());
  }

  double Median() const {
    std::vector<double> sorted = trial_ms;
    std::sort(sorted.begin(), sorted.end());
    std::size_t n = sorted.size();
    return (n % 2 == 1) ? sorted[n / 2] : (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0;
  }

  double StdDev() const {
    double mean = Mean();
    double sum_sq = 0;
    for (double v : trial_ms) sum_sq += (v - mean) * (v - mean);
    return std::sqrt(sum_sq / static_cast<double>(trial_ms.size()));
  }
};

// Runs `fn` `warmup_iters` times (discarded), then `trial_count` trials of
// `iters_per_trial` calls each, timing each trial as a whole. `fn` must be
// callable with no arguments and should include whatever "use the result"
// step is needed to stop the compiler from optimizing the call away
// entirely (e.g. accumulate into a volatile or externally-observable sink).
template <typename Fn>
BenchStats RunBenchmark(std::size_t warmup_iters, std::size_t trial_count,
                         std::size_t iters_per_trial, Fn&& fn) {
  for (std::size_t i = 0; i < warmup_iters; ++i) fn();

  BenchStats stats;
  stats.trial_ms.reserve(trial_count);
  for (std::size_t t = 0; t < trial_count; ++t) {
    auto t0 = std::chrono::steady_clock::now();
    for (std::size_t i = 0; i < iters_per_trial; ++i) fn();
    auto t1 = std::chrono::steady_clock::now();
    stats.trial_ms.push_back(std::chrono::duration<double, std::milli>(t1 - t0).count());
  }
  return stats;
}

inline void PrintStatsRow(const std::string& name, const BenchStats& stats,
                           std::size_t iters_per_trial) {
  double median_ns_per_iter = (stats.Median() * 1e6) / static_cast<double>(iters_per_trial);
  std::printf("%-28s  median=%8.3fms  mean=%8.3fms  min=%8.3fms  max=%8.3fms  stddev=%7.3fms  (%.1f ns/iter)\n",
              name.c_str(), stats.Median(), stats.Mean(), stats.Min(), stats.Max(), stats.StdDev(),
              median_ns_per_iter);
}

}  // namespace rtprotect::bench
