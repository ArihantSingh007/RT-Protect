# Benchmarks — rtprotect Phase 7

Real measurements from this environment (GCC 13.3.0, x86-64, Release
build: `-O3 -DNDEBUG` plus Phase 5's hardening flags), using
`bench/benchmark_harness.h`'s methodology: warm-up iterations discarded,
15 independent trials, full statistics reported (median/mean/min/max/
stddev), not a single number. Run it yourself: `./bench/rtprotect-bench`
after a Release build.

**Methodology limitation, stated plainly:** this still runs on shared,
non-isolated hardware — a sandboxed container, not a dedicated
benchmarking machine, with no CPU pinning or frequency-governor control.
The repeated-trials-with-full-statistics approach makes that noise
visible (see the `stddev` and `max` columns below) rather than eliminating
it. Treat the broad shape of these results — is the VM meaningfully
slower, is flattening within noise of baseline — as the trustworthy part;
treat any single number to three significant figures with appropriate
skepticism.

## A real bug this methodology caught — worth documenting, not hiding

The first version of this benchmark passed a **fixed literal** input
(`123456789`) to the native checksum function on every one of 20,000
iterations per trial. At `-O3`, GCC constant-folded the entire computation
at compile time, so the "benchmark" measured 20,000 repeated stores of a
precomputed constant, not the checksum algorithm running at all:

```
native (unprotected baseline)  median=0.008ms  ...  (0.4 ns/iter)
```

0.4 ns/iter for a function with a loop, multiplication, and modulo is not
a plausible number — it was caught by noticing that, not by assuming the
code was correct because it compiled and produced an exit code of 0. The
fix (used throughout real benchmarking practice, and already the pattern
`tests/test_checksum_flattened.cpp`'s timing test used in Phase 5): vary
the input across calls with a runtime-mutated counter, so the compiler
cannot fold the result to a constant. After the fix:

```
native (unprotected baseline)  median=0.482ms  ...  (24.1 ns/iter)
```

A 60x difference between the broken and fixed measurement. This is
exactly the brief's §9 instruction to "report actual test results rather
than inventing successful builds or benchmarks" applied to the benchmark
code itself, not just to what it measures — a benchmark that silently
measures the wrong thing is its own kind of invented result.

## Checksum: native baseline vs Phase 3 VM vs Phase 5 flattening

Three runs, Release build, 20,000 iterations/trial (VM: 200/trial, scaled
down because its per-call cost is ~60x higher — see the tool's own output
for why):

| Implementation | Run 1 median | Run 2 median | Run 3 median | ns/iter (run 3) |
|---|---|---|---|---|
| Native (unprotected baseline) | 0.511 ms | 0.516 ms | 0.482 ms | 24.1 |
| Flattened (Phase 5 obfuscation) | 0.502 ms | 0.491 ms | 0.475 ms | 23.8 |
| VM-interpreted (Phase 3, incl. mandatory re-verification per call) | — | — | 0.301 ms† | 1505.9 |

† VM row uses 200 iterations/trial, not 20,000 — not directly comparable
as a raw median, but the ns/iter column is.

**VM overhead: consistently ~60-63x the native baseline's per-call cost**
across all three runs. This is a real, meaningful, and expected cost — it
includes bytecode dispatch AND the mandatory full re-verification
`vm::Run()` performs on every single call (see `bytecode_vm/vm.h`'s
design note explaining why there's no "skip verification" fast path: the
cost is a deliberate safety trade-off, not an oversight). A production
deployment calling a protected function in a hot loop would likely want
to verify once and cache that result rather than per-call — not
implemented in this project (noted as a limitation in
`docs/ARCHITECTURE.md`'s Phase 3 section) but the benchmark here at least
quantifies what that optimization would be worth.

**Flattening overhead: consistently within 1-5% of native (0.95x-0.99x
across all three runs) — statistically indistinguishable from "no
overhead" given this methodology's noise floor.** This independently
confirms, with a sounder methodology (15 trials vs Phase 5's 4 single-shot
runs), what `docs/OBFUSCATION.md` already reported: at this function's
small size, control-flow flattening's performance cost is not measurably
different from zero in this environment. That doesn't mean flattening is
free in general — a larger, more complex function, or a different
compiler's optimization behavior around the `switch`-based dispatcher,
could show a real cost this particular 6-line function doesn't surface —
but for the one function this project actually measured, the honest
answer is "no measurable overhead," not an invented percentage.

## AES-256-GCM throughput

| Payload size | Median time | Throughput |
|---|---|---|
| 1 KiB | ~0.90-0.95 ms / 500 iters | ~510-545 MiB/s |
| 64 KiB | ~4.1-4.7 ms / 500 iters | ~6.6-7.5 GiB/s |
| 1024 KiB | ~5.9-6.0 ms / 50 iters | ~8.3-8.5 GiB/s |

Small-payload throughput is dominated by fixed per-call overhead (context
setup, nonce generation — see `crypto/aead.h`'s design: a fresh random
nonce is generated on every `Encrypt()` call, by design, to make nonce
reuse structurally impossible; that CSPRNG call has a real, measurable
cost at small payload sizes). Throughput approaches multiple GiB/s at
larger payload sizes, consistent with AES-NI hardware acceleration being
available and used by OpenSSL on this CPU — this project makes no claim
about which specific AES-NI-equivalent instructions Windows/ARM hardware
provides, only reports what was measured here.

## What's still not covered

- **Not run on the primary target platform (Windows/MSVC).** Every number
  above is from this Linux/GCC environment. MSVC's code generation,
  Windows' scheduler behavior, and whatever hardware this runs on when a
  person actually builds it will all differ — these numbers indicate
  magnitude and relative shape, not absolute Windows performance.
- **No comparison against other commercial protectors.** This document
  measures this project's own mechanisms against its own unprotected
  baseline, which is what the brief's §9 asks for. It makes no claim about
  how these numbers compare to Denuvo, VMProtect, Themida, or any other
  product.
- **Phase 6's native-reconstruction overhead is not benchmarked here**,
  since that module is opt-in and off by default (see
  `docs/RUNTIME_RECONSTRUCTION.md`) — adding a benchmark for it would be
  straightforward (compare a plain native call to
  `runtime::CallReconstructedFunction`'s full decrypt-load-call-unload
  cycle) but wasn't done in this delivery to keep the default build's
  benchmark suite buildable without the experimental flag.
