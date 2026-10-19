# Obfuscation techniques — rtprotect Phase 5

Per the project brief's requirement (§4, §6): every technique here is
classified by what it actually defends against, what it doesn't, its
compatibility/performance cost, and whether it's implemented, simulated, or
only documented. Measurements below are real output captured in this
environment (GCC 13.3.0, Ubuntu, x86-64), not invented numbers — commands
are shown so they can be reproduced.

## Classification table

| Technique | Addresses | Attacker can still | Compatibility | Perf/size cost | Status |
|---|---|---|---|---|---|
| Compile-time string obfuscation (`obfuscation/obfuscated_string.h`) | Passive static scanning (`strings`, hex editors, automated harvesters) | Read the key directly from the decryption routine's disassembly; defeated by anyone who looks at the code that uses the string | Portable C++20, no platform dependency | ~1.5-5.6 KB per binary depending on how much of the template gets instantiated + debug info; see measurements below | **Implemented, empirically verified** |
| Control-flow flattening (`obfuscation/checksum_flattened.h`) | Quick/automated CFG pattern-matching (recognizing "this is a loop" at a glance) | Recover the original structure with a real decompiler or modest manual effort — this is a shallow, source-level demo, not an LLVM-pass-level transform | Portable C++20 | See timing measurements below (noisy, not a reliable signal either way at this function's size) | **Implemented, one demonstrative function, parity-tested** |
| Symbol/visibility stripping + dead-code elimination (top-level `CMakeLists.txt`, `RTPROTECT_HARDEN_RELEASE`) | Giving a reverse engineer a free map of internal function/variable names via the symbol table; shipping unreachable code/data that bloats the binary and gives more material to analyze | Still fully disassemble and analyze the remaining code — stripping symbols doesn't remove instructions, only names | GCC/Clang: `-fvisibility=hidden`, `--gc-sections`, `strip --strip-all`. MSVC: `/Gw`, `/OPT:REF`, `/OPT:ICF`, PDB excluded from the release package (Phase 7) | Measured below: ~9-11% binary size reduction on these small demo binaries; larger binaries typically see more | **Implemented, measured** |
| Function splitting / outlining across translation units | Trivial single-function disassembly correlation between source and binary layout | A linker/disassembler can still reconstruct call graphs; this mainly adds friction to "read the source side-by-side with the disassembly" workflows | N/A | N/A | **Documented only, not implemented** — see "What this phase does not implement" below |
| Selective inlining / optimization profile tuning | Nothing security-relevant on its own — inlining mainly changes how much of a function's logic is visible as a single disassembled unit versus split across call sites | N/A | N/A | Already in effect via `-O2`/`/O2` (CMake's default `Release` flags) — no project-specific tuning added | **Relies on standard compiler behavior, not a bespoke technique** |
| Build-time generation of multiple semantically-equivalent representations ("polymorphic" builds) | Signature-based detection of one fixed binary shape across many installs | N/A | N/A | N/A | **Not evaluated this phase** — see "What this phase does not implement" |

## 1. Compile-time string obfuscation — measured results

### What was measured

Two tiny demo binaries, `demo_plain_secret` and `demo_obfuscated_secret`
(`obfuscation/demo/`), both print the identical marker string
`RTPROTECT_DEMO_MARKER_PHRASE_f7a2c9` — one via an ordinary string literal,
the other via `RTPROTECT_OBFUSCATE`. Both compiled with identical flags
(same `CMakeLists.txt`, same build type) so the comparison is fair.

### Release build (`-O3 -DNDEBUG`, hardening + stripping ON)

```
$ ./demo_plain_secret
RTPROTECT_DEMO_MARKER_PHRASE_f7a2c9
$ ./demo_obfuscated_secret
RTPROTECT_DEMO_MARKER_PHRASE_f7a2c9

$ ls -la demo_plain_secret demo_obfuscated_secret
-rwxr-xr-x 1 root root 14464 demo_plain_secret
-rwxr-xr-x 1 root root 14560 demo_obfuscated_secret

$ strings demo_plain_secret | grep -i MARKER
RTPROTECT_DEMO_MARKER_PHRASE_f7a2c9

$ strings demo_obfuscated_secret | grep -i MARKER
(not found)
```

Both binaries produce identical, correct output at runtime. The plain
binary's marker string is trivially found by `strings`; the obfuscated
binary's is not. Size overhead: 96 bytes (0.66%) on this tiny binary — the
cost of the encryption/decryption template code, not of the string itself
(the string is the same length either way).

### Debug build (`-O0`, no hardening)

Re-ran the identical check against the Debug build to confirm the property
holds regardless of optimization level (constexpr evaluation happens at
compile time in the front end, independent of `-O`):

```
$ strings demo_plain_secret | grep -i MARKER
RTPROTECT_DEMO_MARKER_PHRASE_f7a2c9
$ strings demo_obfuscated_secret | grep -i MARKER
(not found)
```

Confirmed at both optimization levels. Debug binaries are larger overall
(debug info), and the size *gap* between plain and obfuscated is larger in
Debug (~5.6 KB) than Release (96 bytes) because debug info for the extra
template instantiations isn't stripped — expected, and not a concern since
Debug builds aren't what ships.

### Honest limitation (restated from the header comment in
`obfuscated_string.h`, because it matters more than the passing test)

The decryption key is derived from compile-time constants (`__LINE__`,
`__COUNTER__`) embedded as immediate values directly in the decryption
routine, which itself ships as ordinary, unobfuscated compiled code (this
phase does not obfuscate its own obfuscation code — see "What this phase
does not implement"). Anyone disassembling `main()` in
`demo_obfuscated_secret` sees the XOR loop and its literal key operands
directly; recovering the string takes reading maybe ten lines of
disassembly. This technique's actual value is narrow and specific: it
defeats **tools that don't execute or analyze code at all** — `strings`,
automated binary scanners, hex editors — which is a real and common first
line of casual/automated analysis, but a genuinely low bar against a human
reverse engineer.

## 2. Control-flow flattening — measured results

`obfuscation/checksum_flattened.h` rewrites
`examples::NativeChecksum`'s natural `while` loop as a single dispatch loop
with a `switch` over an explicit state variable. Correctness:
`tests/test_checksum_flattened.cpp`'s `Flattened_MatchesNativeReference`
and `Flattened_HandlesZeroAndNegativeInputs` tests assert identical output
across 10+ inputs including edge cases, and both pass.

### Timing (indicative only — see methodology caveat below)

```
Debug (-O0):   native: 13.635 ms, flattened: 12.514 ms  (200,000 iterations, single run)

Release (-O3), four separate runs:
  run 1: native 4.144 ms, flattened 4.137 ms
  run 2: native 5.826 ms, flattened 4.684 ms
  run 3: native 4.577 ms, flattened 4.648 ms
  run 4: native 4.488 ms, flattened 4.787 ms
```

The Release numbers above are the actual reason this section leads with a
methodology caveat rather than a conclusion: run-to-run variance (4.1-5.8ms
for the *same* native implementation across four runs) is larger than the
native-vs-flattened difference within any single run. At this function's
size, this measurement setup cannot distinguish "flattening has a real
overhead" from "the machine was doing something else for a few
milliseconds." Reporting a single favorable run (e.g. "flattened is
faster!") would have been the kind of invented-looking conclusion the
brief's §9 explicitly warns against — showing all four runs instead of
picking the best one is the honest version of this measurement.

**Methodology caveat, stated plainly:** this is a single-run,
`std::chrono::steady_clock`-based measurement with no warm-up iterations,
no isolation from other load on the machine, and no statistical
repetition. It is NOT the rigorous benchmark methodology the brief asks
for as a deliverable (§9) — that belongs in Phase 7, which will need
actual repeated trials, warm-up, and a documented methodology before any
performance claim is made with confidence. What this phase's test
demonstrates is correctness (verified) and that the flattened version is
not catastrophically slower (true at this function's small size) — not a
precise overhead percentage, which would be a false precision this phase
doesn't have the measurement rigor to back up.

### Honest limitation

This is a shallow, source-level flattening of one small function. A real
obfuscating compiler pass would also add opaque predicates (conditions
that are always true/false but not obviously so to static analysis),
flatten nested control structures recursively, and obscure the state
variable's own update logic. A moderately capable decompiler (e.g. Ghidra,
IDA with reasonable effort) can likely still recover the original loop
shape from this; what it defeats is quick, automated pattern-matching on
CFG shape, not dedicated manual analysis.

## 3. Release-build hardening — measured results

Compared the same two demo binaries built with `RTPROTECT_HARDEN_RELEASE=ON`
(default) vs explicitly `OFF`, both `-DCMAKE_BUILD_TYPE=Release`:

```
                          hardening OFF   hardening ON   reduction
demo_plain_secret:            15,976          14,464       9.5%
demo_obfuscated_secret:       16,312          14,560      10.7%
```

(`-fvisibility=hidden -fvisibility-inlines-hidden -ffunction-sections
-fdata-sections` at compile time, `-Wl,--gc-sections` at link time, plus a
post-build `strip --strip-all`.) The reduction is modest on these
intentionally tiny single-function demo binaries; dead-code elimination
and symbol stripping typically matter much more on larger binaries with
more unused template instantiations and library code to discard — these
numbers shouldn't be read as "expect ~10% on a real application," only as
confirmation the flags do something measurable and don't break anything.

### What symbol stripping actually removes

`strip --strip-all` removes the symbol table and debug information —
function and variable *names* — not instructions. A stripped binary is
exactly as functionally analyzable via disassembly as an unstripped one;
what's gone is the reverse engineer's free head start of readable names
for every internal function, which otherwise turns "figure out what this
subroutine does" into "read the name someone else already gave it."

## What this phase does not implement

Per the brief's explicit instruction to avoid "meaningless transformations
that only inflate the executable" and to evaluate techniques rather than
implement everything indiscriminately:

- **Function splitting/outlining across translation units** — evaluated,
  not implemented. The realistic benefit (breaking trivial source-to-binary
  correlation) is real but modest against anyone willing to trace call
  graphs, and doing it properly (actually relocating logically-related code
  to non-adjacent translation units in a way a linker won't just re-colocate
  via identical-code-folding or LTO) needs careful build-system work this
  phase didn't attempt rather than a token gesture.
- **"Polymorphic" builds generating multiple semantically-equivalent binary
  representations** — not evaluated this phase. This is a substantial
  undertaking (effectively requires either multiple independently-written
  implementations or a real compiler-pass-level randomizing transform) that
  belongs in a dedicated phase of its own if pursued, not bolted onto
  Phase 5's existing scope.
- **This phase's own obfuscation code is itself unobfuscated.** The XOR
  routine in `obfuscated_string.h` and the dispatcher in
  `checksum_flattened.h` are both ordinary, readable C++ — stated
  explicitly in both files' headers. "Obfuscate the obfuscator" is a
  real and valid technique (commercial protectors do exactly this) but
  adds a layer of complexity and self-referential risk (bugs in obfuscated
  code are much harder to debug) that this phase's two concrete,
  measured techniques don't need in order to make their point honestly.
- **LLVM-pass-level transforms** (real opaque predicates, bogus control
  flow insertion, instruction substitution at the IR level) — the brief's
  §3 lists this as an evaluated-but-not-chosen architecture for Phase 3's
  code protection (the bytecode VM was chosen instead); it remains out of
  scope here for the same reason: a real LLVM pass is a substantial,
  separate engineering effort, not a Phase 5 add-on.

## Relationship to Phase 3's bytecode VM

The VM from Phase 3 and this phase's obfuscation techniques address
different layers and are complementary, not redundant: the VM hides a
function's *logic* entirely (it exists only as bytecode, decrypted
transiently), while this phase's techniques hide *incidental* information
(strings, CFG shape, symbol names) in ordinary compiled C++ code that isn't
inside the VM. A real deployment would use the VM for the small number of
genuinely sensitive algorithms and these lighter-weight techniques
everywhere else, per the brief's own framing of "protect selected critical
functions" rather than wrapping an entire application.
