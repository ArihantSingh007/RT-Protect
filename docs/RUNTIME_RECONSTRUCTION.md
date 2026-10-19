# Runtime native-code reconstruction — rtprotect Phase 6 (optional/experimental)

This phase implements the brief's §3 architecture option 4 ("runtime
reconstruction of selected protected code regions") as the explicitly
optional, isolated research experiment the brief itself asks for — not as
a recommended protection mechanism. **Read this document before enabling
`RTPROTECT_ENABLE_EXPERIMENTAL_RUNTIME_RECONSTRUCTION`.** It is `OFF` by
default; the `runtime/` directory is not even compiled into a default
build.

## Read this first: why this is not the recommended approach

Phase 3's bytecode VM remains this project's primary, recommended
mechanism for protecting a function's logic. The reason is structural, not
a matter of effort or polish:

- **Phase 3's VM has a verifier** (`bytecode_vm/verifier.h`) that
  constrains what a program can possibly do. There is no VM opcode that
  can make a syscall, read or write arbitrary memory, or call native code
  (see `bytecode_vm/opcode.h`'s design goals). A malformed or corrupted VM
  program is rejected before execution, every time, by construction.
- **This phase's native code has no equivalent constraint.** Once bytes
  are mapped executable, they can do anything the CPU and operating system
  permit — there is no verifier that can make arbitrary native machine
  code provably safe to run. The only safety property this module has is
  that AEAD decryption fails closed on anything that wasn't encrypted
  under the caller's key (see `crypto/aead.h`) — that proves
  *authenticity*, not *safety*. Authenticated does not mean harmless.

This is why `runtime/reconstructed_function.h` never exposes a general
"decrypt and run these bytes" API: it decrypts and runs exactly one fixed,
reviewed, tested payload (`runtime/native_payload.h`), and nothing else —
see that file's header comment for the full reasoning and
`runtime/reconstructed_function.h`'s `kUnexpectedPayloadSize` check, which
is tested specifically to prove this boundary is enforced in code, not
just asserted in a comment (`tests/test_reconstructed_function.cpp`'s
`Reconstructed_RejectsCorrectlyAuthenticatedButWrongSizedPayload`).

## What was actually built and verified

### The payload

A single, 6-byte, fully-disassembled function:
`int64_t Reconstructed(int64_t x) { return (x * 2) + 7; }`. No syscalls, no
memory access beyond its own registers, no loops, no branches. Produced by
assembling real Intel-syntax source with GNU `as` and disassembling the
result with `objdump` — not hand-derived from memory:

```
$ as payload.s -o payload.o && objdump -d payload.o
0: 48 8d 44 3f 07       lea    0x7(%rdi,%rdi,1),%rax   ; SysV (Linux): arg in RDI
5: c3                   ret
```

Then loaded into real RW→RX memory and called for every integer -5..5,
confirmed to match `2*x+7` exactly for all eleven values, before being
used anywhere in the project:

```
$ ./verify
f(-5) = -3  (expected -3)  OK
...
f(5) = 17  (expected 17)  OK
```

The Microsoft x64 calling-convention variant (first argument in RCX
instead of RDI) was assembled the same way:

```
0: 48 8d 44 09 07       lea    0x7(%rcx,%rcx,1),%rax
5: c3                   ret
```

**Not verified on Windows.** The RCX variant was assembled and
disassembled (so the bytes are confirmed correct encodings of the intended
instruction) but not loaded and called on an actual Windows system in this
environment, because none is available here. This follows this project's
established pattern (see the main `README.md`'s Windows-verification
notes for every earlier phase) of stating exactly this gap rather than
asserting Windows behavior without having observed it.

### The loader (`runtime/executable_memory.h`/`.cpp`)

W^X-compliant two-step loading (allocate read-write → copy → transition to
read-execute; never simultaneously writable and executable), with
fault-isolated invocation. **Tested for real in this environment**,
including the one test that matters most for this phase's "secure failure
handling" requirement: loading Intel's `UD2` instruction (`0x0F 0x0B`,
architecturally guaranteed to raise an invalid-opcode fault) and confirming
the call is caught and reported as `CallResult::faulted = true` rather
than crashing the test process —
`tests/test_executable_memory.cpp`'s `ExecutableMemory_FaultingCode_IsCaughtNotCrashed`,
which passed in this environment (see the main README's verified test
output).

### The end-to-end pipeline (`runtime/reconstructed_function.h`)

Mirrors Phase 3's `examples/protected_checksum.h` pattern: AEAD-encrypt
the payload at rest, decrypt-verify-execute-wipe on each call, minimizing
how long native code exists as a resident executable mapping. Tested:
correct round-trip, wrong-key rejection, tampered-ciphertext rejection,
truncated-blob rejection, and the wrong-payload-size defense-in-depth
check described above.

## Platform requirements (Windows — the primary target)

| Step | Windows API | Purpose |
|---|---|---|
| 1. Allocate RW | `VirtualAlloc(nullptr, size, MEM_COMMIT \| MEM_RESERVE, PAGE_READWRITE)` | Never request `PAGE_EXECUTE_READWRITE` — that violates W^X and is a well-known AV/EDR detection heuristic (see below) |
| 2. Copy payload in | `memcpy` | — |
| 3. Transition to RX | `VirtualProtect(mem, size, PAGE_EXECUTE_READ, &old)` | The payload is now immutable from this process's own code's perspective |
| 4. Sync I-cache | `FlushInstructionCache(GetCurrentProcess(), mem, size)` | Documented by Microsoft as unnecessary in practice on x86/x64 (I/D-cache coherency is automatic there) but **required and NOT optional on ARM64 Windows** — always call it; skipping it is a real, platform-dependent correctness bug that happens not to manifest on x86/x64 |
| 5. Call | Ordinary indirect call through a function pointer, wrapped in SEH | See CFG note below — this is where it gets complicated |
| 6. Release | `VirtualFree(mem, 0, MEM_RELEASE)` | — |

### Exception handling

Windows: Structured Exception Handling (`__try` / `__except
(EXCEPTION_EXECUTE_HANDLER)`) around the call, converting a hardware fault
(access violation, illegal instruction) into a normal C++ return value
instead of an unhandled exception that terminates the process. Implemented
in `executable_memory.cpp`'s `#ifdef _WIN32` branch, following the
documented SEH contract — **not exercised on Windows in this environment**
(no Windows runtime available), same caveat as the payload above.

The POSIX equivalent used in this project's Linux test harness (`sigaction`
+ `sigsetjmp`/`siglongjmp` around `SIGSEGV`/`SIGBUS`/`SIGILL`) **was**
exercised for real, including the UD2 fault test described above. It
exists solely so this experiment can be built and tested on the toolchain
actually available in this environment — it is explicitly not the Windows
deployment path.

## Real, documented limitations (not glossed over)

### Control Flow Guard (CFG) incompatibility

This project's own top-level `CMakeLists.txt` enables `/guard:cf` for
MSVC Release builds (added in Phase 1, for defense-in-depth against
different attacks). **CFG will fail-fast-crash an indirect call into
memory that was made executable at runtime**, unless that memory region's
entry point is explicitly registered as a valid indirect-call target via
`SetProcessValidCallTargetsForMappedView` — which this module does **not**
implement. This is a genuine, concrete conflict between two of this
project's own techniques, not a hypothetical: enabling both CFG and this
experimental module on the same binary, without that registration call,
would crash at the point of invocation.

`runtime/CMakeLists.txt` addresses this the honest way — by disabling CFG
specifically for this module (`/guard:cf-`) rather than silently shipping
something that would crash — and documents that doing so is itself giving
up real protection to gain this questionable one. Implementing
`SetProcessValidCallTargetsForMappedView` properly (so both techniques can
coexist) is reasonable future work, not attempted here.

### Antivirus / EDR heuristic detection

Allocating memory, writing to it, and transitioning it to executable — the
W^X two-step this module implements correctly — is nonetheless a known,
common heuristic many antivirus and endpoint-detection products flag,
particularly when done repeatedly in a short span (as `decrypt-per-call`
does: every single call to `CallReconstructedFunction` performs this
sequence once). Doing the W^X transition *correctly* (never
simultaneously RW+X) reduces but does not eliminate this risk — the
pattern itself, not just a sloppier version of it, is what gets
heuristically flagged. This is a real deployment cost worth weighing
against the technique's actual protective value, which (per the opening
section of this document) is already weaker than Phase 3's VM approach.

### Instruction cache coherency

Covered in the platform-requirements table above: required on ARM, a
documented no-op in practice on x86/x64, called unconditionally anyway
because that's the only way this code is correct across architectures
rather than "happens to work on the one architecture tested."

### What this module does NOT attempt

- **No defense against the loaded code itself being malicious** beyond the
  single-fixed-payload restriction described above. This is not a sandbox;
  a `CallResult::faulted = false` result only means the call returned
  without a *hardware fault* — it says nothing about what the code did
  while running (which, for this phase's one reviewed payload, is
  "nothing but arithmetic," by construction and by review, not by runtime
  enforcement).
- **No defense against an attacker reading the decrypted bytes from memory
  while they're resident** — `OPENSSL_cleanse` wipes the plaintext buffer
  after loading, but the payload necessarily exists as readable,
  executable memory for the duration of the call, by definition (it has to,
  to run). This is the same category of limitation
  `docs/THREAT_MODEL.md` §6 describes for any decrypted secret: the
  window during *active use* is not, and cannot be, protected the way the
  window before/after use is.

## Relationship to the rest of this project

This module reuses Phase 1-2's AEAD unchanged (`crypto::Encrypt`/
`crypto::Decrypt`) and follows the same encrypt-at-rest,
decrypt-per-call, wipe-after-use pattern as Phase 3's
`examples/protected_checksum.h` — the pattern is sound and portable across
both "protect logic via a constrained VM" (Phase 3, recommended) and
"protect logic via reconstructed native code" (this phase, experimental).
It has not been integrated with Phase 4's manifest/signature system in
this delivery — doing so (binding the encrypted payload blob to a signed
release manifest, the same way Phase 4 could be wired into Phase 3's
checksum pipeline but wasn't, per `docs/ARCHITECTURE.md`'s Phase 4
follow-up notes) is reasonable future work, consistent with how both
earlier phases' own "not yet covered" sections are written.
