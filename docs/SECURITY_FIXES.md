# Response to an external vulnerability/readiness report

This document responds to a readiness assessment and five numbered
findings submitted against this project, comparing it to commercial
anti-tamper systems (Denuvo). The headline conclusion of that report —
**RTProtect is not a Denuvo replacement** — is correct and consistent with
what this project's own documentation has said from Phase 1 onward (see
`docs/THREAT_MODEL.md`'s opening: "no purely client-side defense is
permanent," and `docs/ARCHITECTURE.md`'s "What this project does not
cover" section). This document addresses the five specific findings
individually, because they don't all warrant the same response.

## 1. Patchable boolean integrity verification — FIXED

**The finding was correct.** `integrity::CheckResource`'s hash comparison
and `bytecode_vm::VerifyProgram`'s result are both ordinary boolean gates
guarding a separately-keyed decryption/execution step. An attacker capable
of patching compiled code (the attacker class `docs/THREAT_MODEL.md` §5
already assumes) can flip or NOP one conditional branch to skip the check
without affecting decryption, because decryption's key material never
depended on the check having passed.

**Fix implemented:** `integrity/bound_key.h`/`.cpp` — `DeriveBoundResourceKey`
derives a resource's AES-256 key via HKDF, salted with the manifest's
*committed* SHA-256 hash for that resource, rather than using a key
independent of the hash. This converts "verify hash, then separately
decrypt with a fixed key" into one cryptographic operation: a resource
whose content doesn't match what the signed manifest committed to simply
decrypts under the wrong key, which fails AEAD authentication — the same
deep, hard-to-patch mechanism (inside OpenSSL's `EVP_DecryptFinal_ex`)
`crypto/aead.h` already relies on for ciphertext tampering, instead of one
of this project's own top-level `if` statements.

**Proven, not just implemented:** `tests/test_bound_key.cpp`'s
`BoundKey_SwappedOlderRelease_FailsViaAeadAlone_NoHashCheckCalled` test
constructs the exact bypass scenario — swap in a different, validly
AEAD-encrypted resource (e.g. an older release's) while leaving the
current, correctly-signed manifest untouched — and confirms it fails via
AEAD authentication alone, **without calling any separate hash-comparison
function anywhere in the test**. If the only protection were still a
patchable boolean, a test shaped like this would need to call that
function to catch the substitution; it doesn't, and still passes, because
the binding itself does the work.

**What this does NOT fix, stated with the same honesty as every other
limitation in this project:** the manifest's *signature* still must be
verified before its claimed hash can be trusted — that remains a boolean
gate (`integrity::VerifyManifestSignature`), because bootstrapping initial
trust in a public key cannot be replaced by key derivation. This fix
eliminates the *redundant*, separately-patchable post-decrypt comparison
Phase 3/6's original pattern had; `docs/THREAT_MODEL.md` §5's point that a
fully capable local attacker can still potentially patch the signature
verification call itself stands exactly as before, and always will for
any in-process check — this was never a solvable problem, only a
reducible one.

**Not yet done:** wiring this into `examples/protected_checksum.h` and
`runtime/reconstructed_function.h`'s existing call sites (both currently
still take a raw, independently-supplied key) is a follow-up, consistent
with Phase 4's own "not yet wired into the Phase 3/6 pipelines" notes —
the new primitive is built, tested, and proven; retrofitting the two
existing example pipelines to use it is reasonable future work.

## 2. Cleartext exposure during dynamic reconstruction — PARTLY ALREADY
   DOCUMENTED, ANTI-DEBUG PORTION DECLINED

The underlying fact — decrypted native code necessarily exists as
readable, executable memory for the duration of a call — is real and was
already stated plainly in `docs/RUNTIME_RECONSTRUCTION.md`'s limitations
section before this report: *"the payload necessarily exists as readable,
executable memory for the duration of the call, by definition (it has to,
to run)."* This isn't a new finding; it's a restatement of an existing,
documented limitation.

**"Micro-chunking"** (splitting a function into smaller pieces, decrypted
individually) doesn't meaningfully apply to Phase 6's actual payload — a
single 6-byte, 2-instruction function (see `runtime/native_payload.h`).
Splitting 2 instructions into smaller "chunks" isn't a real technique at
that scale; generalizing the loader to handle arbitrary larger,
chunkable payloads would mean walking back Phase 6's deliberate
single-fixed-payload scope (see `runtime/native_payload.h`'s header on
why that restriction exists) toward a general-purpose native-code loader
— which reopens exactly the unconstrained-execution risk that restriction
exists to prevent. Not done, and not a small follow-up.

**Declined: "integrate anti-debugging checks into the decryption routine
so memory pages cannot be read... when a debugger is attached."** This is
an anti-analysis technique — its function is to blind a debugger-equipped
analyst, which does not distinguish between a reverse engineer and a
security researcher. `docs/THREAT_MODEL.md` §6 already drew this
boundary deliberately in Phase 1, before this report: *"Prioritize robust
integrity checks and explicit security boundaries over aggressive
anti-debugging tricks,"* and explicitly limited even the techniques it
does discuss to "documented," not "implemented," for this exact reason.
This project is not reversing that boundary now because a report
relabeled the same request as a "fix."

## 3. Unbacked executable memory / EDR heuristic risk — ALREADY DOCUMENTED,
   EVASION FIX DECLINED

Also not a new finding: `docs/RUNTIME_RECONSTRUCTION.md`'s "Antivirus /
EDR heuristic detection" section already stated, before this report, that
the W\^X transition sequence Phase 6 implements *correctly* "is
nonetheless a known, common heuristic many antivirus and
endpoint-detection products flag," and that doing it correctly "reduces
but does not eliminate this risk."

**Declined: "implement custom module loading... linked to legitimate
system files" / mimicking a signed module to avoid detection.** This is
specifically a technique for evading security-product detection — making
attacker-controlled (or in this case, this project's own experimental)
code *look like* something it isn't to a defensive tool. That is a
different category of request from "reduce false positives by following
correct W^X discipline" (which Phase 6 already does); it is "defeat the
detection heuristic regardless of correctness." Not implemented, for the
same reason item 2's anti-debug request wasn't: it's anti-detection
tooling, not integrity/anti-tamper hardening, and the fact that the
request frames the target as "false positives" rather than "legitimate
detections" doesn't change what the resulting code would do.

## 4. Fixed VM opcode dispatch — evaluated, deferred (not a quick fix)

A per-build permutation of the VM's opcode-to-byte mapping (so a fixed,
published mapping like the one `bytecode_vm/opcode.h` documents doesn't
directly transfer to every build) is a reasonable, legitimate technique —
the same category as Phase 5's control-flow flattening, not an
anti-analysis evasion request like items 2 and 3's declined portions.

It was evaluated for this response and **not implemented**, for a concrete
reason rather than a vague one: the real security value of opcode
permutation requires it to affect what the *interpreter and verifier*
actually decode at runtime, not just the serialized-at-rest wire format
(which an attacker without the decryption key can't see either way, so
permuting only that boundary provides negligible benefit). Doing it
properly means `bytecode_vm/verifier.cpp` and `vm.cpp` decode through a
build-seeded substitution table instead of the fixed byte values —and
several existing Phase 3 tests
(`tests/test_vm.cpp`'s `Verify_Rejects*` cases) construct raw `Program`
objects using today's hardcoded byte literals (e.g. `p.code = {0x01, ...}`
for `kPushConst`), which are only meaningful under the current fixed
mapping and would need rewriting to use the new table instead of literal
hex. That's a real, moderate-sized, test-touching refactor — not
something to half-implement in the same pass as the fixes above just to
check a box. Recorded here as evaluated-and-deferred with a concrete
design (build-seeded substitution table, applied at the verifier/vm
decode boundary, logical `Opcode` enum and all call-site code in
`builder.h` unchanged), the same honesty standard
`docs/OBFUSCATION.md` already applied to "function splitting" and
"polymorphic builds" — real future work, not implemented today.

## 5. Absence of active anti-debugging — declined in full, by design

**Declined**, consistent with items 2 and 3 above and with Phase 1's
original, deliberate scope decision (`docs/THREAT_MODEL.md` §6, written
before any of these reports existed): `IsDebuggerPresent`/
`CheckRemoteDebuggerPresent`/`NtQueryInformationProcess` checks, hardware
breakpoint scanning (DR0-DR3), and `RDTSC`-based single-step detection are
all techniques whose purpose is detecting and defeating analysis by a
debugger-equipped party — the same party that could be a pirate, a
security researcher, or an incident responder. This project does not
implement anti-analysis tooling regardless of the stated justification;
that determination doesn't change based on how the request is framed
(educational, defensive, commercial-parity), and revisiting an earlier,
deliberate scope decision because a report re-presents the same request
isn't something this project does.

## Summary

| # | Finding | Status |
|---|---|---|
| 1 | Patchable boolean verification | **Fixed** — `integrity/bound_key.h`, tested |
| 2 | Cleartext during reconstruction | Limitation already documented; anti-debug portion declined |
| 3 | EDR flagging of RWX memory | Limitation already documented; evasion portion declined |
| 4 | Fixed VM opcode dispatch | Evaluated, deferred with concrete design (real refactor, not a quick patch) |
| 5 | No active anti-debugging | Declined in full — this project does not implement anti-analysis tooling |

This project remains what `docs/ARCHITECTURE.md` has said since Phase 1:
a research-grade illustration of real anti-tamper techniques with an
honestly-documented threat model, not a commercial-grade or
anti-analysis-evading product. That framing hasn't changed, and claims
framed as "vulnerabilities" that are actually requests to add
anti-debugging or detection-evasion capability get evaluated against that
framing and declined when they fall outside it, the same way they would
have been declined if asked for directly.
