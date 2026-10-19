# Threat Model — rtprotect

This document states, plainly, what this framework can and cannot defend
against. Every later phase must be read against this document, not against
marketing claims about "uncrackable" protection — no such thing exists for
software that must run, unmodified in its trust boundary, on hardware the
attacker fully controls.

## 1. Adversary model

We assume an attacker who:

- Has full, unsupervised access to the distributed binary and all shipped
  resources/data files.
- Can run the binary under a debugger, emulator, or instrumented hypervisor.
- Can read and write arbitrary process memory, including at the moment any
  key or plaintext secret exists in RAM.
- Can modify the binary on disk and re-run it (static patching).
- Can intercept, replay, or forge any network traffic the binary sends,
  unless that traffic is itself authenticated end-to-end.
- Has unlimited time and standard reverse-engineering tooling (disassemblers,
  decompilers, dynamic instrumentation frameworks).

This is deliberately the strongest realistic adversary for client-side
software: **a fully capable local attacker**. Against this adversary, no
purely client-side defense is permanent. Every control below is described in
terms of *cost raised*, *casual/automated attacks stopped*, or *tamper
made detectable*, never in terms of "prevented."

## 2. What client-side protection can realistically achieve

- Stop casual inspection (opening the binary in a hex editor or basic
  decompiler and immediately finding sensitive constants, algorithms, or
  unlocked content).
- Stop fully automated, generic cracking tools that pattern-match on
  common unprotected constructs.
- Detect (not prevent) that the binary or its resources were modified after
  being signed, and fail closed when that's detected.
- Raise the specialized skill and time required for a *manual, targeted*
  break, which deters casual crackers and raises the cost for
  commodity/automated pirate tooling — the actual threat model of most
  commercial protectors, Denuvo included.
- Protect secrets that are genuinely never present in the client at all
  (e.g. a private signing key that stays server-side) absolutely, because
  they're outside the adversary's reach by construction.

## 3. What it cannot achieve, and why

| Claim sometimes made by marketing | Why it's false in this threat model |
|---|---|
| "The binary can't be reverse engineered" | The CPU must execute real instructions; those instructions are observable by definition. Any code path that genuinely runs on the attacker's own hardware can be traced, however slowly. |
| "The key is protected inside the binary" | A key needed at runtime to decrypt something the program must itself use is, by construction, reachable from that process's own memory. Obfuscating *where* it lives raises search cost; it does not remove the key from the attack surface. |
| "Anti-debugging makes the program unanalyzable" | Anti-debug checks are themselves code running under the same full process control as everything else, and can be located, patched out, or bypassed with virtualization/emulation that doesn't trip the specific checks implemented. |
| "Integrity checks stop tampering" | An integrity check that runs *in the same process* as the thing it protects can itself be patched, NOP'd, or have its result forced, by the same attacker capable of tampering with the protected code. Integrity checks **detect and can trigger a response** (e.g. refuse to proceed, corrupt internal state); they do not form a security boundary against a fully capable local attacker unless backed by a component genuinely outside that attacker's control (see §5). |

## 4. Key management reality

- Any symmetric key embedded in the client, obfuscated or not, must be
  assumed recoverable by a sufficiently motivated attacker through dynamic
  analysis (dump memory at the point of use).
- **Never** embed a private signing key in distributed software. Only the
  corresponding public key belongs client-side (see `crypto/` design:
  verification, never signing, happens in the client).
- Per-session keys derived via HKDF (see `crypto/kdf.h`) limit the *blast
  radius* of a single extracted key (it's bound to one session/purpose) but
  do not change the fact that the master secret they're derived from is
  reachable if the client process that holds it is reachable.
- A server-side, network-verified licensing/entitlement check (Phase 6,
  optional) moves a specific check outside the attacker's local control —
  but only for the parts of functionality that can tolerate requiring
  network access and server trust; this is a different and stronger
  category of protection than anything purely client-side, and it has its
  own costs (availability, privacy, offline use).

## 5. Where real trust boundaries can and cannot be drawn

| Component | Attacker-reachable? | Trust boundary? |
|---|---|---|
| In-process integrity verifier | Yes — same process, same privilege | No — detects, doesn't prevent |
| Kernel-mode anti-tamper driver | Harder, but a sufficiently privileged local attacker can still defeat it; also carries real security/compatibility risk and is explicitly **out of scope** for this project | Weak, and we do not implement one |
| Server-side license/entitlement check over an authenticated channel | No (assuming the server itself is secure) | Yes, for the specific check performed |
| Hardware security module / TPM-backed secret | No (if used correctly) | Yes, for the specific secret it holds |

This project implements the first row (useful for tamper *detection and
response*, not prevention) and designs the key-management module so a
server-side check (third row) can be added without restructuring, but does
not implement kernel-mode components, and treats any future HSM/TPM
integration as future work (see `docs/ARCHITECTURE.md` roadmap).

## 6. Plaintext and key lifetime

- `crypto::SecureBuffer` (see `crypto/secure_buffer.h`) wipes sensitive
  memory with `OPENSSL_cleanse` on destruction/shrink. This reduces the
  window during which a key or decrypted secret sits in **freed** heap
  memory that could be scraped from a memory dump taken after the fact.
- It does **not**: prevent the secret from being read while still in use
  (an attacker single-stepping the decryption routine sees the plaintext
  the instant it's produced, by definition), lock pages against swapping
  to disk (`mlock`/`VirtualLock`, not yet implemented — tracked as future
  work), or defend against an attacker who dumps memory *before* the
  buffer is destroyed.

## 7. Scope boundary for this project

Explicitly **out of scope**, regardless of phase:

- Defeating a fully-equipped, patient reverse engineer with unlimited time.
- Kernel-mode / ring-0 protection components.
- Interfering with, terminating, or fingerprinting unrelated processes on
  the user's machine.
- Any persistence, stealth, or destructive "anti-piracy" behavior (e.g.
  corrupting user data on detected tampering). Detected tampering triggers
  **fail-closed refusal to run the protected functionality**, logged
  locally, never collateral damage to the user's system.
- Claims that a given technique is "unbreakable." Every section of every
  later phase's documentation must state what the technique is known to
  resist and what it's known not to resist.
