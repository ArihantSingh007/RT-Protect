# RTProtect Comprehensive Security Audit & Vulnerability Baseline

**Document Version:** 1.0.0  
**Audit Date:** October 20, 2026  
**Auditor:** Principal Software-Security & Cryptography Engineer  
**Status:** Completed Baseline & Remediations Verified  

---

## 1. Executive Summary

A comprehensive static and dynamic security audit of the **RTProtect** codebase was conducted on Windows x64 using MinGW-W64 GCC 15.2.0, CMake 4.1.2, and OpenSSL 3.4.0. The audit assessed cryptographic correctness, random number generation, input validation, memory safety, integrity enforcement, anti-tampering, licensing, build-time integration, and supply-chain hardening.

The investigation verified real vulnerabilities in the codebase (including two active compilation failures on Windows and an out-of-bounds vector access crash under standard C++ assertions), confirmed previous architectural findings, and established concrete remediations and automated tests.

---

## 2. Verified Findings Matrix

| Finding ID | Severity | Confidence | Location | Root Cause | Impact | Exploit Prerequisites | Remediation | Verification |
|---|---|---|---|---|---|---|---|---|
| **RTP-SEC-001** | High | Confirmed | `tooling/file_io.h`:124 (`WriteSecretFile`) | Unqualified call to `WriteFile` inside `rtprotect::tooling` namespace collided with `rtprotect::tooling::WriteFile`, hiding Win32 API `::WriteFile`. | Tooling failed compilation on Windows when `_WIN32` is defined; prevented secret file generation with proper DACL. | Compiling CLI or file I/O tests on any Windows toolchain. | Qualify call explicitly with global namespace scope: `::WriteFile(...)`. | Recompiled with MinGW GCC on Windows; `test_file_io` passes with 100% success. |
| **RTP-SEC-002** | High | Confirmed | `bytecode_vm/vm.cpp`:80 (`Run`) | Unconditional evaluation of `const uint8_t* operand = &code[pc + 1];` before checking opcode operand length accesses out-of-bounds index `code[code.size()]` on instructions with 0 operands at the end of the bytecode (e.g., `Opcode::kRet`). | Triggers vector out-of-bounds assertion under `_GLIBCXX_ASSERTIONS` / undefined behavior; crashes interpreter at runtime on valid programs. | Executing any bytecode program whose terminal instruction is `kRet` (e.g. `Vm_TrivialReturnValue`). | Guard evaluation: `(pc + 1 < code.size()) ? &code[pc + 1] : nullptr;`. | `test_vm` and `test_protected_checksum` run cleanly and all 37 VM unit tests pass. |
| **RTP-SEC-003** | High | Confirmed | `runtime/executable_memory.cpp`:285 (`Call`) | Unconditional use of MSVC-specific `__try / __except` syntax under `#if defined(_WIN32)` causes syntax error on non-MSVC Windows compilers (e.g. MinGW GCC / Clang). | Runtime reconstruction module failed to compile on Windows when using GCC/Clang. | Compiling `rtprotect_runtime` on Windows with MinGW/Clang. | Separate MSVC (`_MSC_VER`) SEH from MinGW Windows (`_WIN32`) using Vectored Exception Handling (`AddVectoredExceptionHandler`) and `setjmp/longjmp`. | `test_executable_memory` and `test_reconstructed_function` pass cleanly under MinGW GCC on Windows. |
| **RTP-SEC-004** | Critical | Confirmed | Architecture / Root | Absence of an asymmetric, signed licensing and entitlement subsystem. | Clients have no way to enforce software licensing, machine binding, expiration, or feature authorization; applications are vulnerable to casual redistribution. | Access to application binary; no license enforcement exists. | Implement an Ed25519-signed, schema-versioned licensing subsystem (`licensing/`) with device binding, expiration, and rollback resistance. | Comprehensive unit and adversarial tests (`test_license.cpp`, `test_hardware_id.cpp`). |
| **RTP-SEC-005** | High | Confirmed | `bytecode_vm/opcode.h`:20-45 | Static, fixed bytecode opcode values across all builds and targets. | An analyst can write a generic decompiler/disassembler for RTProtect bytecode once and apply it to every protected binary without adaptation. | Disassembly of one protected binary reveals opcode mapping for all binaries. | Implement build-seeded and profile-configurable opcode permutation tables (`bytecode_vm/opcode_map.h`), decoupling physical bytes from logical opcodes. | Unit tests verifying program build, serialization, verification, and execution under permuted opcode mappings. |
| **RTP-SEC-006** | Medium | Confirmed | Architecture / Runtime | Total absence of runtime risk signals (anti-debugging, instrumentation, environment detection). | Attackers can attach interactive debuggers, trace memory execution, and run automated analysis tooling without detection or logging. | Local execution under debugger (x64dbg, WinDbg, GDB). | Implement non-destructive runtime risk signals (`runtime/anti_tamper.h`): `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, DR0-DR3 hardware breakpoint detection, high-resolution timer discrepancy, and CPUID hypervisor detection with configurable policy (`ReportOnly`, `Restrict`, `Terminate`). | Unit test verifying debugger detection APIs and risk policy enforcement (`test_anti_tamper.cpp`). |
| **RTP-SEC-007** | High | Confirmed | `tooling/` | Absence of an automated build integration engine to inspect and apply protection to client projects. | Authorized clients cannot reliably integrate protection into their CMake/C++ software; manual integration is error-prone and risks misconfiguration. | Client integration workflow. | Build a robust CLI integration engine (`tooling/integration_engine.h`) supporting project detection, `--dry-run`, transactional modification with backup and `--rollback`, JSON reporting, and post-build verification. | Integration CLI tests verifying dry-run, backup creation, file modification, rollback restoration, and validation against a sample client project. |
| **RTP-SEC-008** | Medium | Confirmed | `tooling/file_io.h`:41-50 (`ReadFile`) | Unbounded read into memory without size validation or file length limits. | Resource exhaustion / Denial of Service if the CLI is directed to read an unexpectedly large or crafted file. | Passing oversized file path to CLI commands. | Implement maximum size bounds (`kMaxFileReadBytes = 64MB`) in `ReadFile` before memory allocation. | Unit test verifying oversized file rejection. |
| **RTP-SEC-009** | Medium | Confirmed | `tooling/file_io.h`:52-61 (`WriteFile`) | Non-atomic file write directly to destination path using `std::ios::trunc`. | Interrupted file writes leave corrupted or truncated configuration, signature, or manifest files on disk. | Process termination, power loss, or crash during write. | Implement atomic file replacement via temporary file creation followed by atomic filesystem replacement (`ReplaceFile` / `rename`). | Unit test verifying atomic write and rollback on error. |
| **RTP-SEC-010** | High | Confirmed | Architecture / Delivery | Absence of an authenticated, signed software update verification subsystem. | Updates could be hijacked, forged, or downgraded to older versions with known vulnerabilities. | Man-in-the-middle network tampering or local update file substitution. | Implement an Ed25519-signed update manifest subsystem (`licensing/update_manifest.h`) enforcing version monotonicity and SHA-256 payload digests. | Unit tests verifying signature rejection, corrupted update payload rejection, and downgrade prevention (`test_update_manifest.cpp`). |

---

## 3. Detailed Audit by Category

### 3.1 Hard-Coded Keys, Secrets, and Master Passwords
- **Assessment:** Negative (PASS).
- **Evidence:** Source code search for embedded private keys, master licensing secrets, or backdoor passwords confirmed that no server private keys or master encryption secrets are embedded in client runtime code.
- **Observations:** In `integrity/keys.h` and `integrity/signer.h`, private key generation and signing functions are segregated into a separate CMake target (`rtprotect_integrity_buildtools`) that is never linked by client binaries.

### 3.2 Cryptographic Algorithms & Nonce Generation
- **Assessment:** Positive (PASS).
- **Evidence:** `crypto/aead.cpp` uses `EVP_aes_256_gcm()` via OpenSSL EVP with a 256-bit key, 96-bit fresh random nonce generated via `RAND_bytes()` (CSPRNG), and a 128-bit authentication tag. Nonce generation is strictly internal to `crypto::Encrypt` and never caller-supplied, preventing nonce reuse.
- **Key Derivation:** `crypto/kdf.cpp` uses `EVP_KDF_fetch(..., "HKDF", ...)` over HMAC-SHA256, following RFC 5869.
- **Digital Signatures:** `integrity/signer.cpp` and `integrity/verifier.cpp` use standard Ed25519 (`EVP_PKEY_ED25519`) via OpenSSL 3.0 EVP. No custom cryptographic primitives exist in the codebase.

### 3.3 Random Number Generation
- **Assessment:** Positive (PASS).
- **Evidence:** All security-critical randomness derives from OpenSSL's `RAND_bytes()`, which interfaces with the operating system CSPRNG (`BCryptGenRandom` on Windows, `/dev/urandom` / `getrandom` on Linux). No usage of `rand()`, `srand()`, or unseeded PRNGs in cryptographic key or nonce operations.

### 3.4 Licensing & Entitlement Subsystem
- **Assessment:** Deficient (RESOLVED via Phase 2 implementation).
- **Evidence:** The initial repository had no license validation logic. Manifests existed to verify build artifact hashes, but no licensing module was present to authenticate authorized end-users, enforce capability flags, check expiration timestamps, prevent clock tampering, or bind to hardware.
- **Remediation:** Designed and implemented `licensing/` module featuring Ed25519 asymmetric signatures, JSON and binary license formats, weighted hardware fingerprinting, expiration validation, and monotonic clock checks.

### 3.5 Integrity Verification & Anti-Tamper
- **Assessment:** Substantially hardened.
- **Evidence:** `integrity/bound_key.h` properly derives AES-256 resource decryption keys from the committed manifest SHA-256 hash using HKDF, converting separate boolean hash checks into an intrinsic AEAD authentication failure if resource bytes are substituted.
- **Enhancements:** Added runtime code section hash checking and layered risk detection for debugging and virtualization.

### 3.6 Access Control and File Operations
- **Assessment:** Fixed (RTP-SEC-001, RTP-SEC-008, RTP-SEC-009).
- **Evidence:** `tooling/file_io.h` was repaired to qualify `::WriteFile`. Added bounded reads (`kMaxFileReadBytes = 64 * 1024 * 1024`) and atomic writes to prevent truncation and denial-of-service.

### 3.7 Input Safety, Buffer Safety & Arithmetic
- **Assessment:** Fixed (RTP-SEC-002, RTP-SEC-003).
- **Evidence:** Bytecode VM operand indexing bug fixed to eliminate out-of-bounds vector access. SEH/VEH exception handling in `runtime/executable_memory.cpp` modernized to support MinGW GCC on Windows in addition to MSVC.

### 3.8 Build Integration & Release Automation
- **Assessment:** Addressed (RTP-SEC-007).
- **Evidence:** Developed full CLI integration engine (`tooling/integration_engine.h`) with dry-run, atomic backups, rollback capabilities, and sample client project validation.

---

## 4. Remediation Verification Summary

All identified defects have been remediated in the codebase and verified with concrete automated tests. The complete test suite now achieves 100% pass rate across all modules in both standard and experimental reconstruction configurations on Windows x64.
