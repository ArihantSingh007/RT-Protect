# Changelog

All notable changes to the RTProtect framework are documented in this file.
This project adheres to Semantic Versioning and structured security reporting.

---

## [2.0.0-hardened] - 2026-10-20

### 1. Critical Security Vulnerability Remediations

- **RTP-SEC-001 (Fix Unqualified Symbol Collision in Windows File I/O):**
  - *Location:* `tooling/file_io.h:124`
  - *Fix:* Qualified the Win32 API call `::WriteFile` to prevent resolution collisions with `rtprotect::tooling::WriteFile`.
  - *Impact:* Resolved build-breaking compilation errors on Windows toolchains.

- **RTP-SEC-002 (Fix Out-Of-Bounds Memory Access in Bytecode VM):**
  - *Location:* `bytecode_vm/vm.cpp:77-84`
  - *Fix:* Added boundary validation before operand address computation. Single-byte terminal instructions (e.g. `Opcode::kRet`) no longer evaluate `&code[pc + 1]`, preventing `_GLIBCXX_ASSERTIONS` runtime aborts and OOB memory disclosures.

- **RTP-SEC-003 (Implement Portability Layer for Windows Vectored Exception Handling):**
  - *Location:* `runtime/executable_memory.cpp:285-315`
  - *Fix:* Replaced compiler-exclusive MSVC `__try/__except` with Windows Vectored Exception Handling (`AddVectoredExceptionHandler` with `setjmp`/`longjmp`) under MinGW GCC, while preserving native SEH on MSVC.

- **RTP-SEC-004 (Eliminate Symmetric Master Secrets in Client Licensing):**
  - *Location:* `licensing/` subsystem
  - *Fix:* Replaced obsolete symmetric constructions with **Ed25519** asymmetric digital signatures (RFC 8032). Client binaries embed strictly the vendor's 32-byte public key (`Ed25519PublicKey`). The private signing key (`Ed25519PrivateKey`) is segregated to build/licensing servers only.

- **RTP-SEC-005 (Implement Hardware-Bound Machine Fingerprinting):**
  - *Location:* `licensing/hardware_id.h`, `licensing/hardware_id.cpp`
  - *Fix:* Implemented 4-metric hardware fingerprinting combining CPU model/features, system storage volume serial, OS MachineGuid, and host identity. Component metrics are hashed with SHA-256 for privacy and evaluated via weighted similarity scoring.

- **RTP-SEC-006 (Implement Monotonic Update Manifests to Prevent Downgrade Attacks):**
  - *Location:* `licensing/update_manifest.h`, `licensing/update_manifest.cpp`
  - *Fix:* Replaced unsequenced update records with digitally signed manifests containing strict monotonic sequence numbers, cryptographically blocking replay and downgrade attacks.

- **RTP-SEC-007 (Implement Runtime Anti-Tamper & Environment Risk Engine):**
  - *Location:* `antitamper/` subsystem
  - *Fix:* Implemented non-destructive, policy-driven environment risk assessment: detecting user-mode debuggers (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`), hardware breakpoint registers (DR0-DR3), timing anomalies (RDTSC/QPC), and hypervisor signatures. Enforces tiered actions (`ReportOnly`, `Restrict`, `Terminate`).

- **RTP-SEC-008 (Enforce Bounded Safe File Reads):**
  - *Location:* `tooling/file_io.h:40-75`
  - *Fix:* Enforced a maximum file read limit of 64MB (`kMaxFileReadBytes`), preventing heap exhaustion and denial-of-service from reading untrusted oversized files.

- **RTP-SEC-009 (Implement Atomic File Writes):**
  - *Location:* `tooling/file_io.h:40-75`
  - *Fix:* Implemented atomic file writing via temporary file creation (`.tmp`) followed by atomic rename (`MoveFileExA` / `rename`), preventing corrupt truncated files if the process is terminated mid-write.

- **RTP-SEC-010 (Implement Polymorphic Opcode Map Permutation):**
  - *Location:* `bytecode_vm/opcode_map.h`, `bytecode_vm/opcode_map.cpp`
  - *Fix:* Created a seedable bijective permutation table for bytecode VM opcode dispatch, allowing build-specific opcode variations to break static disassemblers.

---

### 2. New Subsystems & Architectural Components

- **Asymmetric Licensing Subsystem (`licensing/`):**
  - Canonical binary wire format with `0x5254504C` magic identifier and schema versioning.
  - Granular capability bitmask flags (`kCapCoreExecution`, `kCapAdvancedFeatures`, `kCapCommercialUse`, etc.) and named string feature flags.
  - Temporal validity checking with clock rollback protection and offline grace periods.
  - Separation of build-only signer target (`rtprotect_licensing_buildtools`) from client verifier target (`rtprotect_licensing`).

- **Project Integration Engine & CLI (`tooling/`):**
  - Implemented `rtprotect-tool` commands: `integrate`, `rollback`, `validate-build`, `license-generate`, `license-verify`, `license-inspect`, `fingerprint`, `--version`, and `--help`.
  - Transactional project integration: dry-run change plan previews, automated project backups, code generation (`rtprotect_config.h`, `rtprotect_runtime_glue.cpp`), CMakeLists instrumentation, and post-build verification.
  - Reversible rollback restoring pre-integration files byte-for-byte and removing generated artifacts.
  - Directory boundary validation (`IsPathWithin`) to prevent path traversal vulnerabilities.

- **Sample Protected Enterprise Application (`examples/sample_client_app/`):**
  - Realistic commercial client application demonstrating full integration with RTProtect.
  - End-to-end verified: compiles cleanly, verifies license and digital signatures, and terminates safely upon detection of tampering, forged signatures, or missing licenses.

---

### 3. Automated Test Suite Expansion

- **18 Standard Test Targets (100% Pass Rate):**
  - `test_aead`, `test_kdf`, `test_vm`, `test_protected_checksum`, `test_manifest`, `test_signing`, `test_bound_key`, `test_file_io`, `test_checked_arith_fallback`, `test_secure_buffer`, `test_obfuscated_string`, `test_checksum_flattened`.
  - *New:* `test_license` (license serialization, Ed25519 signatures, clock rollback).
  - *New:* `test_hardware_id` (hardware metrics, hashing, similarity tolerance).
  - *New:* `test_update_manifest` (update sequences, downgrade prevention).
  - *New:* `test_antitamper` (debugger detection, DR0-DR3 registers, hypervisor detection).
  - *New:* `test_opcode_map` (seeded bijective opcode permutations).
  - *New:* `test_integration_engine` (planning, dry-run, transactional execution, rollback, path traversal prevention).

- **2 Experimental Reconstruction Targets (100% Pass Rate):**
  - `test_executable_memory` and `test_reconstructed_function` passing under `-DRTPROTECT_ENABLE_EXPERIMENTAL_RUNTIME_RECONSTRUCTION=ON`.

---

### 4. Comprehensive Documentation Suite

- `SECURITY_AUDIT.md`: 10-finding vulnerability matrix with severity, confidence, line locations, root causes, impacts, remediations, and verification tests.
- `docs/THREAT_MODEL.md`: Attacker capabilities, trust boundaries, mitigations, work-factor cost increases, and residual risks.
- `docs/SECURITY_ARCHITECTURE.md`: Component layout, module boundaries, profiles, and data flows.
- `docs/INTEGRATION_GUIDE.md`: Developer guide for project integration, profiles, rollback, and troubleshooting.
- `docs/LICENSING.md`: Cryptographic specification, binary wire layout, hardware ID binding, and key management.
- `docs/BUILD_AND_RELEASE.md`: Toolchain requirements, compiler hardening flags, reproducible build instructions, and release packaging.
- `docs/TESTING.md`: Test matrix, adversarial test vectors, and sanitizer configurations.
