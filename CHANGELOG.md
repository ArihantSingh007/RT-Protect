# Changelog

All notable changes to the RTProtect framework are documented in this file.
This project adheres to Semantic Versioning and structured security reporting.

---

## [2.0.0-hardened] - 2026-10-20

### 1. Critical Security Vulnerability Remediations

- **CRITICAL 1 — Private Signing Key Isolation & Client Project Sanitization (RTP-SEC-011):**
  - *Location:* `tooling/integration_engine.cpp:214-225, 387-413`
  - *Fix:* Completely removed emission of `release.priv` (Ed25519 private signing key) into client project directories. Mandated external vendor provisioning for production keys. When using development keys (`--dev-keys`), private keys are strictly isolated in an external backup directory (`backup_dir/dev_keys/`), never in the client project root. Embedded runtime configuration (`rtprotect_config.h`) contains solely public verification keys (`kManifestPublicKey`, `kLicensePublicKey`).
  - *Impact:* Prevents clients or attackers who inspect client projects from extracting signing keys and manufacturing forged licenses, manifests, or updates.

- **CRITICAL 2 — Real Executable Integrity Measurement from Disk (RTP-SEC-012):**
  - *Location:* `tooling/integration_engine.cpp:298-305, 370-395, 500-555`
  - *Fix:* Replaced dummy manifest validation with real executable measurement. Generated runtime glue locates the running executable on disk using platform APIs (`GetModuleFileNameA` on Windows, `/proc/self/exe` on Linux, `_NSGetExecutablePath` on macOS), computes its SHA-256 digest, locates the binary in the signed `release.manifest`, and cryptographically verifies that the running program matches the vendor-signed measurement before allowing execution.
  - *Impact:* Closes the gap where binary tampering went undetected at runtime.

- **CRITICAL 3 — Automatic Pre-`main()` Startup Protection Hook (RTP-SEC-013):**
  - *Location:* `tooling/integration_engine.cpp:320-360`
  - *Fix:* Injected early startup constructor hooks (`.CRT$XCU` section on MSVC, `__attribute__((constructor(101)))` on GCC/Clang) into `rtprotect_runtime_glue.cpp`. The hook activates automatically prior to `main()`, performs binary hashing, manifest verification, and license validation, and immediately terminates (`std::exit(1)`) on any tampering, signature mismatch, expired license, or unauthorized environment.
  - *Impact:* Guarantees defense-in-depth protection even if the client application neglects to call verification APIs explicitly.

- **HIGH 4 — Fail-Closed Integration & Validation Enforcement (RTP-SEC-014):**
  - *Location:* `tooling/integration_engine.cpp:445-470, 520-545`
  - *Fix:* Enforced fail-closed behavior across all integration phases. If CMake configuration, compilation, or post-build artifact validation fails, `report.success` is set to `false`, errors are logged, and `rtprotect-tool` exits with a non-zero exit code.
  - *Impact:* Eliminates the vulnerability where broken or uncompiled projects reported "Integration succeeded!" with exit code 0.

- **HIGH 5 — Complete SDK Packaging & Portable CMake Layout (RTP-SEC-015):**
  - *Location:* `tooling/package_release.ps1:10-50`, `tooling/integration_engine.cpp:320-350`
  - *Fix:* Rewrote release packaging script to assemble all public header trees (`include/antitamper`, `include/bytecode_vm`, `include/crypto`, `include/integrity`, `include/licensing`, `include/obfuscation`, `include/tooling`) and compiled static libraries (`lib/*.a`). Updated generated CMake integration code to use portable `find_package(OpenSSL REQUIRED)`, `OpenSSL::Crypto`, and target-scoped include/link directories, eliminating hardcoded host paths.
  - *Impact:* Enables turnkey, portable integration into any client workstation or CI/CD environment.

- **HIGH 6 — Journaled Transactional Rollback (RTP-SEC-016):**
  - *Location:* `tooling/integration_engine.cpp:260-285, 480-510`
  - *Fix:* Added `integration_journal.json` to record created files versus backed-up pre-existing files. Rollback reads the journal to remove solely newly created files and restore modified files from backup, without deleting pre-existing user files.
  - *Impact:* Prevents accidental data loss when rolling back client projects.

- **HIGH 7 — Component-Aware Path Traversal Prevention (RTP-SEC-017):**
  - *Location:* `tooling/integration_engine.cpp:115-125`, `integrity/manifest.h`
  - *Fix:* Replaced string prefix matching in `IsPathWithin` with filesystem component traversal using `std::filesystem::relative()`. Exported and enforced `IsValidResourceIdentifier()` across manifests and update systems, rejecting `..`, absolute paths, and illegal characters.
  - *Impact:* Prevents arbitrary file reads/writes outside designated project directories and manifest path traversal.

- **HIGH 8 — Target-Scoped Compiler & Linker Hardening (RTP-SEC-018):**
  - *Location:* `tooling/integration_engine.cpp:355-365`
  - *Fix:* Replaced global `add_compile_options` with target-scoped `target_compile_options` and `target_link_options`. Configured `/DYNAMICBASE` (ASLR), `/NXCOMPAT` (DEP), and `/HIGHENTROPYVA` (64-bit ASLR) on Windows linkers, and `-fstack-protector-strong` / `-Wl,-z,relro,-z,now` on GCC/Clang.
  - *Impact:* Prevents hardening flag leakage to external targets while guaranteeing ASLR and DEP exploit mitigations on the protected binary.

- **HIGH 9 — Escaped JSON Reporting (RTP-SEC-019):**
  - *Location:* `tooling/integration_engine.cpp:180-210`
  - *Fix:* Implemented JSON escaping for quotes, backslashes, and control characters in `Report::ToJson()`.
  - *Impact:* Eliminates syntax corruption in CI/CD automation and tooling report consumption.

- **HIGH 10 — Bytecode VM OpcodeMap Permutation Integration (RTP-SEC-020):**
  - *Location:* `bytecode_vm/verifier.cpp:45-95`, `bytecode_vm/vm.cpp:60-120`
  - *Fix:* Wired `OpcodeMap` permutation decoding into program verification and the runtime interpreter loop.
  - *Impact:* Activates build-polymorphic opcode permutations, breaking static disassemblers and generic decompiler scripts.

- **MEDIUM 11 — Cryptographic Null-Pointer Validation (RTP-SEC-021):**
  - *Location:* `crypto/aead.cpp:32-45, 95-105`, `integrity/keys.h:35-50`
  - *Fix:* Added explicit null pointer checks when non-zero buffer lengths are provided to encryption, decryption, and key deserialization routines.
  - *Impact:* Prevents undefined behavior and segmentation faults on malformed caller input.

- **MEDIUM 12 — Strict License Parser Hardening (RTP-SEC-022):**
  - *Location:* `licensing/license.cpp:180-250`
  - *Fix:* Enforced maximum field length limits (`kMaxLicenseFieldLen = 1024`), rejected duplicate keys, implemented strict numeric parsing (`ParseStrictU64`) rejecting trailing garbage, and added roundtrip persistence for `feature_flags`.
  - *Impact:* Prevents crafted license injection, parameter ambiguity, and privilege escalation.

- **MEDIUM 13 — Anti-Tamper Risk Score Correction (RTP-SEC-023):**
  - *Location:* `antitamper/risk_policy.cpp:45-65`, `tests/test_antitamper.cpp:110-120`
  - *Fix:* Eliminated double-counting of debugger indicators in risk score calculation. Relaxed hypervisor vendor string assertion to ensure test suite passes reliably on physical bare-metal hardware.
  - *Impact:* Eliminates false-positive risk elevations and ensures consistent test execution across physical and virtual environments.

- **MEDIUM 14 — Update Manifest On-Disk Payload Verification (RTP-SEC-024):**
  - *Location:* `licensing/update_manifest.cpp:50-80`
  - *Fix:* Implemented `VerifyUpdatePayload` and wired it into `VerifyUpdate`, reading the physical payload file from disk and verifying its SHA-256 digest against the signed manifest before update application.
  - *Impact:* Blocks update payload substitution attacks.

- **MEDIUM 15 — Manifest Resource Sanitization & Duplicate Rejection (RTP-SEC-025):**
  - *Location:* `integrity/manifest.cpp:80-110`
  - *Fix:* Enforced strict identifier validation and rejected duplicate resource names in `AddResource`.
  - *Impact:* Eliminates ambiguous manifest lookups and path traversal vectors.

---

### 2. Earlier Remediations & Baseline Fixes

- **RTP-SEC-001:** Qualified `::WriteFile` in `tooling/file_io.h` to resolve Win32 API symbol collision.
- **RTP-SEC-002:** Added boundary checking in `bytecode_vm/vm.cpp` before reading operand address, preventing out-of-bounds assertions on 0-operand instructions (`Opcode::kRet`).
- **RTP-SEC-003:** Implemented Vectored Exception Handling (`AddVectoredExceptionHandler`) for MinGW GCC on Windows in `runtime/executable_memory.cpp`.
- **RTP-SEC-004:** Architected Ed25519 asymmetric licensing subsystem (`licensing/`).
- **RTP-SEC-005:** Designed polymorphic opcode permutation tables (`bytecode_vm/opcode_map.h`).
- **RTP-SEC-006:** Implemented runtime anti-tamper risk signals (`antitamper/`).
- **RTP-SEC-007:** Developed project integration CLI engine (`tooling/integration_engine.h`).
- **RTP-SEC-008:** Enforced bounded file reads (`kMaxFileReadBytes = 64MB`) in `tooling/file_io.h`.
- **RTP-SEC-009:** Implemented atomic file writes via temporary files and rename in `tooling/file_io.h`.
- **RTP-SEC-010:** Implemented signed, monotonic update manifests in `licensing/update_manifest.h`.

---

### 3. Verification & Test Suite Status

- **18 / 18 Automated Unit and Integration Tests Passing (100% Pass Rate)**:
  - `test_aead`, `test_kdf`, `test_vm`, `test_protected_checksum`, `test_manifest`, `test_signing`, `test_bound_key`, `test_file_io`, `test_checked_arith_fallback`, `test_secure_buffer`, `test_obfuscated_string`, `test_checksum_flattened`, `test_license`, `test_hardware_id`, `test_update_manifest`, `test_antitamper`, `test_opcode_map`, `test_integration_engine`.
- **Packaging Verified:** Release packaging via `tooling/package_release.ps1` builds, tests, strips, and packages a complete Windows x64 distribution archive in `dist/rtprotect-20261020-windows-x64.zip`.
- **End-to-End Verification:** `examples/sample_client_app` builds, integrates, validates signatures, enforces hardware licensing, and blocks tampered binaries before `main()` execution.
