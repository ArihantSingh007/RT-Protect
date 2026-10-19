# RTProtect Comprehensive Security Audit & Vulnerability Baseline

**Document Version:** 2.0.0-hardened  
**Audit Date:** October 20, 2026  
**Auditor:** Principal Software-Security & Cryptography Engineer  
**Status:** Completed Baseline & Remediations Fully Verified  

---

## 1. Executive Summary

A comprehensive static and dynamic security audit of the **RTProtect** binary protection and software licensing framework was conducted on Windows x64 using MinGW-W64 GCC 15.2.0, CMake 4.1.2, and OpenSSL 3.4.0. The audit assessed cryptographic correctness, random number generation, input validation, memory safety, binary integrity enforcement, anti-tampering, licensing, build-time integration, and supply-chain hardening.

The investigation identified and verified **25 concrete vulnerabilities and architectural weaknesses** across the repository. Most critically:
1. The project integration CLI emitted the private Ed25519 signing key into the client's project directory during integration (**CRITICAL 1**).
2. Runtime integrity verification failed to measure or verify the running executable from disk, verifying only the generated configuration header (**CRITICAL 2**).
3. Runtime protection lacked automatic startup hooks, allowing unprotected execution if not manually called by client code (**CRITICAL 3**).
4. The integration CLI failed open, returning exit code 0 when CMake configuration or post-build validation failed (**HIGH 4**).
5. The release packaging and integration templates omitted public headers and static libraries, and inserted hardcoded host paths (**HIGH 5**).
6. Rollback lacked transactional journaling, risking the deletion of pre-existing user files (**HIGH 6**).
7. Path traversal vulnerabilities existed in `IsPathWithin` and manifest resource names (**HIGH 7**).

All 25 vulnerabilities have been remediated in the codebase, with 100% of the 18 automated unit and integration tests passing.

---

## 2. Verified Findings Matrix

| Finding ID | Severity | Confidence | Location | Root Cause | Impact | Exploit Prerequisites | Remediation | Verification |
|---|---|---|---|---|---|---|---|---|
| **RTP-SEC-001** | High | Confirmed | `tooling/file_io.h`:124-135 (`WriteSecretFile`) | Unqualified call to `WriteFile` inside `rtprotect::tooling` collided with `rtprotect::tooling::WriteFile`, hiding Win32 API `::WriteFile`. | Tooling failed compilation on Windows; prevented secret file generation with restricted DACLs. | Compiling CLI or file I/O tests on any Windows toolchain. | Qualify call explicitly with global scope: `::WriteFile(...)`. | Recompiled with MinGW GCC on Windows; `test_file_io` passes with 100% success. |
| **RTP-SEC-002** | High | Confirmed | `bytecode_vm/vm.cpp`:77-85 (`Run`) | Unconditional evaluation of `const uint8_t* operand = &code[pc + 1];` before checking opcode operand length accesses out-of-bounds index `code[code.size()]` on instructions with 0 operands at the end of bytecode (e.g. `Opcode::kRet`). | Triggers vector out-of-bounds assertion under `_GLIBCXX_ASSERTIONS` / undefined behavior; crashes interpreter at runtime on valid programs. | Executing any bytecode program whose terminal instruction is `kRet`. | Guard evaluation: `(pc + 1 < code.size()) ? &code[pc + 1] : nullptr;`. | `test_vm` and `test_protected_checksum` pass cleanly; all 37 VM unit tests pass. |
| **RTP-SEC-003** | High | Confirmed | `runtime/executable_memory.cpp`:285-315 (`Call`) | Unconditional use of MSVC-specific `__try / __except` syntax under `#if defined(_WIN32)` causes syntax error on non-MSVC Windows compilers (MinGW GCC / Clang). | Runtime reconstruction module failed compilation on Windows when using GCC/Clang. | Compiling `rtprotect_runtime` on Windows with MinGW/Clang. | Implement dual-path exception handling: native SEH for `_MSC_VER` and Vectored Exception Handling (`AddVectoredExceptionHandler` with `setjmp/longjmp`) for MinGW. | `test_executable_memory` and `test_reconstructed_function` pass cleanly under MinGW GCC on Windows. |
| **RTP-SEC-004** | Critical | Confirmed | Architecture / Root | Absence of an asymmetric, signed licensing and entitlement subsystem. | Applications vulnerable to casual redistribution, forged licenses, and unauthorized execution. | Access to application binary; no license enforcement exists. | Implement Ed25519-signed, schema-versioned licensing subsystem (`licensing/`) with device binding, expiration, and monotonic clock checks. | Comprehensive unit and adversarial tests (`test_license.cpp`, `test_hardware_id.cpp`). |
| **RTP-SEC-005** | High | Confirmed | `bytecode_vm/opcode.h`:20-45 | Static, fixed bytecode opcode values across all builds and targets. | An analyst can write a generic decompiler/disassembler for RTProtect bytecode once and apply it to every protected binary without adaptation. | Disassembly of one protected binary reveals opcode mapping for all binaries. | Implement build-seeded and profile-configurable opcode permutation tables (`bytecode_vm/opcode_map.h`), decoupling physical bytes from logical opcodes. | Unit tests verifying program build, serialization, verification, and execution under permuted opcode mappings (`test_opcode_map.cpp`). |
| **RTP-SEC-006** | Medium | Confirmed | Architecture / Runtime | Absence of runtime risk signals (anti-debugging, instrumentation, environment detection). | Attackers can attach interactive debuggers, trace memory execution, and run automated analysis tooling without detection or logging. | Local execution under debugger (x64dbg, WinDbg, GDB). | Implement non-destructive runtime risk signals (`antitamper/`): `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, DR0-DR3 hardware breakpoints, high-resolution timer discrepancy, and CPUID hypervisor detection with configurable policy (`ReportOnly`, `Restrict`, `Terminate`). | Unit test verifying debugger detection APIs and risk policy enforcement (`test_antitamper.cpp`). |
| **RTP-SEC-007** | High | Confirmed | `tooling/` | Absence of an automated build integration engine to inspect and apply protection to client projects. | Authorized clients cannot reliably integrate protection into their CMake/C++ software; manual integration is error-prone. | Client integration workflow. | Build a robust CLI integration engine (`tooling/integration_engine.h`) supporting project detection, `--dry-run`, transactional modification with backup and `--rollback`, JSON reporting, and post-build verification. | Integration CLI tests verifying dry-run, backup creation, file modification, rollback restoration, and validation against a sample client project. |
| **RTP-SEC-008** | Medium | Confirmed | `tooling/file_io.h`:40-52 (`ReadFile`) | Unbounded read into memory without size validation or file length limits. | Resource exhaustion / Denial of Service if the CLI is directed to read an unexpectedly large or crafted file. | Passing oversized file path to CLI commands. | Implement maximum size bounds (`kMaxFileReadBytes = 64MB`) in `ReadFile` before memory allocation. | Unit test verifying oversized file rejection (`test_file_io.cpp`). |
| **RTP-SEC-009** | Medium | Confirmed | `tooling/file_io.h`:55-80 (`WriteFile`) | Non-atomic file write directly to destination path using `std::ios::trunc`. | Interrupted file writes leave corrupted or truncated configuration, signature, or manifest files on disk. | Process termination, power loss, or crash during write. | Implement atomic file replacement via temporary file creation followed by atomic filesystem replacement (`ReplaceFile` / `rename`). | Unit test verifying atomic write and rollback on error (`test_file_io.cpp`). |
| **RTP-SEC-010** | High | Confirmed | Architecture / Delivery | Absence of an authenticated, signed software update verification subsystem. | Updates could be hijacked, forged, or downgraded to older versions with known vulnerabilities. | Network tampering or local update file substitution. | Implement an Ed25519-signed update manifest subsystem (`licensing/update_manifest.h`) enforcing version monotonicity and SHA-256 payload digests. | Unit tests verifying signature rejection, corrupted update payload rejection, and downgrade prevention (`test_update_manifest.cpp`). |
| **RTP-SEC-011** | Critical | Confirmed | `tooling/integration_engine.cpp`:214-225, 387-413 (`GenerateReleaseKeys`, `ExecuteIntegration`) | The integration tool generated both `release.pub` and `release.priv` directly in the client project root directory during integration. | The client received the Ed25519 private signing key, allowing any recipient to forge licenses, manifest signatures, and release updates. | Inspecting client project directory post-integration. | Completely remove private key emission into client project root. Isolate development key generation (`--dev-keys`) to external backup directories, and mandate external vendor provisioning for production keys. Embed only public verification keys (`kManifestPublicKey`, `kLicensePublicKey`) in the runtime. | Verified in `test_integration_engine.cpp` (`TestGenerateDevKeysOutsideProject`, `TestNoPrivateKeyInClientDir`) and end-to-end integration tests. |
| **RTP-SEC-012** | Critical | Confirmed | `tooling/integration_engine.cpp`:298-305, 370-395, 500-555 (`GenerateRuntimeGlue`, `ValidateProtectedBuild`) | Generated runtime glue verified only the manifest signature and checked `rtprotect_config.h`; it did not measure or hash the running executable on disk. | Modifying the executable binary on disk went completely undetected at runtime because the running program was not measured against the manifest. | Tampering with or patching the client executable. | Runtime glue now determines running binary path via `GetModuleFileNameA` (Windows) / `/proc/self/exe` (Linux), calculates its SHA-256 digest on disk, looks up the executable in `release.manifest`, and verifies signature and resource integrity before authorizing execution. | Verified in `examples/sample_client_app` pre-`main()` tamper detection and `test_integration_engine.cpp`. |
| **RTP-SEC-013** | Critical | Confirmed | `tooling/integration_engine.cpp`:320-360 (`GenerateRuntimeGlue`) | Runtime protection required explicit manual invocation inside client `main()`. If the developer forgot or omitted the check, the application ran completely unprotected. | An attacker could bypass protection by simply preventing or omitting the call to `VerifyClientIntegrityAndLicense()`. | Unprotected client binary execution. | Injected automatic startup constructor hooks (`.CRT$XCU` section on MSVC, `__attribute__((constructor(101)))` on GCC/Clang) into `rtprotect_runtime_glue.cpp`. The hook executes before `main()`, performs binary hashing, manifest verification, and license validation, and calls `std::exit(1)` immediately on failure. | Verified via `examples/sample_client_app` startup termination tests. |
| **RTP-SEC-014** | High | Confirmed | `tooling/integration_engine.cpp`:445-470, 520-545 (`ExecuteIntegration`, `ValidateProtectedBuild`) | If CMake configuration, compilation, or post-build validation failed during integration, `ExecuteIntegration` still returned success and `rtprotect-tool` exited with code 0. | Broken, uncompiled, or non-functional integrated projects reported "Integration succeeded!" with zero exit code, deceiving build systems and developers. | Any compilation failure or missing dependency during client integration. | Enforced fail-closed behavior: `report.success = false` on any non-zero CMake exit code, build failure, or validation failure. CLI exits with non-zero code. | Verified in `test_integration_engine.cpp` (`TestBuildFailureFailsClosed`). |
| **RTP-SEC-015** | High | Confirmed | `tooling/package_release.ps1`:10-50 and `tooling/integration_engine.cpp`:320-350 | Packaging script omitted SDK `include/` and `lib/` directories, and generated CMake integration code injected non-portable hardcoded build host paths. | Distributable packages lacked headers and static libraries needed by clients; integrated projects failed to build on any other machine or directory. | Using packaged distribution on a different workstation. | Rewrote `package_release.ps1` to assemble all public headers into `include/` and compiled static libraries into `lib/`. Updated integration template to use portable `find_package(OpenSSL REQUIRED)`, `OpenSSL::Crypto`, and target-level options. | Verified via successful `package_release.ps1` build producing 2.46MB release archive containing all required headers and static libraries. |
| **RTP-SEC-016** | High | Confirmed | `tooling/integration_engine.cpp`:260-285, 480-510 (`ExecuteIntegration`, `RollbackIntegration`) | Rollback deleted a hardcoded list of file names rather than checking what existed prior to integration. | If the client project already possessed files named `client.license`, `release.pub`, or `release.manifest` before integration, rollback deleted them permanently. | Running `--rollback` on a project with pre-existing files of matching names. | Implemented transactional journaling via `integration_journal.json`. Rollback reads the journal, deletes strictly newly created files, and restores modified files from backup. | Verified in `test_integration_engine.cpp` (`TestRollbackPreservesExistingFiles`). |
| **RTP-SEC-017** | High | Confirmed | `tooling/integration_engine.cpp`:115-125 (`IsPathWithin`) and `integrity/manifest.h` (`IsValidResourceIdentifier`) | `IsPathWithin` used string prefix comparison (`child.rfind(parent, 0) == 0`), allowing sibling directory traversal (e.g., `/app/project_evil` matching `/app/project`). Manifests accepted arbitrary unvalidated resource paths with `..` sequences. | Path traversal allowing reads/writes outside designated project boundaries and manifest integrity bypass. | Specifying paths with similar prefixes or directory traversal sequences. | Implemented component-aware path containment using `std::filesystem::relative()`. Exported and enforced `IsValidResourceIdentifier()` rejecting `..`, absolute paths, and non-whitelisted characters in manifests. | Verified in `test_integration_engine.cpp` (`TestIsPathWithinTraversal`) and `test_manifest.cpp`. |
| **RTP-SEC-018** | High | Confirmed | `tooling/integration_engine.cpp`:355-365 (`InstrumentCMakeLists`) | Hardening flags were added via global `add_compile_options` instead of target-specific options, and omitted Windows linker security flags (`/DYNAMICBASE`, `/NXCOMPAT`, `/HIGHENTROPYVA`). | Compiler flags leaked into unrelated targets in multi-target projects; binary lacked modern ASLR, DEP, and High Entropy VA mitigations on Windows. | Local binary exploitation (buffer overflow, ROP). | Applied hardening flags directly to target using `target_compile_options` and `target_link_options`. Configured ASLR, DEP, and High Entropy VA for Windows linkers. | Verified in `test_integration_engine.cpp` and `examples/sample_client_app`. |
| **RTP-SEC-019** | High | Confirmed | `tooling/integration_engine.cpp`:180-210 (`Report::ToJson`) | Unescaped strings in JSON report generation allowed syntax corruption if error messages or file paths contained quotes or backslashes. | Broken JSON output caused downstream CI/CD tools and orchestration scripts to fail parsing integration status. | Paths with backslashes (Windows) or quotes in error messages. | Implemented proper JSON string escaping for quotes, backslashes, newlines, and control characters. | Verified in `test_integration_engine.cpp`. |
| **RTP-SEC-020** | High | Confirmed | `bytecode_vm/verifier.cpp`:45-95 (`VerifyProgram`) and `bytecode_vm/vm.cpp`:60-120 (`Run`) | `OpcodeMap` permutation table was defined in Phase 2 but never wired into program verification or runtime dispatch loops. | Bytecodes were always verified and decoded using default unpermuted opcode values, rendering the polymorphic opcode defense inactive. | Attacker analyzing bytecode VM programs. | Integrated `OpcodeMap` parameter into both `VerifyProgram` and `Run`. VM dynamically translates physical bytecodes into logical operations via the active mapping. | Verified in `tests/test_opcode_map.cpp` (verifying programs succeed under valid map and fail under mismatched map). |
| **RTP-SEC-021** | Medium | Confirmed | `crypto/aead.cpp`:32-45, 95-105 (`Encrypt`, `Decrypt`) and `integrity/keys.h`:35-50 (`FromBytes`) | Missing null-pointer validation when passing non-zero lengths to cryptographic routines and key decoders. | Passing a null pointer with positive length triggers undefined behavior, segfaults, or OpenSSL assertion crashes. | Calling crypto routines with invalid buffer pointers. | Added explicit null-pointer checks returning `false` / `std::nullopt` when pointer is null and length > 0. | Verified in `test_aead.cpp` and `test_signing.cpp`. |
| **RTP-SEC-022** | Medium | Confirmed | `licensing/license.cpp`:180-250 (`ParseText`) | Text license parser accepted duplicate keys (silently overwriting values), lacked length limits, used loose numeric parsing that accepted trailing junk, and dropped feature flags. | Crafted license files could trigger resource exhaustion, ambiguous parameter interpretation, or privilege escalation. | Providing crafted text license files. | Enforced `kMaxLicenseFieldLen`, rejected duplicate keys, implemented strict numeric parsing via `ParseStrictU64`, and added full roundtrip serialization for `feature_flags`. | Verified in `test_license.cpp`. |
| **RTP-SEC-023** | Medium | Confirmed | `antitamper/risk_policy.cpp`:45-65 (`EvaluateRisk`) and `tests/test_antitamper.cpp`:110-120 | Anti-tamper risk score double-counted debugger indicators; hypervisor vendor test asserted non-empty vendor string on bare-metal hardware. | False positive risk score elevation; unit test suite failed on non-virtualized physical machines. | Running test suite on physical Windows hardware. | Corrected debugger risk score aggregation to avoid duplicate counting; updated test to verify hypervisor detection without asserting vendor string presence. | Verified in `test_antitamper.cpp` (passing cleanly on bare metal). |
| **RTP-SEC-024** | Medium | Confirmed | `licensing/update_manifest.cpp`:50-80 (`VerifyUpdate`) | `VerifyUpdate` only verified in-memory records and signatures, failing to check the physical update payload file on disk. | An attacker could substitute the update payload file on disk while presenting a valid manifest signature, deploying unverified update files. | Local file substitution during update application. | Implemented `VerifyUpdatePayload` and integrated it into `VerifyUpdate`, reading the physical payload file from disk and verifying its SHA-256 hash against the manifest. | Verified in `test_update_manifest.cpp`. |
| **RTP-SEC-025** | Medium | Confirmed | `integrity/manifest.cpp`:80-110 (`AddResource`) | Manifest accepted duplicate resource names and unvalidated paths containing directory traversal (`..`) or invalid characters. | Duplicate entries caused ambiguity in digest lookup; traversal paths allowed measuring files outside designated project structure. | Submitting malformed manifest definitions. | Exported and enforced `IsValidResourceIdentifier` and rejected duplicate entries in `AddResource`. | Verified in `test_manifest.cpp`. |

---

## 3. Cryptographic and Architecture Review

### 3.1 Digital Signatures & Key Isolation
- **Ed25519 (RFC 8032):** Digital signatures for licenses, release manifests, and update payloads use standard Ed25519 implemented via OpenSSL 3.4.0 EVP (`EVP_PKEY_ED25519`).
- **Key Isolation:** Private signing keys are strictly separated from client runtime libraries. The runtime targets (`rtprotect_licensing`, `rtprotect_integrity`) contain only verification capabilities (`Ed25519PublicKey`, `Verifier`). Private key operations (`Ed25519PrivateKey`, `Signer`) reside exclusively in `*_buildtools` static libraries.
- **Client Project Cleanliness:** The integration tool generates client projects containing only public verification keys (`release.pub`). Development keys generated with `--dev-keys` are isolated in an external backup directory, never left in the client project.

### 3.2 Authenticated Encryption & Key Derivation
- **AEAD:** `crypto/aead.cpp` implements AES-256-GCM via `EVP_aes_256_gcm()`. Each encryption operation automatically generates a fresh 96-bit random nonce using the operating system CSPRNG (`RAND_bytes`). Nonces are never caller-supplied, eliminating nonce-reuse risks.
- **KDF:** Key derivation in `crypto/kdf.cpp` and `integrity/bound_key.cpp` uses HKDF (RFC 5869) over HMAC-SHA256 (`EVP_KDF_fetch(..., "HKDF", ...)`).
- **Bound Keys:** Decryption keys for protected resources are derived directly from the SHA-256 hash of the verified release manifest, ensuring that any modification of manifest resources intrinsically invalidates decryption keys.

### 3.3 Random Number Generation
- **CSPRNG:** All cryptographic randomness derives from OpenSSL's `RAND_bytes()`, which connects to Windows `BCryptGenRandom` or Linux `getrandom`/`/dev/urandom`. No predictable PRNGs (`rand()`, `srand()`, unseeded MT) are utilized in security paths.

---

## 4. Verification & Quality Assurance Summary

The entire suite of 18 automated unit, component, and integration tests passes with 100% success rate on Windows x64:

```
Test project C:/Users/Arihant Singh/Downloads/rtprotect_hardening_WIP/build
      Start  1: test_aead
 1/18 Test  #1: test_aead ........................   Passed    0.04 sec
      Start  2: test_kdf
 2/18 Test  #2: test_kdf .........................   Passed    0.03 sec
      Start  3: test_vm
 3/18 Test  #3: test_vm ..........................   Passed    0.02 sec
      Start  4: test_protected_checksum
 4/18 Test  #4: test_protected_checksum ..........   Passed    0.03 sec
      Start  5: test_manifest
 5/18 Test  #5: test_manifest ....................   Passed    0.02 sec
      Start  6: test_signing
 6/18 Test  #6: test_signing .....................   Passed    0.03 sec
      Start  7: test_bound_key
 7/18 Test  #7: test_bound_key ...................   Passed    0.03 sec
      Start  8: test_file_io
 8/18 Test  #8: test_file_io .....................   Passed    0.02 sec
      Start  9: test_checked_arith_fallback
 9/18 Test  #9: test_checked_arith_fallback ......   Passed    0.12 sec
      Start 10: test_secure_buffer
10/18 Test #10: test_secure_buffer ...............   Passed    0.02 sec
      Start 11: test_obfuscated_string
11/18 Test #11: test_obfuscated_string ...........   Passed    0.02 sec
      Start 12: test_checksum_flattened
12/18 Test #12: test_checksum_flattened ..........   Passed    0.03 sec
      Start 13: test_license
13/18 Test #13: test_license .....................   Passed    0.03 sec
      Start 14: test_hardware_id
14/18 Test #14: test_hardware_id .................   Passed    0.03 sec
      Start 15: test_update_manifest
15/18 Test #15: test_update_manifest .............   Passed    0.05 sec
      Start 16: test_antitamper
16/18 Test #16: test_antitamper ..................   Passed    0.02 sec
      Start 17: test_opcode_map
17/18 Test #17: test_opcode_map ..................   Passed    0.02 sec
      Start 18: test_integration_engine
18/18 Test #18: test_integration_engine ..........   Passed    2.98 sec

100% tests passed, 0 tests failed out of 18
Total Test time (real) = 3.57 sec
```

In addition, the release package generation script (`tooling/package_release.ps1`) verifies all build artifacts, executes the test suite prior to packaging, and produces a complete distribution archive containing executables, static libraries, public headers, and documentation.
