# Changelog

All notable changes to the RTProtect framework are documented in this file.
This project adheres to Semantic Versioning and structured security reporting.

---

## [2.2.0-hardened] - 2026-10-20

### Security & Hardening Remediations (Audit WIP 3)

- **Finding 1 — Cryptographic Key Correspondence Verification in `SignRelease` (RTP-SEC-033):**
  - *Location:* `tooling/integration_engine.cpp:SignRelease`
  - *Fix:* Before writing `release.sig` and reporting success, `SignRelease` now reads the target project's configured `release.pub` and cryptographically verifies `integrity::VerifyManifestSignature(updated_manifest_bytes, signature, project_pubkey)`. If the private key does not match `release.pub`, the operation fails closed, no signature file is created or left on disk, and a clear error is returned. Furthermore, `SignRelease` executes full post-signing validation (`ValidateProtectedBuild`) before returning true.
  - *Verification:* `TestSignReleaseKeyMismatchRejected` in `tests/test_integration_engine.cpp`.

- **Finding 2 — Integration Lifecycle State Machine & Unsigned Release Reporting (RTP-SEC-034):**
  - *Location:* `tooling/integration_engine.h`, `tooling/integration_engine.cpp`, `tooling/main.cpp`
  - *Fix:* Replaced ambiguous binary success reporting with an explicit lifecycle state enum `IntegrationState` (`kPlanned`, `kIntegrated`, `kBuilt`, `kAwaitingSignature`, `kValidated`, `kFailed`). Integration reports in `--no-build` mode now report `kIntegrated` (unbuilt, unsigned), while `--staging` builds report `kAwaitingSignature` (staged, unsigned). The CLI clearly announces whether artifacts require offline vendor signing, and only reports "Protected release ready" when the release is in state `kValidated`.
  - *Verification:* `TestNoBuildReportsIntegratedState` in `tests/test_integration_engine.cpp`.

- **Finding 3 — Production License Signing Automation (RTP-SEC-035):**
  - *Location:* `tooling/integration_engine.cpp:ExecuteIntegration`
  - *Fix:* Integrated `--sign-license-key` with the production licensing engine on authorized vendor build infrastructure. When provided, the integration engine automatically generates an authorized production license (`Edition: Production`), signs it with the vendor's private key, verifies it against `license.pub`, and places it in the project and build outputs.
  - *Verification:* `TestProductionLicenseSigningWorkflow` in `tests/test_integration_engine.cpp`.

- **Finding 4 — Mandatory Artifact Contract & License Enforcement in `ValidateProtectedBuild` (RTP-SEC-036):**
  - *Location:* `tooling/integration_engine.cpp:ValidateProtectedBuild`
  - *Fix:* `ValidateProtectedBuild` now enforces mandatory artifact presence and validity: non-empty manifest resources, streaming SHA-256 verification of executable binaries, and cryptographic verification of `client.license` against `license.pub` (rejecting tampered, corrupt, or expired licenses).
  - *Verification:* `TestValidateProtectedBuildEnforcesLicenseIntegrity` in `tests/test_integration_engine.cpp`.

- **Exact Capability Token Parsing & Rejection (RTP-SEC-037):**
  - *Location:* `tooling/main.cpp:ParseCapabilitiesExact`
  - *Fix:* Replaced substring searching with strict tokenization, duplicate flag rejection, and rejection of unrecognized capabilities with exit code 2 and helpful usage instructions.

- **Safe Hardware Breakpoint Context Inspection on Windows (RTP-SEC-038):**
  - *Location:* `antitamper/anti_debug.cpp:CheckHardwareBreakpoints`
  - *Fix:* Replaced raw `GetThreadContext(GetCurrentThread())` with safe asynchronous thread context inspection via a monitoring thread that suspends the target thread, inspects `Dr0..Dr3` registers, and resumes it without faulting.

- **External Default Backup Directory Isolation (RTP-SEC-040):**
  - *Location:* `tooling/integration_engine.cpp:ExecuteIntegration`
  - *Fix:* Moved the default transactional backup location from within the client project to an external system temporary directory with collision-resistant random hex suffixes. Prohibited custom `--backup-dir` paths pointing inside the client project.

- **Always-Active Release-Mode Test Assertions (RTP-SEC-039):**
  - *Location:* `tests/test_integration_engine.cpp`
  - *Fix:* Introduced `RT_TEST_ASSERT` macro that aborts with full diagnostic context regardless of `NDEBUG`, ensuring all test assertions remain 100% active during Release builds and packaging scripts.

---

## [2.1.0-hardened] - 2026-10-20

### 1. Critical Security Vulnerability Remediations

- **CRITICAL 1 — Permanent Elimination of Signing Keys from Client Projects (RTP-SEC-011):**
  - *Location:* `tooling/integration_engine.cpp:221-237, 282-316`
  - *Fix:* Prohibited generation of private signing keys during production integration (`use_dev_keys = false`). Pre-provisioned vendor public keys (`--manifest-pubkey` and `--license-pubkey`) are mandatory. In development mode (`--dev-keys`), ephemeral test keys are generated strictly in an external system temporary directory (`temp_directory_path() / rtprotect_dev_keys_<ts>`), never in the client project or backup directory. Custom `--dev-keys-dir` arguments pointing within the client project or backup are rejected with a security policy error.
  - *Impact:* Guarantees that private Ed25519 signing keys are never placed in client projects, backups, or release packages.

- **CRITICAL 2 — Fail-Closed Runtime Executable Integrity (RTP-SEC-012, RTP-SEC-029):**
  - *Location:* `tooling/integration_engine.cpp:401-487`, `integrity/sha256.cpp`
  - *Fix:* Replaced fail-open checks with strict fail-closed enforcement. Executable path retrieval dynamically resizes buffers (`GetModuleFileNameA` loop on Windows, `readlink` loop on Linux) to prevent truncation. Implemented `Sha256File` streaming SHA-256 calculation in 64KB blocks, eliminating the 64 MiB memory limit and allowing binaries of arbitrary size to be verified. The running executable must match an exact mandatory resource entry in the signed `release.manifest`. If path resolution fails, hashing fails, the resource entry is missing, or digests mismatch, the check immediately terminates execution (`std::exit(1)`).
  - *Impact:* Closes all fail-open paths where modified or untracked binaries could run without verification.

- **CRITICAL 3 — Production Staging & Vendor Release Signing Workflow (RTP-SEC-013):**
  - *Location:* `tooling/integration_engine.cpp`, `tooling/main.cpp`
  - *Fix:* Introduced `--staging` mode and a dedicated `rtprotect-tool sign-release` command. Allows client projects to be instrumented with vendor public verification keys in CI/CD without exposing private keys. A separate vendor release signing system computes binary digests, signs `release.manifest` with the vendor private key, deploys `release.sig`, and validates outputs.
  - *Impact:* Enables commercial separation of untrusted client builds from trusted vendor signing infrastructure.

- **CRITICAL 4 — Decoupled Production Licensing (RTP-SEC-004):**
  - *Location:* `tooling/integration_engine.cpp`
  - *Fix:* Removed automatic production license issuance from integration runs. Integration accepts an explicit `--license-file <path>` for pre-issued vendor licenses. In `--dev-keys` mode, generated licenses are explicitly marked `Edition: Development-Test` and `developer-local-test`.
  - *Impact:* Eliminates unauthorized entitlement issuance during build integration.

- **HIGH 5 — CMake Executable Target Discovery & Selection (RTP-SEC-026):**
  - *Location:* `tooling/integration_engine.cpp:143-192`
  - *Fix:* Implemented `DiscoverCMakeExecutableTargets` parsing `add_executable` while stripping comments. When multiple targets exist, integration requires `--target <name>` to select the exact target to protect. Validates target presence before instrumentation.
  - *Impact:* Prevents misattaching runtime glue to unintended targets or corrupting multi-target projects.

- **HIGH 6 — Safe Subprocess Invocation & Input Whitelisting (RTP-SEC-027):**
  - *Location:* `tooling/integration_engine.cpp:650-657`
  - *Fix:* Replaced `std::system()` command string concatenation with `RunProcess`, executing CMake directly via Win32 `CreateProcessA` (with Microsoft-standard argument escaping) and POSIX `fork/execvp`, completely bypassing shell interpreters (`cmd.exe` / `/bin/sh`). Enforced strict identifier validation (`^[A-Za-z0-9_.-]+$`, max 128 chars) on product IDs and version strings.
  - *Impact:* Eliminates command injection and source code injection vectors.

- **HIGH 7 — Relocatable SDK Layout & Linux Packaging (RTP-SEC-015):**
  - *Location:* `tooling/package_release.sh`, `tooling/package_release.ps1`
  - *Fix:* Updated Linux release packaging script `package_release.sh` to assemble all SDK public headers (`include/`) and static libraries (`lib/`), matching `package_release.ps1`. Updated generated CMake integration code to detect whether `RTPROTECT_ROOT` is an installed SDK or source repository, linking relocatable targets.
  - *Impact:* Guarantees that packaged distributions work out-of-the-box on foreign machines without source tree dependencies.

- **HIGH 8 — Pre-Execution Transactional Journaling (RTP-SEC-016):**
  - *Location:* `tooling/integration_engine.cpp:260-285`
  - *Fix:* Integration writes `integration_journal.json` before performing any file modifications. Verifies that every backup file copy operation succeeds before continuing. Rollback uses the journal to delete created files and restore modified files.
  - *Impact:* Prevents data corruption or unrecoverable states if integration is interrupted.

- **HIGH 9 — Authoritative Runtime Metadata File Lookup (RTP-SEC-032):**
  - *Location:* `tooling/integration_engine.cpp:419-429`
  - *Fix:* Generated runtime glue restricts auxiliary file lookup (`client.license`, `release.manifest`, `release.sig`) strictly and authoritatively to the directory adjacent to the running binary. Removed fallbacks to current working directory (`.`) and parent (`..`).
  - *Impact:* Prevents CWD-based hijacking of license or manifest files.

- **HIGH 10 — Secure Temporary File Creation (RTP-SEC-028):**
  - *Location:* `tooling/file_io.h:55-80`
  - *Fix:* Replaced predictable `.tmp` filenames with cryptographically unique random suffixes (`.tmp.<random_hex>`). Uses exclusive creation flags (`CREATE_NEW` on Windows, `O_CREAT | O_EXCL` on POSIX) and verifies complete byte writes before atomic replacement (`MoveFileExA` / `rename`).
  - *Impact:* Prevents symlink redirection attacks and race collisions during file writing.

- **HIGH 11 & 12 — Runtime Capability & Entitlement Enforcement:**
  - *Location:* `tooling/integration_engine.cpp`
  - *Fix:* Exposes `rtprotect_client::GetLicenseEdition()`, `rtprotect_client::GetLicenseCapabilities()`, and `rtprotect_client::HasCapability(uint64_t)`. Enforces `kRequiredCapabilities` and monotonic sequence numbers (`kMinimumReleaseSequence`).
  - *Impact:* Allows applications to enforce feature-level licensing dynamically.

- **MEDIUM 15 — Bytecode Deserializer Null-Pointer Rejection (RTP-SEC-030):**
  - *Location:* `bytecode_vm/serialize.cpp:54`
  - *Fix:* Rejects null pointer input before any dereference.
  - *Impact:* Eliminates crashes and undefined behavior on malformed deserialization inputs.

- **MEDIUM 16 — Update Manifest Truncation Prevention (RTP-SEC-031):**
  - *Location:* `licensing/update_manifest.cpp:39-43`
  - *Fix:* Replaced silent clamping of strings and file counts with explicit bounds validation, failing safely by returning empty buffers if limits are exceeded.
  - *Impact:* Prevents signing unintended, truncated update representations.

- **MEDIUM 17 — Streaming SHA-256 for Arbitrary File Sizes (RTP-SEC-029):**
  - *Location:* `integrity/sha256.h`, `integrity/sha256.cpp`
  - *Fix:* Implemented `Sha256File` reading files in 64KB blocks, eliminating the 64 MiB limit in `ReadFile`.
  - *Impact:* Enables integrity verification of arbitrarily large game and enterprise executables without memory exhaustion.

- **MEDIUM 19 — Anti-Tamper Deduplication on POSIX:**
  - *Location:* `antitamper/anti_debug.cpp`, `antitamper/risk_policy.cpp`
  - *Fix:* Corrected debugger detection on Linux so `CheckRemoteDebugger()` does not duplicate `CheckDebuggerPresent()`, preventing improper corroboration bumps.
  - *Impact:* Eliminates false-positive risk elevations on Linux systems.

---

### 2. Verification & Automated Test Status

- **18 / 18 Automated Test Suites Passing (100% Pass Rate):**
  - `test_aead`, `test_kdf`, `test_vm`, `test_protected_checksum`, `test_manifest`, `test_signing`, `test_bound_key`, `test_file_io`, `test_checked_arith_fallback`, `test_secure_buffer`, `test_obfuscated_string`, `test_checksum_flattened`, `test_license`, `test_hardware_id`, `test_update_manifest`, `test_antitamper`, `test_opcode_map`, `test_integration_engine`.
- **Sample Client Application End-to-End Test:**
  - Integrated, built, and executed `examples/sample_client_app`.
  - Verified valid authorization and execution.
  - Verified pre-`main()` static initialization constructor termination (`exit code 1`) on altered manifest.
  - Verified clean, byte-for-byte rollback.
- **Packaged Standalone Distribution:**
  - Generated and verified `dist/rtprotect-20261020-windows-x64.zip` (2.51 MB) containing `bin/`, `include/`, `lib/`, and `docs/`.
