# Changelog

All notable changes to the RTProtect framework are documented in this file.
This project adheres to Semantic Versioning and structured security reporting.

---

## [2.3.0-hardened] - 2026-10-21

### Security & Hardening Expansion (Comprehensive Audit Completion)

- **Track A.1 — Hardware Fingerprint Hardening & Fallback Collision Elimination (RTP-SEC-041):**
  - *Location:* `licensing/hardware_id.h`, `licensing/hardware_id.cpp`
  - *Remediation:* Eliminated public deterministic fallback strings ("DefaultVolume", "Windows-Fallback-System-ID", "Linux-Fallback-Machine-ID", "DefaultHostname", "Generic-CPU-Architecture") that previously allowed sandboxed/container attackers to force identical hardware IDs across disparate machines.
  - *Entropy Binding:* Implemented `GetOrCreateDeviceSeed()` generating a cryptographically secure 32-byte secret machine seed persisted in protected OS storage (`%LOCALAPPDATA%\RTProtect\device.seed` / `~/.config/rtprotect/device.seed`). Probing fallbacks now derive unique non-deterministic fallback entropy via `GenerateProbeFallbackEntropy()`.
  - *Configurable Weights & Degraded Tracking:* Added `HardwareSimilarityWeights` (allowing custom CPU, storage, system GUID, and hostname weightings) and probe status tracking in `HardwareFingerprint` (`cpu_probed_successfully`, etc.).
  - *Documentation:* Added comprehensive analysis of VM cloning and snapshot replication boundaries in `docs/LICENSING.md` §7.

- **Track A.2 — Online Activation Ticket & Revocation Subsystem (RTP-SEC-042):**
  - *Location:* `licensing/activation.h`, `licensing/activation.cpp`, `licensing/activation_server.h`, `licensing/activation_server.cpp`
  - *Remediation:* Implemented a complete Denuvo-class online ticket subsystem enabling dynamic seat concurrency caps and instant server-side revocation.
  - *Cryptographic Protocol:* Client generates `ActivationRequest` with a cryptographically random challenge nonce and hardware fingerprint. Vendor activation authority (`ActivationManager`) verifies revocation status and concurrency caps, generates a 32-byte session key, and issues a short-lived, Ed25519-signed `ActivationTicket`.
  - *CLI Commands:* Added `rtprotect-tool activate-issue`, `activate-verify`, and `activate-revoke` to `tooling/main.cpp`.
  - *Verification:* `test_activation.cpp` with 10 unit tests covering wire round-trip, signature validation, nonce replay protection, temporal expiration, dynamic seat enforcement, and JSON revocation export/import.

- **Track B — De-Centralized Tamper Response & Cryptographic Key Poisoning (RTP-SEC-043):**
  - *Location:* `antitamper/risk_policy.h`, `antitamper/risk_policy.cpp`
  - *Remediation:* Eliminated the classic "single patchable boolean gate" vulnerability where `EnforceRiskPolicy()` relied on a centralized `std::exit(1)` easily NOPed by reverse engineers.
  - *Tamper-Poisoned Key Derivation:* Implemented `DeriveRiskSalt()` and `DeriveTamperBoundKey(master, assessment, context)`. In a clean environment, HKDF derives the authentic key. If any debugging, hardware breakpoints (`DR0-DR3`), timing anomalies, or memory modifications are present, HKDF derives a poisoned key, causing subsequent AEAD authentication to fail or bytecode execution to desynchronize silently without any central branch to patch.
  - *State Perturbation:* Implemented `DeriveTamperPerturbation()` and `ScatterTamperCheck()` for distributed state-accumulator poisoning.
  - *Documentation Alignment:* Rewrote `docs/SECURITY_FIXES.md` §4 and §5 to eliminate contradictions and accurately reflect active anti-debugging and opcode map implementations.

- **Track C — Bytecode VM Memory Opcodes, Subroutines & C-Subset Compiler (RTP-SEC-044):**
  - *Location:* `bytecode_vm/opcode.h`, `bytecode_vm/verifier.cpp`, `bytecode_vm/vm.h`, `bytecode_vm/vm.cpp`, `bytecode_vm/builder.h`, `bytecode_vm/compiler.h`, `bytecode_vm/compiler.cpp`
  - *Remediation:* Expanded the VM instruction set with memory-indexed operations (`kLoadMem8`, `kStoreMem8`, `kLoadMem64`, `kStoreMem64`) and subroutine control flow (`kCall`, `kRetSub`).
  - *Memory Context:* Added `MemoryContext` to `vm::Run()` supporting isolated heap/scratch buffer execution with boundary checking (`kMemoryAccessOutOfBounds`).
  - *C-Subset Compiler:* Implemented a recursive-descent C-subset compiler translating C functions with arithmetic, bitwise operators, local variables, memory indexing (`load8`, `store8`, `load64`, `store64`), conditionals (`if/else`), and loops (`while`) directly into verified `Program` instances.
  - *Verification:* Expanded `tests/test_vm.cpp` with comprehensive test coverage for memory load/store 8/64, call/return subroutines, while loops, branching, and arithmetic expressions.

- **Track D — Intelligent Integration Engine & Function Virtualization (RTP-SEC-045):**
  - *Location:* `tooling/integration_engine.h`, `tooling/integration_engine.cpp`
  - *Per-Build Opcode Permutation:* Build integration generates a random 32-bit seed (`kBuildOpcodeSeed`) embedded in `rtprotect_config.h`, activating `OpcodeMap::FromSeed()` for every protected binary.
  - *Automated Function Virtualization:* During project integration, candidate functions tagged with `RTPROTECT_VIRTUALIZE` are automatically compiled via `CompileCSubset`, encrypted under a tamper-bound key (`DeriveTamperBoundKey`), and wrapped in a C++ runner executing through the build's permuted VM mapping.
  - *String Obfuscation & Scattered Checks:* Added automated transformation for `OBFUSCATED_STRING` and injected scattered anti-tamper checkpoints.
  - *Execution Reporting:* Extended `IntegrationReport::ToJson()` with `virtualized_functions`, `obfuscated_string_count`, `scattered_check_count`, and `opcode_seed`.
  - *Verification:* Added `TestPerBuildOpcodeSeeding`, `TestFunctionVirtualization`, and `TestDetailedJsonReporting` in `tests/test_integration_engine.cpp`.

- **Track D.1 — Opcode Map Permutation Virtualization Synchronization (RTP-SEC-046):**
  - *Location:* `bytecode_vm/builder.h`, `bytecode_vm/compiler.cpp`, `bytecode_vm/compiler.h`, `bytecode_vm/opcode_map.h`, `tooling/integration_engine.cpp`
  - *Remediation:* Threaded `const OpcodeMap*` through `ProgramBuilder` and `CompileCSubset`. Added `RemapProgramOpcodes` to translate bytecode between arbitrary mappings. Fixed compiler control flow dead terminal jump emission when `then` branch terminates with `return`.
  - *Verification:* `test_opcode_map.cpp` (`OpcodeMap_RemapProgramOpcodes_TransformsAndExecutes`) and `test_integration_engine.cpp` (`TestFunctionVirtualizationExecutionRoundTrip`).

- **Track D.2 — Plaintext Virtualization Master Key Elimination & Dynamic Derivation (RTP-SEC-047):**
  - *Location:* `tooling/integration_engine.cpp`, `rtprotect_config.h`
  - *Remediation:* Eliminated raw 32-byte `master_key` arrays (`s_master[]`) from generated C++ source and `.rodata`. Implemented compile-time XOR sharding (`kAuthShard0..3 ^ kAuthMask0..3`) in `rtprotect_config.h` and per-function HKDF key derivation via `kManifestPublicKey` and `s_fn_salt`.
  - *Verification:* Added assertion in `test_integration_engine.cpp` ensuring `s_master` is absent from all generated client wrappers.

- **Track E.1 — Multi-Layer Unhookable Anti-Debugging & Direct PEB/Kernel Inspection (RTP-SEC-048):**
  - *Location:* `antitamper/anti_debug.h`, `antitamper/anti_debug.cpp`
  - *Remediation:* Implemented direct inline assembly inspection (`gs:0x60` / `fs:0x30`) checking `BeingDebugged` and `NtGlobalFlag` (`0x70`), bypassing Win32 user-mode hooks on `IsDebuggerPresent`. Added dynamic kernel querying via `NtQueryInformationProcess` checking `ProcessDebugPort` (7) and `ProcessDebugObjectHandle` (30).
  - *Verification:* `test_antitamper.cpp`.

- **Track E.2 — Memory Tamper & Inline Hook Detection with Background Watchdog (RTP-SEC-049):**
  - *Location:* `antitamper/anti_debug.h`, `antitamper/anti_debug.cpp`, `antitamper/risk_policy.cpp`
  - *Remediation:* Implemented `CheckMemoryTampered()` inspecting entry-point bytes of critical Win32 security APIs for software breakpoints (`0xCC` INT 3) and trampoline hooks (`0xE9`, `0xFF 0x25`). Added background hardware breakpoint watchdog (`StartHardwareBreakpointWatchdog` / `StopHardwareBreakpointWatchdog`) with process-wide thread snapshot scanning (`ScanProcessThreadsForHardwareBreakpoints`).
  - *Verification:* `test_antitamper.cpp` (`AntiTamper_MemoryTamperCheck_CleanBinary_DoesNotTrigger`, `AntiTamper_Watchdog_StartsAndStopsCleanly`, `AntiTamper_ScatterTamperCheck_CleanState_PreservesAccumulator`).

- **Track F.1 — Degraded Hardware License Enforcement (RTP-SEC-050):**
  - *Location:* `licensing/license_verifier.h`, `licensing/license_verifier.cpp`
  - *Remediation:* Added `reject_degraded_hardware` option and `kHardwareDegraded` status in `LicenseVerifier` to evaluate `HardwareFingerprint::is_degraded()` and reject licenses when operating in degraded fallback mode.
  - *Verification:* `test_license.cpp`.

- **Track F.2 — Non-Volatile Hardware Seed Concurrency Resilience (RTP-SEC-051):**
  - *Location:* `licensing/hardware_id.cpp`
  - *Remediation:* Added re-read fallback on write collisions in `GetOrCreateDeviceSeed()` to resolve concurrent initialization races. Added non-volatile hardware attribute hashing for read-only filesystem environments.
  - *Verification:* `test_hardware_id.cpp`.

- **Track D.3 — Comment/String-Aware Lexical Extraction for Source Virtualizer (RTP-SEC-052):**
  - *Location:* `tooling/integration_engine.cpp`
  - *Remediation:* Implemented a lexical scanner state machine ignoring `{` and `}` braces within single-line comments (`//`), block comments (`/* ... */`), double-quoted strings, and character literals during function boundary discovery.
  - *Verification:* `test_integration_engine.cpp` (`TestFunctionExtractionHandlesCommentsAndStrings`).

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
