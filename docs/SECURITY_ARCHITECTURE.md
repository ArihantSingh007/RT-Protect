# RTProtect Security Architecture & Component Specification

**Document Version:** 2.0.0  
**Specification Level:** Production Architecture  
**Status:** Baseline Established & Hardening Specification  

---

## 1. Architectural Overview & Component Boundaries

RTProtect organizes software protection into modular subsystems with distinct trust profiles, clear interfaces, and explicit isolation between build-time capabilities (signing, encryption, transformation) and client-time capabilities (verification, bound decryption, VM execution).

```
+-----------------------------------------------------------------------------------+
|                           BUILD & RELEASE ENVIRONMENT                              |
|                                                                                   |
|  +-----------------------------+       +---------------------------------------+  |
|  |     Integration Engine      | ----> |  Signer & Keys (rtprotect_buildtools) |  |
|  | (Project inspection, build, |       | (Ed25519 Private Key, Master Secrets) |  |
|  |   transforms, rollback)     |       +---------------------------------------+  |
|  +-----------------------------+                           |                      |
|                 |                                          |                      |
|                 v                                          v                      |
|         Generated Code, Manifests & Signed Licenses (Artifacts)                   |
+-----------------------------------------------------------------------------------+
                                          |
                      Distribution Channel (Untrusted)
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                        CLIENT RUNTIME EXECUTION ENVIRONMENT                       |
|                                                                                   |
|  +--------------------------------+       +------------------------------------+  |
|  | 1. Licensing & Entitlement     | ----> | 2. Signed Manifest & Integrity     |  |
|  | (Ed25519 Verify, HWID, Expiry) |       | (VerifyManifest, CheckResource)    |  |
|  +--------------------------------+       +------------------------------------+  |
|                 |                                          |                      |
|                 +------------------+   +-------------------+                      |
|                                    v   v                                          |
|                          +-----------------------+                                |
|                          | 3. Bound Key (HKDF)   |                                |
|                          +-----------------------+                                |
|                                    |                                              |
|                                    v                                              |
|                          +-----------------------+                                |
|                          | 4. Crypto AEAD        |                                |
|                          | (AES-256-GCM Decrypt) |                                |
|                          +-----------------------+                                |
|                                    |                                              |
|                                    v                                              |
|                          +-----------------------+                                |
|                          | 5. Bytecode VM        | <--- [Permuted Opcode Table]   |
|                          | (Verifier + Run)      |                                |
|                          +-----------------------+                                |
|                                    ^                                              |
|                                    | (Continuous Monitoring)                      |
|                          +-----------------------+                                |
|                          | 6. Anti-Tamper & Risk |                                |
|                          | (Debug, VM, Signals)  |                                |
|                          +-----------------------+                                |
+-----------------------------------------------------------------------------------+
```

---

## 2. Core Components Specification

### Component 1: Core Protection Library (`crypto/`)
- **Responsibilities:** Misuse-resistant authenticated encryption (AES-256-GCM), key derivation (HKDF-HMAC-SHA256), and zeroizable secure memory (`SecureBuffer`).
- **Interfaces:**
  - `Encrypt(key, plaintext, aad)` -> `CiphertextBlob` (random 96-bit IV, ciphertext, 128-bit tag).
  - `Decrypt(key, blob, aad)` -> `SecureBuffer` (fail-closed authentication check).
  - `DeriveKey(master_key, salt, info)` -> `Aes256Key` (RFC 5869 KDF).
- **Trust Boundary:** Client and Build. Contains no persistent keys.

### Component 2: License Verification and Entitlement Module (`licensing/`)
- **Responsibilities:** Authenticates client licenses issued by the vendor. Validates digital signature, product/edition match, capability flags, validity period (issue date to expiration date), clock rollback, and hardware binding.
- **Data Model:**
  - `LicenseHeader`: Magic (`RTPL`), schema version, license ID (UUID/string), customer ID, product ID, edition.
  - `Capabilities`: 64-bit entitlement bitmask and custom feature strings.
  - `Validity`: `issued_at`, `expires_at`, `grace_period_seconds`.
  - `DeviceBinding`: Target hardware fingerprint hash.
  - `Signature`: 64-byte Ed25519 signature over canonical serialized license body.
- **Interfaces:**
  - `VerifyLicense(license, public_key, current_time, hw_fingerprint)` -> `LicenseStatus`.
  - `IsFeatureAuthorized(license, feature_bit)` -> `bool`.

### Component 3: Build-Time Integration Engine (`tooling/`)
- **Responsibilities:** Command-line executable (`rtprotect-tool` / integration CLI) that analyzes authorized client C/C++ projects, generates protection wrappers, produces build manifests, applies transactional source/build changes with backup and rollback, and executes compilation and validation.
- **Workflow:**
  1. Detect project configuration and CMake structure.
  2. Plan source and build-system transformations.
  3. Create timestamped backup archive for clean `--rollback`.
  4. Generate protection code, compile-time constants, and build rules.
  5. Build project with toolchain.
  6. Sign release manifest with developer private key.
  7. Run verification smoke tests against output binary.
- **Interfaces:**
  - CLI commands: `integrate`, `rollback`, `validate-build`, `license-generate`, `license-verify`, `fingerprint`.

### Component 4: Platform-Specific Runtime Protection Layer (`runtime/`)
- **Responsibilities:** Runtime risk signals and environment assessment.
  - Anti-Debugging: `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, DR0-DR3 hardware breakpoint detection, high-resolution performance counter timing variance.
  - Virtualization & Environment: CPUID hypervisor bit check, hypervisor vendor signature check.
  - Code Section Integrity: In-memory hash checking of critical executable text sections.
- **Configurable Policy:**
  - `RiskPolicy::ReportOnly`: Logs diagnostic event or telemetry beacon.
  - `RiskPolicy::Restrict`: Disables non-essential features or revokes license tokens.
  - `RiskPolicy::Terminate`: Exits process cleanly without crashing or corrupting user data.

### Component 5: Protected-Build Manifest & Integrity Verification (`integrity/`)
- **Responsibilities:** SHA-256 release hashing, signed manifest serialization/deserialization, Ed25519 signature verification, and bound key derivation.
- **Interfaces:**
  - `DeriveBoundResourceKey(master_key, committed_sha256)` -> `Aes256Key`.
  - `VerifyManifestSignature(manifest_bytes, signature, public_key)` -> `bool`.
  - `VerifyResourceHash(entry, resource_bytes)` -> `bool`.

### Component 6: Secure Update & Version Management Subsystem (`licensing/update_manifest.h`)
- **Responsibilities:** Cryptographic verification of downloaded software updates and patches before application.
- **Guarantees:**
  - Signed metadata with Ed25519.
  - Anti-Downgrade: Monotonically increasing release sequence numbers.
  - SHA-256 integrity verification of every update payload file.
  - Atomic update application with recovery on interruption.

### Component 7: Licensing Administration & Backend Boundary
- **Responsibilities:** Clean API boundaries for vendor backends (license issuance, activation, revocation).
- **Separation:** The vendor backend generates licenses with private Ed25519 signing keys. The client application only performs verification using public keys.

### Component 8: Configuration, Diagnostics, Testing, and Reporting System
- **Responsibilities:** Structured JSON reports (`--report`), verbose diagnostics, micro-test framework, fuzz harnesses, and statistical benchmarking (`bench/`).

---

## 3. Profiles and Protection Levels

| Feature / Defense | `development` | `balanced` (Default) | `maximum` |
|---|---|---|---|
| **License Verification** | Permissive / dev keys allowed | Strict Ed25519 validation | Strict + HWID binding + clock validation |
| **Integrity Enforcement** | Warning on mismatch | Bound Key derivation (HKDF) | Bound Key + runtime section hashing |
| **Bytecode Virtualization** | Standard bytecode mapping | Permuted opcodes | Permuted opcodes + instruction budget |
| **Obfuscation** | Disabled (debug symbols on) | Compile-time string obfuscation | Control-flow flattening + string protection |
| **Anti-Debugging Signals** | Disabled (profilers allowed) | ReportOnly (telemetry logging) | Restrict / Terminate on active debugger |
| **Virtualization Checks** | Ignored (VM friendly) | Informational | Restrict if hypervisor detected |
| **Compiler Hardening** | Standard debug flags | ASLR, DEP, `-fstack-protector` | ASLR, DEP, CFG `/guard:cf`, symbol strip |
