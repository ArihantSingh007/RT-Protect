# API Reference Manual

## 1. Overview of System Interfaces

RTProtect exposes four distinct interfaces for integration, automation, and operational management:
1. **C++ Developer SDK:** In-process headers and static libraries for direct integration in C++ applications.
2. **C-ABI Runtime DLL (`rtprotect_runtime.dll`):** Foreign function interface for C, C#, Python, Rust, and Go.
3. **CLI Protection Tool (`rtprotect-tool`):** Command-line utility for CI/CD automation, licensing, and key management.
4. **Activation Server REST API:** HTTPS service endpoints for client licensing and administrative auditing.

---

## 2. C++ Developer SDK

### 2.1 Namespace `rtprotect::antitamper`

Defined in `#include <antitamper/anti_debug.h>` and `#include <antitamper/risk_policy.h>`.

#### `CheckDebuggerPresent()`
```cpp
bool CheckDebuggerPresent();
```
Performs unhookable PEB inspection (`BeingDebugged`, `NtGlobalFlag`). Returns `true` if a debugger is attached.

#### `CheckRemoteDebugger()`
```cpp
bool CheckRemoteDebugger();
```
Queries kernel process flags via `NtQueryInformationProcess` (`ProcessDebugPort`). Returns `true` if active.

#### `CheckHardwareBreakpoints()`
```cpp
bool CheckHardwareBreakpoints();
```
Inspects CPU debug registers (`DR0`–`DR3`) for the current process thread using an isolated helper thread. Returns `true` if hardware breakpoints are active.

#### `AssessEnvironmentRisk()`
```cpp
RiskAssessment AssessEnvironmentRisk();
```
Executes all dynamic inspection routines and computes a composite `RiskAssessment` object containing detected flags and a normalized integer risk score (0–100).

#### `EnforceRiskPolicy(RiskAction action, const RiskAssessment& assessment)`
```cpp
bool EnforceRiskPolicy(RiskAction action, const RiskAssessment& assessment);
```
Enforces a policy based on the risk score:
- `RiskAction::kReportOnly`: Always returns `true`.
- `RiskAction::kRestrict`: Returns `false` if risk score >= 50.
- `RiskAction::kTerminate`: Terminates process immediately (`std::exit(1)`) if risk score >= 80.

---

### 2.2 Namespace `rtprotect::licensing`

Defined in `#include <licensing/hardware_id.h>` and `#include <licensing/license.h>`.

#### `GetLocalHardwareId()`
```cpp
std::string GetLocalHardwareId();
```
Computes and returns a 64-character hexadecimal composite machine fingerprint derived from CPU, motherboard, and disk parameters.

#### `VerifyHardwareMatch(const std::string& recorded_hwid, const std::string& current_hwid, double tolerance)`
```cpp
bool VerifyHardwareMatch(const std::string& recorded_hwid, const std::string& current_hwid, double tolerance = 0.75);
```
Calculates weighted Hamming similarity between two fingerprints. Returns `true` if similarity exceeds the tolerance threshold.

#### `VerifyLicenseBytes(const uint8_t* data, size_t len, const Ed25519PublicKey& pubkey, const LicenseVerificationContext& ctx, License* out_license)`
```cpp
LicenseStatus VerifyLicenseBytes(
    const std::uint8_t* data,
    std::size_t len,
    const integrity::Ed25519PublicKey& pubkey,
    const LicenseVerificationContext& ctx,
    License* out_license = nullptr);
```
Parses, verifies digital signature, validates product ID, and checks hardware binding for serialized license bytes. Returns `LicenseStatus::kValid` on success.

---

### 2.3 Namespace `rtprotect_client` (Generated Runtime Glue)

Defined in `#include "rtprotect_config.h"`.

#### `VerifyClientIntegrityAndLicense(const char* activation_credential = nullptr)`
```cpp
bool VerifyClientIntegrityAndLicense(const char* activation_credential = nullptr);
```
Authorizes execution by verifying:
1. Environment risk against active policy.
2. Digital signature and hardware binding of `client.license`.
3. Digital signature and anti-rollback sequence of `release.manifest`.
4. Windows DPAPI cached activation token or online activation server.
5. Executable binary SHA-256 digest against the release manifest.

Returns `true` if and only if all five verification stages succeed.

#### `HasCapability(std::uint64_t cap)`
```cpp
bool HasCapability(std::uint64_t cap);
```
Returns `true` if the verified client license possesses the specified capability bitmask.

---

## 3. C-ABI Runtime Library (`rtprotect_runtime.dll`)

Header: `#include "runtime/c_api.h"`. All exported functions use `cdecl` calling convention and C linkage.

```c
#ifdef __cplusplus
extern "C" {
#endif

// Returns local machine 64-character hardware fingerprint into buffer (min 65 bytes).
// Returns length on success, or -1 on error.
RTPROTECT_API int rtprotect_get_hardware_id(char* buffer, int buffer_len);

// Assesses host environment for debuggers and dumpers.
// Returns normalized risk score between 0.0 (clean) and 1.0 (compromised).
RTPROTECT_API double rtprotect_assess_environment_risk(void);

// Verifies release.manifest and adjacent release.sig against a 32-byte Ed25519 public key.
// Returns 1 if valid, 0 if invalid or missing.
RTPROTECT_API int rtprotect_verify_manifest(const char* manifest_path, const uint8_t* pub_key);

// Validates machine-bound client.license against vendor public key and expected product ID.
// Returns 1 if valid, 0 if invalid, expired, or hardware mismatch.
RTPROTECT_API int rtprotect_verify_license(const char* license_path, const uint8_t* pub_key, const char* expected_product_id);

#ifdef __cplusplus
}
#endif
```

---

## 4. CLI Tool Reference (`rtprotect-tool`)

### `integrate`
```text
rtprotect-tool integrate <project-path> [options]
```
Instruments a CMake or C++ project:
- `--profile <dev|balanced|maximum>`: Security hardening profile (default: `balanced`).
- `--product <id>`: Canonical product identifier (e.g. `com.vendor.game`).
- `--version <ver>`: Release version string (default: `1.0.0`).
- `--dry-run`: Previews AST and modification plan without writing files.
- `--dev-keys`: Uses temporary development test keys stored outside the project.
- `--manifest-pubkey <file>`: External Ed25519 public key for manifest verification.
- `--license-pubkey <file>`: External Ed25519 public key for license verification.
- `--sign-manifest-key <file>`: Private key for signing the release manifest.
- `--backup-dir <dir>`: Custom backup directory.
- `--report <json-file>`: Generates a JSON execution report.

### `rollback`
```text
rtprotect-tool rollback <project-path> <backup-dir>
```
Restores an instrumented project to its pre-integration state using a timestamped backup directory.

### `license-generate`
```text
rtprotect-tool license-generate [options]
```
Generates an Ed25519-signed node-locked license:
- `--priv-key <file>`: Vendor Ed25519 private key (required).
- `--out <file>`: Output license file path (required).
- `--product <id>`: Target product ID (required).
- `--hwid <id>`: Node-locked hardware fingerprint (default: local machine).
- `--capabilities <flags>`: Capability flags or bitmask (default: `core,commercial`).
- `--expires-in-days <n>`: Expiration duration in days (default: `0` perpetual).

### `validate-build`
```text
rtprotect-tool validate-build <project-dir> <pub-key> <manifest> <sig>
```
Verifies the cryptographic integrity of compiled target binaries against a signed manifest.

---

## 5. Activation Server HTTP REST API

The activation server communicates over HTTP/1.1 or TLS (HTTPS). All requests and responses use `application/json`.

### 5.1 `POST /activate`
Requests an online hardware-bound activation token.

#### Request Body
```json
{
  "license_key": "LIC-ENT-001",
  "device_fingerprint": "a1b2c3d4e5f6...",
  "product_id": "com.vendor.game",
  "client_version": "1.0.0",
  "client_timestamp": 1729965600,
  "client_nonce": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "activation_credential": "optional_activation_secret"
}
```

#### Successful Response (`200 OK`)
```json
{
  "status": "success",
  "server_nonce": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "encrypted_token_hex": "48656c6c6f...",
  "countermeasure_config_hex": "optional_signed_policy_hex"
}
```

#### Error Response (`200 OK` with Error Status or `429 Too Many Requests`)
```json
{
  "status": "seat_limit_exceeded",
  "error_message": "All allocated seats for this license are currently registered."
}
```

---

### 5.2 `POST /renew`
Renews an existing activation token.

#### Request Body
```json
{
  "token_hex": "48656c6c6f...",
  "device_fingerprint": "a1b2c3d4e5f6...",
  "client_nonce": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

---

### 5.3 `POST /deactivate`
Releases an active machine seat, freeing capacity for activation on another device.

#### Request Body
```json
{
  "token_hex": "48656c6c6f...",
  "device_fingerprint": "a1b2c3d4e5f6..."
}
```

#### Successful Response (`200 OK`)
```json
{
  "success": true
}
```

---

### 5.4 `GET /health`
Returns service availability status. Does not require authentication.

#### Response (`200 OK`)
```json
{
  "status": "ok"
}
```

---

### 5.5 `GET /events`
Retrieves recent audit event telemetry. Requires administrative authentication via `X-Admin-Key` header or `Authorization: Bearer <admin-token>`.

#### Response (`200 OK`)
```json
{
  "events": [
    {
      "timestamp": 1729965600,
      "type": "activation_success",
      "license_id": "LIC-ENT-001",
      "device_fingerprint": "a1b2c3d4...",
      "ip": "192.168.1.100",
      "details": "Seat allocated (1/5)"
    }
  ]
}
```
If the token is missing or invalid, the server responds with `401 Unauthorized`.
