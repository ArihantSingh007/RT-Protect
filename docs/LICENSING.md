# RTProtect Licensing Architecture & Cryptographic Specification

## 1. Architectural Principles & Trust Boundaries

The RTProtect licensing subsystem provides cryptographically verifiable authorization for protected software products.

### Non-Negotiable Security Rules:
1. **Asymmetric Authorization:** Digital authorization tokens (licenses) are signed exclusively with **Ed25519** asymmetric digital signatures (RFC 8032).
2. **Strict Key Segregation:**
   - **Private Signing Keys (`Ed25519PrivateKey`):** Must reside exclusively on secure vendor infrastructure, license generation servers, or build nodes. They are never shipped, compiled into, or accessible from client-side binaries.
   - **Public Verification Keys (`Ed25519PublicKey`):** Distributed with the client application (embedded into `rtprotect_config.h`). A public key allows verifying signatures without providing the mathematical capability to forge them.
3. **No Homemade Cryptography:** All signing, hashing, and verification operations utilize OpenSSL 3.0+ EVP standard algorithms (`EVP_PKEY_ED25519`, `EVP_DigestVerify`, `EVP_DigestSign`, `SHA-256`).
4. **Defense-in-Depth Validation:** Every license undergoes schema validation, cryptographic signature verification, temporal validity bounds checking, anti-clock rollback detection, product/edition matching, and hardware fingerprint similarity evaluation before granting execution authorization.

---

## 2. Canonical License Wire Specification

Every license file is serialized in a strictly ordered canonical binary wire format (`0x5254504C` magic) designed to prevent field ambiguity or re-ordering attacks.

### 2.1 Binary Wire Format Layout

```
Offset   Length      Type        Field Description
─────────────────────────────────────────────────────────────────────────────
0x00     4 bytes     uint32_t    Magic Identifier ('RTPL' = 0x5254504C)
0x04     4 bytes     uint32_t    Schema Version (currently 1)
0x08     2 bytes     uint16_t    Length of License ID (N1 <= 256)
0x0A     N1 bytes    bytes       License ID string (UTF-8, non-null-terminated)
...      2 bytes     uint16_t    Length of Product ID (N2 <= 256)
...      N2 bytes    bytes       Product ID string (e.g. "com.vendor.app")
...      2 bytes     uint16_t    Length of Edition (N3 <= 256)
...      N3 bytes    bytes       Edition string (e.g. "Enterprise")
...      2 bytes     uint16_t    Length of Customer ID (N4 <= 256)
...      N4 bytes    bytes       Customer ID / Email string
...      8 bytes     uint64_t    Capability bitmask (little-endian)
...      4 bytes     uint32_t    Feature Flag Count (F <= 64)
         [For each feature flag]:
         2 bytes     uint16_t    Feature name length (M <= 256)
         M bytes     bytes       Feature name string
...      8 bytes     uint64_t    Issued At Unix timestamp (seconds, little-endian)
...      8 bytes     uint64_t    Expires At Unix timestamp (0 = perpetual)
...      8 bytes     uint64_t    Grace Period duration (seconds, little-endian)
...      2 bytes     uint16_t    Length of Bound Hardware ID (H <= 256)
...      H bytes     bytes       Hardware ID string (composite hex)
...      2 bytes     uint16_t    Length of Metadata (P <= 4096)
...      P bytes     bytes       Vendor payload string
─────────────────────────────────────────────────────────────────────────────
[END OF PAYLOAD SIGNED BY ED25519]
...      64 bytes    bytes       Ed25519 Digital Signature (R || S)
```

### 2.2 Standard Capability Flags

| Flag Name | Value | Purpose |
|---|---|---|
| `kCapCoreExecution` | `0x00000001` | Baseline authorization to execute core runtime |
| `kCapAdvancedFeatures` | `0x00000002` | Unlocks advanced proprietary modules |
| `kCapExportData` | `0x00000004` | Unlocks reporting and data export capabilities |
| `kCapCommercialUse` | `0x00000008` | Commercial authorization (non-eval/academic) |
| `kCapTrialMode` | `0x00000010` | Evaluation/trial restriction flag |
| `kCapOfflineAllowed` | `0x00000020` | Authorizes extended offline operation |

---

## 3. Hardware Fingerprinting & Machine Binding

RTProtect generates a composite, multi-metric hardware fingerprint to prevent unauthorized sharing of license files across separate machines while accommodating legitimate component upgrades.

### 3.1 Composite Metrics

The system collects four independent hardware characteristics:
1. **CPU Characteristics (`cpu_component`):** Processor vendor string, family, model, stepping, and feature flags extracted via `__cpuid`.
2. **Storage Volume Serial (`storage_component`):** Root volume serial number extracted via `GetVolumeInformationA`.
3. **Operating System GUID (`system_component`):** Windows MachineGuid extracted from `HKLM\SOFTWARE\Microsoft\Cryptography`.
4. **Host Identity (`host_component`):** Local computer name via `GetComputerNameExA`.

### 3.2 Privacy Protection
To protect user privacy and avoid transmitting raw device serials, each individual component is immediately hashed with SHA-256 into a truncated 16-character hex string. The final hardware ID is formatted as:
```
<cpu_hex>:<storage_hex>:<system_hex>:<host_hex>-<composite_sha256_prefix>
```

### 3.3 Similarity Scoring Algorithm
Rather than performing a brittle binary equality check, RTProtect computes a weighted similarity score between $0.0$ and $1.0$:
- Exact Match: `1.0`
- Component Weights:
  - CPU: $30\%$
  - System Storage: $30\%$
  - OS Machine GUID: $25\%$
  - Host Name: $15\%$

A similarity score $\ge 0.75$ permits benign hardware changes (such as renaming the computer or attaching external drives) while blocking deployment to a different host machine.

---

## 4. Temporal Integrity & Clock Rollback Defense

### 4.1 Future-Issue Protection
A license whose `issued_at` is greater than `current_time + 300s` is rejected with `LicenseStatus::kNotYetValid` to detect forged clocks or prematurely deployed licenses.

### 4.2 Clock Rollback Detection
When the client application maintains a secure monotonic state (e.g. `ctx.last_recorded_time`), RTProtect checks:
$$\text{current\_time} + 300 < \text{last\_recorded\_time} \implies \text{kClockRollbackDetected}$$
If an attacker rolls back their OS clock to prevent license expiration, verification fails closed.

### 4.3 Offline Grace Periods
For mission-critical enterprise software, licenses can specify a `grace_period_seconds` (e.g. 7 days). If `current_time > expires_at` but within `expires_at + grace_period_seconds`, the application can emit renewal warnings while remaining operational.

### 4.4 Online/Offline Posture & Trusted Time Architecture
RTProtect operates under a hybrid online/offline model:
1. **14-Day Online Revalidation Leases:** Upon `/activate` or `/renew`, the vendor activation server issues an installation-bound `ActivationToken` containing the authorized `vm_root`, valid for 14 days (`expires_at = now + 14d`).
2. **3-Day Offline Grace Window:** If an endpoint is offline (e.g. travelling, field work, network outage), the client continues running for up to 3 days after token expiration (`grace_expires_at = expires_at + 3d`) while warning the user to reconnect.
3. **Monotonic Server Timestamp Anchoring:** When communicating with the activation authority, the client anchors its local clock state with the server's signed timestamp:
   - If local system clock is modified to be earlier than the server-anchored timestamp ($$\text{current\_time} + 300\text{s} < \text{last\_known\_server\_time}$$), clock tampering is flagged immediately (`TimeValidationResult::kClockTampered`).
   - If system wall clock jumps backwards relative to process monotonic runtime (`std::chrono::steady_clock`), tampering is detected.
4. **Windows Secure Storage Vault:** Tokens and time state are persisted using Windows DPAPI (`CryptProtectData` / `CryptUnprotectData`), cryptographically binding credentials to the Windows user account master key and login session.

---

## 5. Server-Side Key Management & CLI Workflows

### 5.1 Generating Keypairs
On an offline vendor administration workstation:
```powershell
rtprotect-tool.exe genkey-ed25519 vendor_master.priv vendor_master.pub
```
> [!IMPORTANT]
> Store `vendor_master.priv` in a hardware security module (HSM) or encrypted offline vault. Only `vendor_master.pub` is distributed with client builds.

### 5.2 Issuing Licenses
To generate an annual Enterprise license bound to a customer's machine:
```powershell
rtprotect-tool.exe license-generate `
    --priv-key vendor_master.priv `
    --out customer.license `
    --product com.vendor.cadsoftware `
    --edition Enterprise `
    --customer enterprise-buyer@acme.corp `
    --capabilities core,adv,export,commercial `
    --expires-in-days 365 `
    --hwid "ef8dbafa66929b73:8cd40bf0d002d6e7:0385cc14820d929b:40f7dcbf81beeb9f-e041923d0f0a6e0f"
```

### 5.3 Inspecting Licenses
To view decrypted, human-readable contents of any license file:
```powershell
rtprotect-tool.exe license-inspect customer.license
```

### 5.4 Verifying Licenses
To verify validity against a public key:
```powershell
rtprotect-tool.exe license-verify `
    --pub-key vendor_master.pub `
    --license customer.license `
    --product com.vendor.cadsoftware `
    --edition Enterprise
```

---

## 6. Online Activation Tickets & Revocation Subsystem

While static asymmetric licenses provide offline verification, commercial anti-piracy systems require a mechanism to cap concurrent activations across machines and instantly revoke compromised licenses or leaked tickets.

### 6.1 Ticket Architecture & Wire Specification
RTProtect implements a short-lived **Activation Ticket** subsystem:
1. **Challenge Request (`ActivationRequest`):** The client application generates a cryptographically random 32-byte challenge `nonce`, records the local `hardware_id` and client timestamp, and submits it to the vendor activation endpoint.
2. **Authority Issuance (`ActivationTicket`):** The vendor licensing authority verifies active concurrency against registered seats, validates revocation status, generates a random 32-byte `session_key`, and signs the ticket with the vendor's Ed25519 private key.
3. **Short Temporal Windows:** Tickets typically have a validity window of 24 hours to 7 days (`validity_seconds`). Once expired, the client application must re-activate online.

### 6.2 Dynamic Concurrency Caps & Instant Revocation
The vendor server (`ActivationManager`) tracks active sessions per `license_id`:
- Concurrent device activations exceeding `max_concurrency` are rejected with `ActivationStatus::kConcurrencyLimitExceeded`.
- Hardware ID renewals from the same machine refresh active tickets without consuming additional seats.
- Revoked licenses or tickets take effect immediately upon next activation or via synchronized revocation lists (`activate-revoke`).

### 6.3 Activation CLI Workflows
```powershell
# Issue an activation ticket (valid for 24 hours)
rtprotect-tool.exe activate-issue `
    --priv-key vendor_master.priv `
    --license-id "LIC-ENTERPRISE-001" `
    --hwid local `
    --validity-hours 24 `
    --out "device.ticket"

# Verify ticket against public key and local device
rtprotect-tool.exe activate-verify `
    --pub-key vendor_master.pub `
    --ticket "device.ticket" `
    --license-id "LIC-ENTERPRISE-001"

# Revoke a leaked license or compromised ticket
rtprotect-tool.exe activate-revoke `
    --db revocations.json `
    --revoke-license "LIC-ENTERPRISE-001" `
    --reason "Compromised credential reported"
```

---

## 7. Machine Fingerprinting Limitations & Virtual Machine Cloning

Hardware binding relies on OS-exposed metrics (`cpuid`, root volume serial, OS MachineGuid, hostname) and a persistent local device seed (`LOCALAPPDATA\RTProtect\device.seed` / `~/.config/rtprotect/device.seed`).

### 7.1 The VM Snapshot & Image Replication Boundary
In purely user-mode software protection, perfect protection against full VM snapshot replication is theoretically impossible without external trusted hardware (TPM / hardware dongles) or network telemetry:
- **VM Cloning:** If a virtual machine is snapshotted or cloned, the guest OS state, registry, volume serials, and filesystem files (including `device.seed`) are cloned verbatim. Both clones will generate identical hardware IDs and pass local hardware similarity checks.
- **Container Sandboxing:** Containers sharing an identical container base image and virtualized root volume will encounter probe fallbacks unless a unique persistent seed is maintained.

### 7.2 Layered Mitigations
RTProtect counters VM cloning and container replication through layered controls:
1. **Short-Lived Online Activation Tickets:** Cloned machines can run until ticket expiration (maximum 24h), but cannot renew online simultaneously when concurrency seats are capped.
2. **Non-Deterministic Probe Fallbacks:** When OS hardware queries fail (e.g. inside restrictive sandboxes), RTProtect mixes a cryptographically random device secret (`GetOrCreateDeviceSeed()`) rather than static public literals, ensuring different sandboxed machines do not collide on identical fallback hashes.
3. **Hypervisor & VM Detection:** Anti-tamper heuristics detect hypervisor environments and virtualized machine signatures, enabling risk policies to restrict high-value operations or demand online verification.

