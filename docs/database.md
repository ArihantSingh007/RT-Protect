# Activation Database Architecture

## 1. Overview

The activation authority service (`rtprotect-activation-server`) persists licensing records, active machine registrations, anti-replay nonces, and administrative audit events using `ActivationDatabase` (`licensing/activation_database.h`).

The database is engineered specifically for secure software licensing:
- **Envelope Encryption:** Sensitive fields (such as VM root seeds and activation credential hashes) are encrypted at rest with AES-256-GCM using an envelope encryption key.
- **Atomic Persistence:** Write operations commit to a temporary sibling file (`.tmp`) before atomic replacement, guaranteeing database integrity against power failures or process termination.
- **In-Memory Thread Safety:** Read and write operations are synchronized using internal mutexes (`std::mutex`), ensuring safe concurrency across multithreaded HTTP request handlers.

---

## 2. Data Models

### 2.1 License Record (`LicenseRecord`)
Represents an authorized customer license:

| Field | Type | Description |
|:---|:---|:---|
| `license_id` | `std::string` | Primary key identifier for the license (e.g. `LIC-ENT-001`). |
| `product_id` | `std::string` | Bound product identifier (e.g. `com.vendor.game`). |
| `status` | `LicenseRecordStatus` | Status flag: `kActive` (0), `kRevoked` (1), or `kRefunded` (2). |
| `max_seats` | `std::uint32_t` | Maximum number of concurrent unique machine fingerprints allowed. |
| `vm_root` | `std::array<uint8_t, 32>` | 256-bit cryptographic seed root required by the client VM engine. Encrypted at rest. |
| `created_at` | `std::uint64_t` | UTC timestamp of license registration. |
| `activation_credential_hash` | `std::string` | SHA-256 digest of secret activation credential. Encrypted at rest. |

---

### 2.2 Activation Session Record (`ActivationRecord`)
Represents an active device seat reservation:

| Field | Type | Description |
|:---|:---|:---|
| `license_id` | `std::string` | Foreign key referencing the parent `LicenseRecord`. |
| `device_fingerprint` | `std::string` | 64-character machine hardware ID. |
| `first_seen` | `std::uint64_t` | UTC timestamp of initial machine registration. |
| `last_seen` | `std::uint64_t` | UTC timestamp of most recent token renewal or heartbeat. |
| `sequence_number` | `std::uint64_t` | Monotonically increasing counter for anti-replay enforcement. |

---

### 2.3 Audit Event Record (`ActivationEvent`)
Represents an immutable operational audit event:

| Field | Type | Description |
|:---|:---|:---|
| `timestamp` | `std::uint64_t` | UTC timestamp of event occurrence. |
| `type` | `ActivationEventType` | Event category: `kActivationSuccess`, `kActivationFailed`, `kSeatLimitExceeded`, `kRenewalSuccess`, `kRenewalFailed`, `kDeactivation`, `kRateLimited`, `kReplayBlocked`. |
| `license_id` | `std::string` | Target license identifier. |
| `device_fingerprint` | `std::string` | Client hardware fingerprint. |
| `ip_address` | `std::string` | Originating client IP address. |
| `details` | `std::string` | Diagnostic description or failure reason. |

---

## 3. Envelope Encryption Architecture

To protect sensitive licensing material from compromise if database files are exfiltrated from the server, `ActivationDatabase` implements envelope encryption:

1. **Envelope Key Source:** An AES-256 key is provided either:
   - Via Windows DPAPI secret vault (`--db-vault-id <id>`).
   - Via command-line argument or key file (`--db-key <hex|file>`).
2. **Encrypted Fields:**
   - `vm_root`: Encrypted with AES-256-GCM using a randomized 96-bit nonce and stored in hexadecimal format with a tag prefix (`enc:<iv_hex>:<tag_hex>:<ct_hex>`).
   - `activation_credential_hash`: Encrypted similarly under the master envelope key.
3. **Decryption at Load:** When the database loads from disk, encrypted fields are decrypted into memory. If envelope encryption is enabled and an invalid key is supplied, database initialization fails closed.

---

## 4. Concurrency Control and Seat Allocation

Seat reservations use an atomic compare-and-swap model (`SeatReservationResult`):

```cpp
struct SeatReservationResult {
  bool success = false;
  bool is_new_seat = false;
  std::uint64_t sequence_number = 1;
  std::uint64_t first_seen = 0;
  std::string error;
};
```

1. When a client requests activation, the service queries registered sessions for `license_id`.
2. If `device_fingerprint` matches an existing session, the registration is refreshed, sequence numbers advance, and `is_new_seat` returns `false`.
3. If `device_fingerprint` is novel, the total count of active sessions is compared to `max_seats`.
4. If `active_sessions < max_seats`, a new seat record is inserted atomically.
5. If `active_sessions >= max_seats`, the reservation fails with `SeatLimitExceeded` and no session is created.

---

## 5. Maintenance and Key Migration

### Provisioning a New Database Vault Key
Generate an AES-256 database key directly inside the Windows DPAPI vault:
```powershell
rtprotect-activation-server.exe --provision-db-vault "db-key-prod-01"
```

### Migrating Existing Plaintext Records
To encrypt existing legacy databases containing plaintext VM roots under a newly provisioned envelope key:
```powershell
rtprotect-activation-server.exe `
    --db activations.db `
    --db-vault-id "db-key-prod-01" `
    --migrate-db
```
The migration command decrypts legacy records, re-encrypts all sensitive fields under the vault key, atomically writes the updated database file, and terminates cleanly.
