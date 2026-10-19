# RTProtect Verification and Automated Testing Guide

## 1. Test Suite Architecture

The RTProtect test suite provides comprehensive automated verification of all cryptographic primitives, integrity subsystems, licensing structures, anti-tamper mechanisms, and integration workflows.

Every security feature is validated through both **positive tests** (verifying correct behavior on legitimate inputs) and **negative/adversarial tests** (verifying safe fail-closed termination on tampered, forged, or malicious inputs).

---

## 2. Comprehensive Test Matrix

| # | Test Target | Source File | Subsystem Under Test | Primary Security Assertions & Adversarial Vectors |
|---|---|---|---|---|
| 1 | `test_aead` | `tests/test_aead.cpp` | AES-256-GCM AEAD | Confirms authenticated encryption; rejects single-bit ciphertext and auth-tag tampering; rejects truncated payloads. |
| 2 | `test_kdf` | `tests/test_kdf.cpp` | HKDF-SHA256 | Validates key derivation from high-entropy salt/info; verifies non-colliding subkeys; enforces minimum entropy bounds. |
| 3 | `test_vm` | `tests/test_vm.cpp` | Bytecode VM Interpreter | Verifies memory protection, opcode execution, and arithmetic bounds; prevents out-of-bounds memory accesses on terminal opcodes (`Opcode::kRet`). |
| 4 | `test_protected_checksum` | `tests/test_protected_checksum.cpp` | E2E Protected Pipeline | End-to-end integration test validating VM bytecode execution protected by signed manifest integrity and AEAD resource encryption. |
| 5 | `test_manifest` | `tests/test_manifest.cpp` | Manifest Parser | Validates canonical binary serialization and deserialization of resource manifests; rejects malformed, truncated, or cyclic manifest data. |
| 6 | `test_signing` | `tests/test_signing.cpp` | Ed25519 Signatures | Positive signature verification; rejects single-byte signature forgery, modified manifest payloads, and public key mismatch. |
| 7 | `test_bound_key` | `tests/test_bound_key.cpp` | Machine-Bound Keys | Validates derivation of AES encryption keys bound to machine/release parameters; ensures different machines derive distinct decryption keys. |
| 8 | `test_file_io` | `tests/test_file_io.cpp` | Safe File I/O | Enforces 64MB bounded read limit (`RTP-SEC-008`); tests atomic replacement writes (`RTP-SEC-009`); tests DACL restricted secret file creation. |
| 9 | `test_checked_arith_fallback` | `tests/test_checked_arith_fallback.cpp` | Overflow-Safe Math | Tests software fallback arithmetic for signed/unsigned addition, subtraction, and multiplication overflow detection without compiler builtins. |
| 10 | `test_secure_buffer` | `tests/test_secure_buffer.cpp` | Secure Memory Scrubbing | Verifies zeroization upon destruction (`OPENSSL_cleanse`); prevents compiler dead-store elimination; enforces non-copyable semantics. |
| 11 | `test_obfuscated_string` | `tests/test_obfuscated_string.cpp` | Compile-Time XOR Strings | Confirms strings are encrypted at compile time in `.rdata`; verifies runtime ephemeral decryption and in-place stack wiping. |
| 12 | `test_checksum_flattened` | `tests/test_checksum_flattened.cpp` | Control Flow Flattening | Verifies correctness of switch-dispatch state machine transformation against reference implementation. |
| 13 | `test_license` | `tests/test_license.cpp` | Asymmetric Licensing | Validates canonical binary and text wire serialization; verifies Ed25519 signature checks; tests clock rollback detection; tests expired license rejection. |
| 14 | `test_hardware_id` | `tests/test_hardware_id.cpp` | Hardware Fingerprinting | Multi-metric collection (CPU, storage serial, machine GUID, hostname); tests SHA-256 privacy hashing; tests similarity scoring tolerance. |
| 15 | `test_update_manifest` | `tests/test_update_manifest.cpp` | Secure Update Manifest | Enforces strictly monotonic sequence numbers; rejects downgrade / replay attacks; verifies digital signature over update payloads. |
| 16 | `test_antitamper` | `tests/test_antitamper.cpp` | Anti-Debug & Environment | Tests debugger presence checks, hardware breakpoint register inspection (DR0-DR3), hypervisor detection, and configurable risk policy enforcement. |
| 17 | `test_opcode_map` | `tests/test_opcode_map.cpp` | Opcode Map Permutation | Validates bijection permutation table generation from random seeds; ensures identical seeds produce identical bijective mappings; tests encode/decode fidelity. |
| 18 | `test_integration_engine` | `tests/test_integration_engine.cpp` | Integration Engine | Tests project detection; dry-run preview; transactional integration; backup restoration; manifest build validation; path traversal attack rejection. |
| 19* | `test_executable_memory` | `tests/test_executable_memory.cpp` | Executable Memory (Exp.) | Validates page allocation with `PAGE_EXECUTE_READWRITE` and `PAGE_EXECUTE_READ`; tests Windows Vectored Exception Handling crash protection. |
| 20* | `test_reconstructed_function` | `tests/test_reconstructed_function.cpp` | Runtime Reconstruction (Exp.) | Tests encrypted machine-code payload decryption into executable pages, dynamic execution, and zeroization upon completion. |

*\* Note: Tests 19 and 20 are included when `-DRTPROTECT_ENABLE_EXPERIMENTAL_RUNTIME_RECONSTRUCTION=ON` is enabled.*

---

## 3. Running Automated Tests

### 3.1 Executing All Tests
From the repository root:
```powershell
$openssl_dir = "$((Get-Item .).FullName)\third_party\openssl"
$env:PATH = "C:\mingw64\bin;$openssl_dir\bin;$env:PATH"

ctest --test-dir build --output-on-failure
```

### 3.2 Running an Individual Test Target
Any test executable can be run directly from the command line:
```powershell
.\build\tests\test_license.exe
.\build\tests\test_integration_engine.exe
.\build\tests\test_antitamper.exe
```

---

## 4. Adversarial Test Vector Details

### 4.1 Digital Signature Forgery & Payload Tampering
- Tested in `test_signing.cpp`, `test_license.cpp`, and `test_integration_engine.cpp`.
- Verifies that flipping any single bit in an Ed25519 signature (64 bytes) or within the signed manifest payload immediately triggers `IntegrityError::kSignatureInvalid` or `LicenseStatus::kInvalidSignature`.
- Replaces standard signatures with all-zero arrays, inverted bytes, and mismatched public keys to ensure `fail-closed` behavior.

### 4.2 Anti-Downgrade & Monotonic Sequence Attacks
- Tested in `test_update_manifest.cpp`.
- Verifies that attempting to apply an update manifest with sequence $N \le N_{\text{current}}$ is rejected with `UpdateManifestStatus::kDowngradeDetected`.

### 4.3 Clock Rollback Attacks
- Tested in `test_license.cpp`.
- Emulates an attacker setting system time back by several days to bypass an expiration date.
- Checks that when `ctx.current_time + 300 < ctx.last_recorded_time`, the verifier returns `LicenseStatus::kClockRollbackDetected`.

### 4.4 Hardware ID Mismatch Attacks
- Tested in `test_hardware_id.cpp` and `test_integration_engine.cpp`.
- Replaces registered hardware fingerprint with an unauthorized machine ID.
- Confirms that similarity score falls below `0.75` threshold and authorization is refused.

### 4.5 Path Traversal Directory Escapes
- Tested in `test_integration_engine.cpp`.
- Verifies that malicious backup archives or target file paths containing relative traversal sequences (`../`) are detected and rejected by `ExecuteRollback` and `IsPathWithin`.

---

## 5. Dynamic Analysis & Sanitizers

For memory error and undefined behavior analysis, build with LLVM/Clang or GCC AddressSanitizer (ASan):
```powershell
cmake -B build_asan -S . -G Ninja `
    -DOPENSSL_ROOT_DIR="$openssl_dir" `
    -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"
cmake --build build_asan
ctest --test-dir build_asan --output-on-failure
```
This detects out-of-bounds reads/writes, use-after-free, double-free, and signed integer overflow at runtime.
