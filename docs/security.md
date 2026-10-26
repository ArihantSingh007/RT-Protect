# Security Architecture and Threat Model

## 1. Threat Model and Assumptions

### 1.1 In-Scope Adversary Model
The RTProtect security architecture assumes an adversary with complete local administrative access to the client execution environment (Windows Ring 3). The adversary possesses:
- Interactive native debuggers (x64dbg, WinDbg, Visual Studio Debugger).
- Disassemblers and static decompilers (IDA Pro, Ghidra, Binary Ninja).
- Dynamic binary instrumentation frameworks (Frida, Cheat Engine, MinHook).
- Memory dumping and process inspection utilities.
- Local system clock manipulation capabilities.

### 1.2 Out-of-Scope Capabilities
- **Kernel-Mode Exploitation (Ring 0):** Malicious kernel drivers with arbitrary physical memory read/write primitives reside outside user-mode defenses.
- **Hardware-Level Virtualization (Ring -1):** Custom hypervisors (e.g. Hyper-V root partitions or bare-metal custom hypervisors) with transparent EPT/SLAT memory page hooking.

---

## 2. Cryptographic Foundations

All cryptographic operations wrap verified OpenSSL 3.4.0 primitives. RTProtect strictly implements established, misuse-resistant standards:

| Primitive | Standard | Usage | Implementation |
|:---|:---|:---|:---|
| **Asymmetric Signatures** | Ed25519 (RFC 8032) | Signing release manifests, licenses, activation tokens, and countermeasure policies. | OpenSSL `EVP_PKEY_ED25519` |
| **Authenticated Encryption** | AES-256-GCM | Encrypting VM bytecode blobs, stored credentials, and network payloads. | OpenSSL `EVP_aes_256_gcm` |
| **Key Derivation** | HKDF-SHA256 (RFC 5869) | Deriving context-specific keys from master secrets. | OpenSSL `EVP_KDF_HKDF` |
| **Integrity Hashing** | SHA-256 (FIPS 180-4) | Resource manifest hashing and binary integrity verification. | OpenSSL `EVP_sha256` |
| **Secure Memory** | Memory Zeroization | Wiping cryptographic keys and plaintext buffers upon deallocation. | `SecureBuffer` (`OPENSSL_cleanse`) |

### Nonce Generation
Nonces are never supplied by callers. AES-256-GCM authenticated encryption always generates fresh 96-bit (12-byte) nonces internally via `RAND_bytes()`, eliminating nonce reuse vulnerabilities under fixed keys.

---

## 3. Defense-in-Depth Mechanisms

### 3.1 Pre-Main Static Initialization Hook
To eliminate the vulnerability where developers forget to call protection APIs in `main()`, `rtprotect-tool integrate` injects pre-main execution hooks:
- **MSVC:** Injected into CRT dynamic initializer section `.CRT$XCU` using an `extern "C"` retained symbol (`#pragma comment(linker, "/include:...")`) and C++ static initialization fallback.
- **GCC / MinGW / Clang:** Injected via high-priority constructor attributes (`__attribute__((constructor(101)))`).

The hook evaluates signature validity, manifest digests, hardware licensing, and anti-tamper risk. Any failure terminates execution (`std::exit(1)`) before application `main()` is entered.

### 3.2 Tamper-Poisoned Key Derivation
To prevent attackers from bypassing protection by patching conditional jumps (`jz` -> `jnz`), RTProtect avoids boolean gates for critical execution paths.

In `DeriveTamperBoundKey()`, the detected environment risk assessment is incorporated as entropy into HKDF-SHA256:
```cpp
// If tampering is detected, the risk assessment is altered, poisoning the derived key
auto key = rtprotect::integrity::DeriveTamperBoundKey(master_key, salt, risk_assessment);
```
If an attacker modifies the binary or runs a debugger, the derived AES-256 key becomes mathematically corrupted. Subsequent decryption of bytecode or data buffers fails cryptographically.

### 3.3 Anti-Debugging & PEB Inspection
Standard Win32 debugging checks (`IsDebuggerPresent`) are hookable via simple inline trampolines. RTProtect reads the Process Environment Block directly:
```cpp
#if defined(_WIN64)
  auto* peb = reinterpret_cast<const std::uint8_t*>(__readgsqword(0x60));
  bool being_debugged = peb[2] != 0;
  std::uint32_t nt_global_flag = *reinterpret_cast<const std::uint32_t*>(peb + 0xBC);
#endif
```
If `being_debugged` or `nt_global_flag & 0x70` (`FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS`) are asserted, risk scores escalate.

### 3.4 Hardware Breakpoint Watchdog
The watchdog checks CPU debug registers (`DR0`–`DR3`). A dedicated helper thread suspends the target thread temporarily, calls `::GetThreadContext` with a 16-byte aligned buffer (`alignas(16) CONTEXT`), inspects the registers, resumes the target thread, and alerts the risk policy if any debug register contains a non-zero address.

### 3.5 Anti-Clock-Rollback Protection
To prevent users from extending expired evaluation licenses by modifying their local system clocks, `TrustedTime` records the latest verified timestamp in an encrypted state file. If `current_system_time < last_recorded_time - grace_period_seconds`, time tampering is flagged and license authorization is denied.

### 3.6 Dynamic Countermeasure Channel
The activation server can distribute signed `CountermeasureConfig` payloads during `/activate` or `/renew` requests. The client verifies the Ed25519 signature against `kCountermeasurePublicKey` before applying updated process blacklists, window title blacklists, or driver hashes. Expired policies are discarded automatically.
