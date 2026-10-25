# Vendored OpenSSL Release & Maintenance Policy

This document defines the governance, security monitoring, reproducible Windows compilation, and upgrade procedures for the vendored OpenSSL cryptographic library in RTProtect.

---

## 1. Upstream Tracking & Branch Policy

RTProtect vendors pre-built OpenSSL binaries and headers under `third_party/openssl/` to ensure a deterministic, reproducible build environment for client applications across Windows development environments (MSVC and MinGW-w64) without requiring external package managers (such as vcpkg or chocolatey).

### Upstream Baseline
- **Series:** OpenSSL 3.4.x
- **Active Version:** OpenSSL 3.4.0 (Windows x64 Native)
- **Vendored Artifacts:**
  - Headers: `third_party/openssl/include/openssl/`
  - Import / Static Libraries: `third_party/openssl/lib/` (`libcrypto.lib`, `libssl.lib`)
  - Runtime DLLs: `third_party/openssl/bin/` (`libcrypto-3-x64.dll`, `libssl-3-x64.dll`)

### Upstream Release Lifecycle & 3.5.x LTS Transition Roadmap
Under OpenSSL's official release lifecycle policy:
- **Active Release:** OpenSSL 3.4.x (Standard Release). Initial GA October 2024; upstream End-of-Life (EOL) scheduled for October 2025 (1-year standard lifecycle).
- **Previous LTS Release:** OpenSSL 3.0.x LTS. Supported through **September 7, 2026** (5-year lifecycle from September 2021).
- **Target Long-Term Baseline:** OpenSSL 3.5.x is designated as the next official Long Term Support (LTS) series (targeted GA Q2 2025, supported for 5 years through **2030**).
- **Transition Architecture & Compatibility:**
  - RTProtect uses exclusively standard OpenSSL 3.x EVP and KDF interfaces (`EVP_PKEY_ED25519`, `EVP_aes_256_gcm`, `EVP_KDF_HKDF`, `RAND_bytes`).
  - No deprecated OpenSSL 1.1.1 or legacy internal struct accesses exist in the codebase.
  - Forward ABI and API compatibility is guaranteed across all OpenSSL 3.x minor releases.
- **Migration Protocol for OpenSSL 3.5.x LTS:**
  1. **Continuous Point Release Tracking:** Apply upstream patch updates (3.4.1+) during the active 3.4.x branch lifecycle.
  2. **Pre-GA Validation:** Monitor upstream 3.5-alpha/beta tags; perform test builds against the RTProtect cryptographic test suite in CI.
  3. **GA LTS Adoption:** Upon OpenSSL 3.5.0 GA release, trigger the reproducible build pipeline (§3) with full Control Flow Guard (`/GUARD:CF`), ASLR, and DEP hardening flags enabled.
  4. **Multi-Toolchain Regression:** Run full test suites under MSVC v143 (Release x64) and MinGW-w64 GCC 15.2.0 before promoting to production distribution.
  5. **Enterprise OpenSSL 3.0 LTS Fallback:** Enterprise integrators whose compliance baselines mandate an existing certified LTS library may build RTProtect against OpenSSL 3.0.x LTS headers and libraries without code modification.

### Core Cryptographic Primitives Used by RTProtect
- **Asymmetric Signature & Verification:** Ed25519 (`EVP_PKEY_ED25519`) for release manifests, client license tokens, and online activation tickets.
- **Symmetric Encryption & AEAD:** AES-256-GCM (`EVP_aes_256_gcm`) for license payloads and offline tickets; AES-256-CTR (`EVP_aes_256_ctr`) for binary section encryption and runtime unpacking.
- **Key Derivation:** HKDF-SHA256 (`EVP_KDF_HKDF`) for hardware-bound VM root keys and license credential derivation.
- **Cryptographic Randomness:** `RAND_bytes()` backed by the Windows OS entropy pool (`BCryptGenRandom`).
- **Transport Security:** OpenSSL TLS 1.3 server context termination in `rtprotect-activation-server`.

---

## 2. Security Advisory Monitoring & Patch SLA

All upstream OpenSSL security advisories are actively tracked against the RTProtect codebase.

### Monitored Feeds
- **Official OpenSSL Security Advisories:** [https://openssl-library.org/news/vulnerabilities/](https://openssl-library.org/news/vulnerabilities/)
- **OpenSSL Announce Mailing List:** `openssl-announce@openssl.org`
- **NIST National Vulnerability Database (NVD):** CPE `cpe:2.3:a:openssl:openssl:3.4.*`

### Severity Response SLAs
| Advisory Severity | Definition | Target Resolution Window | Action Protocol |
|:---|:---|:---|:---|
| **CRITICAL** | Remote code execution, private key disclosure, memory corruption in TLS handshakes | **< 48 Hours** | Immediate vendor bump, rebuild of SDK, hotfix release tagged, customer security notification dispatched. |
| **HIGH** | Denial-of-service against server termination, cryptographic verification bypass | **< 5 Business Days** | Vendored patch release built, full CTest regression validation, minor patch release. |
| **MODERATE / LOW** | Minor side-channel leakage, non-exploitable memory leaks | **Next Scheduled Release** | Rolled into standard quarterly maintenance release cycle. |

---

## 3. Reproducible Windows Compilation Guide

When upgrading or verifying vendored OpenSSL artifacts, builds must be conducted in a clean, reproducible environment on Windows 10/11 x64 or Windows Server 2022.

### Prerequisites
1. **Perl:** Strawberry Perl 5.38+ (added to `PATH`)
2. **Assembler:** NASM 2.16+ (added to `PATH` for optimized AVX-512 / AES-NI assembly routines)
3. **Compiler:** Visual Studio 2022 (MSVC v143, x64 Native Tools Command Prompt)

### Compilation Steps

Open the **x64 Native Tools Command Prompt for VS 2022**:

```cmd
:: 1. Download and verify official release tarball
curl -LO https://github.com/openssl/openssl/releases/download/openssl-3.4.0/openssl-3.4.0.tar.gz
curl -LO https://github.com/openssl/openssl/releases/download/openssl-3.4.0/openssl-3.4.0.tar.gz.sha256
certutil -hashfile openssl-3.4.0.tar.gz SHA256

:: 2. Extract source tree
tar -xzf openssl-3.4.0.tar.gz
cd openssl-3.4.0

:: 3. Configure for Windows x64 Native with binary hardening
perl Configure VC-WIN64A ^
    --prefix="%CD%\_build_install" ^
    --openssldir="%CD%\_build_install\ssl" ^
    shared ^
    no-unit-test ^
    no-docs ^
    no-legacy ^
    enable-fips=no ^
    CFLAGS="/GS /guard:cf /DYNAMICBASE /NXCOMPAT /W3 /O2" ^
    LDFLAGS="/GUARD:CF /DYNAMICBASE /NXCOMPAT /OPT:REF /OPT:ICF"

:: 4. Compile and link
nmake

:: 5. Execute internal OpenSSL self-tests
nmake test

:: 6. Stage artifacts
nmake install_sw
```

---

## 4. Checksum & Signature Verification

Before replacing vendored files, all upstream downloads and compiled binaries must be cryptographically verified:

1. **GPG Signature Verification:** Verify release tarballs using OpenSSL Release Team public keys.
2. **SHA256 Fingerprint Check:** Checksums are computed and recorded in release manifests.
3. **PE Binary Authenticity:** Run `dumpbin /headers third_party/openssl/bin/libcrypto-3-x64.dll` to verify:
   - Machine: `x64 (AMD64)`
   - Subsystem: `Windows CUI`
   - Characteristics: `DYNAMIC_BASE`, `NX_COMPAT`, `GUARD_CF` (Control Flow Guard enabled)

---

## 5. Upgrade Procedure Checklist

When performing an OpenSSL update:

- [ ] **Step 1:** Download upstream release and verify PGP / SHA256 checksums.
- [ ] **Step 2:** Compile x64 Release binaries using the reproducible instructions above.
- [ ] **Step 3:** Overwrite headers in `third_party/openssl/include/openssl/`.
- [ ] **Step 4:** Overwrite import libraries in `third_party/openssl/lib/` (`libcrypto.lib`, `libssl.lib`).
- [ ] **Step 5:** Overwrite runtime DLLs in `third_party/openssl/bin/` (`libcrypto-3-x64.dll`, `libssl-3-x64.dll`).
- [ ] **Step 6:** Run complete build and test suite under **MSVC 2022**:
  ```powershell
  cmake -B build-vs2022 -G "Visual Studio 17 2022" -A x64
  cmake --build build-vs2022 --config Release
  ctest --test-dir build-vs2022 -C Release --output-on-failure
  ```
- [ ] **Step 7:** Run complete build and test suite under **MinGW GCC + Ninja**:
  ```powershell
  cmake -B build -G "Ninja" -DCMAKE_BUILD_TYPE=Release
  cmake --build build
  ctest --test-dir build --output-on-failure
  ```
- [ ] **Step 8:** Execute release packaging script to ensure bundle integrity:
  ```powershell
  powershell -ExecutionPolicy Bypass -File tooling/package_release.ps1 -BuildDir build -Configuration Release
  ```
- [ ] **Step 9:** Commit changes with detailed breakdown including upstream version, CVEs resolved, and SHA256 checksums.
