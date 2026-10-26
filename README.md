<p align="center">
  <img src="docs/assets/logo.png" alt="RTProtect Logo" width="180">
</p>

# RTProtect

Enterprise C++ Runtime Binary Protection, Anti-Tamper, and Cryptographic Licensing Framework for Windows x64.

[![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D6.svg)](https://microsoft.com)
[![Standard](https://img.shields.io/badge/standard-C%2B%2B20-00599C.svg)](https://en.cppreference.com/w/cpp/20)
[![Compiler](https://img.shields.io/badge/compilers-MSVC%202022%20%7C%20MinGW--w64%20GCC-green.svg)](https://visualstudio.microsoft.com/)
[![Cryptography](https://img.shields.io/badge/crypto-OpenSSL%20(AES--256--GCM%20%2F%20Ed25519)-7A3E9D.svg)](https://www.openssl.org/)
[![Tests](https://img.shields.io/badge/tests-26%2F26%20passed%20(100%25)-brightgreen.svg)]()
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

---

## 1. Project Overview

RTProtect is an engineering framework providing compile-time source transformation, bytecode virtualization, active anti-tamper defenses, and cryptographic license validation for native applications running on Windows x64. It is designed to harden proprietary software, game clients, and enterprise tools against static decompilation, dynamic debugger instrumentation, in-memory dumping, and unlicensed execution.

The framework enforces a **fail-closed, defense-in-depth architecture**:
- **Offline Asymmetric Authority:** Authorization is verified against vendor-signed Ed25519 cryptographic structures. Client binaries embed only public verification keys; private signing keys are isolated to offline signing environments or secure activation servers.
- **Fail-Closed Pre-Main Initialization:** CRT static constructor hooks (`.CRT$XCU` on MSVC, `__attribute__((constructor(101)))` on GCC/Clang) enforce signature, manifest, license, and environmental integrity before `main()` executes, terminating invalid binaries immediately.
- **Tamper-Poisoned Key Derivation:** Direct boolean branching (`if (debugger_present) exit()`) is supplemented with HKDF-HMAC-SHA256 key poisoning (`DeriveTamperBoundKey`). Detected instrumentation poisons runtime cryptographic master keys, causing subsequent operations to fail cryptographically.
- **Automated AST-Driven Integration:** Clang AST analysis (`-Xclang -ast-dump=json`) discovers, verifies, and transforms marked functions into virtualized bytecode with automated backup, validation, and rollback capability.
- **Windows Subsystem Specialization:** Uses Windows Data Protection API (DPAPI) for credential isolation, Thread Debug Registers (`DR0`–`DR3`) for hardware breakpoint detection, Process Environment Block (PEB) inspection, and dynamic PE export resolution.

---

## 2. Core Components

```
+-----------------------------------------------------------------------------------+
|                                Client Application                                 |
+-----------------------------------------------------------------------------------+
       |                                       |                               |
       v                                       v                               v
+-------------------------+         +-------------------------+     +--------------------+
|  Pre-Main Startup Hook  |         |   Bytecode VM Engine    |     |   C / C++ SDK      |
|  - Digital Signature    |         |  - Stack / Threaded VM  |     |  - Programmatic    |
|  - Release Manifest     |         |  - Randomized Opcodes   |     |    Integrity API   |
|  - Machine License      |         |  - Linear Bytecode      |     |  - C-ABI Runtime   |
|  - Environment Risk     |         |    Verifier             |     |    DLL Export      |
+-------------------------+         +-------------------------+     +--------------------+
       |                                       |                               |
       +-------------------+-------------------+-------------------------------+
                           |
                           v
+-----------------------------------------------------------------------------------+
|                              Protection Subsystems                                |
+-------------------------+-------------------------+-------------------------------+
|  antitamper / Integrity |  licensing / Authority  |  crypto / Memory Security     |
|  - PEB Flag Probing     |  - Hardware ID (CPU,    |  - AES-256-GCM Authenticated  |
|  - DR0-DR3 HW BP Watch  |    Motherboard, Disk)   |    Encryption                 |
|  - Timing Anomaly Check |  - DPAPI Secure Storage |  - HKDF-SHA256 Derivation     |
|  - Anti-Dump Stripping  |  - Replay-Protected     |  - Ed25519 Asymmetric Sign    |
|  - PE Import Hashing    |    HTTPS Activation     |  - SecureBuffer Zeroization   |
+-------------------------+-------------------------+-------------------------------+
```

### 2.1 Bytecode Virtual Machine (`bytecode_vm/`)
Translates native instructions into a custom virtual instruction set. Includes both stack-based and register-threaded execution backends, dynamic execution fuel limits to prevent execution loops, randomized per-build opcode mappings, and an ahead-of-time linear bytecode verifier that validates jump offsets, instruction boundaries, and operand types before execution.

### 2.2 Anti-Tamper & Anti-Debugging Engine (`antitamper/`)
Provides multi-layered dynamic defenses against reverse-engineering tools:
- Probes PEB debug flags (`BeingDebugged`, `NtGlobalFlag`) directly without calling hookable Win32 wrappers.
- Hardware breakpoint detection inspecting processor debug registers (`DR0`–`DR3`).
- Timing anomaly detection using high-resolution performance counters (`QueryPerformanceCounter`) to detect single-stepping latency.
- Anti-dump defenses that strip PE header artifacts from memory and detect memory probing tools.
- Dynamic PE export resolution via runtime symbol hashing, avoiding static IAT entries for sensitive system APIs.

### 2.3 Licensing & Hardware Fingerprinting (`licensing/`)
Implements node-locked, machine-bound entitlement verification:
- Composite hardware fingerprint derived from CPU identity, motherboard firmware UUID, and physical storage drive serial numbers with weighted Hamming similarity matching.
- Secure storage backed by Windows DPAPI (`CryptProtectData` / `CryptUnprotectData`).
- Anti-clock-rollback engine maintaining monotonic timestamps with configurable grace periods.
- Standalone multi-threaded HTTPS activation server (`rtprotect-activation-server`) managing seat reservations, instant revocation, anti-replay nonces, rate limiting, and administrative audit logging.

### 2.4 Cryptographic Primitives (`crypto/`, `integrity/`)
Powered by OpenSSL:
- Authenticated symmetric encryption: AES-256-GCM.
- Key derivation: HKDF-SHA256.
- Digital signatures: Ed25519 (RFC 8032).
- Integrity verification: Streaming SHA-256.
- Secure memory: `SecureBuffer` with automated `SecureWipe` zeroization on deallocation.

---

## 3. Technology Stack and Prerequisites

### Build Environment
- **Operating System:** Windows 10 / 11 (x64) or Windows Server 2019+ (x64).
- **Supported Compilers:**
  - Microsoft Visual Studio 2022 (MSVC v143, Version 19.30 or newer).
  - MinGW-w64 GCC (Version 11.2 or newer, GCC 15.2 verified).
  - LLVM Clang 16+ (for libFuzzer with AddressSanitizer and UndefinedBehaviorSanitizer).
- **Build System:** CMake 3.20 or newer, Ninja 1.10+ or MSBuild.
- **Cryptography:** OpenSSL (bundled under `third_party/openssl/`).

---

## 4. Building from Source

Execute build commands from a PowerShell or Developer Command Prompt at the repository root.

### Building with MinGW-w64 and Ninja
```powershell
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR="third_party/openssl" -DRTPROTECT_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build -C Release --output-on-failure
```

### Building with Visual Studio 2022 (MSVC)
```powershell
cmake -B build-vs2022 -G "Visual Studio 17 2022" -A x64 -DOPENSSL_ROOT_DIR="${PWD}/third_party/openssl" -DRTPROTECT_BUILD_TESTS=ON
cmake --build build-vs2022 --config Release
ctest --test-dir build-vs2022 -C Release --output-on-failure
```

### Automated Test Verification Matrix
All 26 test suites execute under CTest:

```text
 1/26 test_aead ........................ Passed
 2/26 test_kdf ......................... Passed
 3/26 test_vm .......................... Passed
 4/26 test_protected_checksum .......... Passed
 5/26 test_manifest .................... Passed
 6/26 test_signing ..................... Passed
 7/26 test_bound_key ................... Passed
 8/26 test_file_io ..................... Passed
 9/26 test_checked_arith_fallback ...... Passed
10/26 test_secure_buffer ............... Passed
11/26 test_obfuscated_string ........... Passed
12/26 test_checksum_flattened .......... Passed
13/26 test_license ..................... Passed
14/26 test_activation .................. Passed
15/26 test_activation_service .......... Passed
16/26 test_secrets_manager ............. Passed
17/26 test_trusted_time ................ Passed
18/26 test_hardware_id ................. Passed
19/26 test_update_manifest ............. Passed
20/26 test_antitamper .................. Passed
21/26 test_opcode_map .................. Passed
22/26 test_integration_engine .......... Passed
23/26 test_unreal_integration .......... Passed
24/26 test_pe_protector ................ Passed
25/26 test_c_api ....................... Passed
26/26 test_sample_e2e .................. Passed

100% tests passed, 0 tests failed out of 26
```

---

## 5. Usage Workflows

### 5.1 Command-Line Protection Tool (`rtprotect-tool`)

#### 1. Dry-Run Project Inspection
Preview proposed changes and verify function eligibility without writing files:
```powershell
.\build\tooling\rtprotect-tool.exe integrate C:\Projects\MyProject --profile balanced --dry-run
```

#### 2. Project Integration with Development Keys
Execute automated source instrumentation, CMake configuration injection, and validation build:
```powershell
.\build\tooling\rtprotect-tool.exe integrate C:\Projects\MyProject `
    --profile balanced `
    --dev-keys `
    --product com.vendor.myproject `
    --version 1.0.0
```

#### 3. Rollback Changes
Restore the target project to its pre-integration state using the automated backup:
```powershell
.\build\tooling\rtprotect-tool.exe rollback C:\Projects\MyProject C:\Projects\MyProject_backup_timestamp
```

#### 4. Validating Protected Builds
Verify the digital signature and resource digest of a compiled distribution binary:
```powershell
.\build\tooling\rtprotect-tool.exe validate-build `
    C:\Projects\MyProject `
    release.pub `
    release.manifest `
    release.sig
```

### 5.2 Standalone Activation Server (`rtprotect-activation-server`)

The activation authority provides online seat management and hardware-bound activation token issuance over HTTPS.

#### Development Execution (Local HTTP with In-Memory / Ephemeral Keys)
```powershell
.\build\tooling\rtprotect-activation-server.exe `
    --insecure-dev-only `
    --port 8080 `
    --host 127.0.0.1 `
    --db activations.db
```

#### Production Execution (TLS & Windows DPAPI Key Vault)
```powershell
# 1. Provision an Ed25519 signing key into the DPAPI vault
.\build\tooling\rtprotect-activation-server.exe --provision-vault "prod-key-01" "activation_pub.hex"

# 2. Provision an AES-256 database envelope key into the DPAPI vault
.\build\tooling\rtprotect-activation-server.exe --provision-db-vault "db-key-01"

# 3. Launch the production service
.\build\tooling\rtprotect-activation-server.exe `
    --port 8443 `
    --host 0.0.0.0 `
    --tls-cert cert.pem `
    --tls-key key.pem `
    --vault-id "prod-key-01" `
    --db-vault-id "db-key-01" `
    --admin-token-file admin_secret.txt
```

### 5.3 C++ SDK Integration

To integrate RTProtect into an existing C++ project:

#### `CMakeLists.txt`
```cmake
cmake_minimum_required(VERSION 3.20)
project(EnterpriseApp CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(RTProtect CONFIG REQUIRED)

add_executable(EnterpriseApp main.cpp)

target_link_libraries(EnterpriseApp PRIVATE
    RTProtect::rtprotect_licensing
    RTProtect::rtprotect_antitamper
    RTProtect::rtprotect_vm
    RTProtect::rtprotect_integrity
    RTProtect::rtprotect_crypto
)
```

#### `main.cpp`
```cpp
#include <iostream>
#include <antitamper/anti_debug.h>
#include <licensing/hardware_id.h>

int main() {
  if (rtprotect::antitamper::CheckDebuggerPresent()) {
    std::cerr << "Debugger detected. Halting execution.\n";
    return 1;
  }

  std::string hwid = rtprotect::licensing::GetLocalHardwareId();
  std::cout << "Machine Binding: " << hwid << "\n";
  return 0;
}
```

### 5.4 C-ABI Runtime Library (`rtprotect_runtime.dll`)

Applications in C, C#, Python, or Rust can consume the C-ABI interface exposed by `runtime/c_api.h`:

```c
#include "c_api.h"
#include <stdio.h>

int main(void) {
    char hwid[65] = {0};
    if (rtprotect_get_hardware_id(hwid, sizeof(hwid)) > 0) {
        printf("Hardware ID: %s\n", hwid);
    }

    double risk = rtprotect_assess_environment_risk();
    if (risk > 0.5) {
        fprintf(stderr, "Host environment risk exceeded threshold: %.2f\n", risk);
        return 1;
    }

    return 0;
}
```

---

## 6. Project Structure

```text
rtprotect/
|-- antitamper/            # PEB checking, hardware breakpoint watchdog, PE import hashing, anti-dump
|-- bytecode_vm/           # Custom bytecode VM, instruction set, verification pass, opcode map
|-- crypto/                # OpenSSL AES-256-GCM, HKDF-SHA256, SecureBuffer zeroization
|-- integrity/             # Streaming SHA-256, Ed25519 signatures, release manifests, bound keys
|-- licensing/             # Hardware ID, DPAPI storage, activation client/server, trusted time
|-- obfuscation/           # Mixed Boolean-Arithmetic (MBA), opaque predicates, control-flow flattening
|-- runtime/               # C-ABI export layer (c_api.h) producing rtprotect_runtime.dll
|-- tooling/               # rtprotect-tool CLI, integration engine, GUI front-end, activation server
|-- bench/                 # Benchmark harness measuring VM and AEAD throughput (rtprotect-bench)
|-- examples/              # Consumer samples and integration reference targets
|-- tests/                 # Unit, integration, E2E PowerShell, and regression test suites
|-- fuzz/                  # LibFuzzer targets for parser, VM, and PE modules
|-- docs/                  # Detailed architectural, API, and operational documentation
+-- third_party/           # Bundled OpenSSL headers and precompiled x64 Windows libraries
```

---

## 7. Verified Benchmarks

Benchmarks recorded on Windows x64 via `rtprotect-bench.exe` (1,000 discarded warm-up iterations, 15 independent trials, 20,000 iterations per trial):

| Execution Model | Median Duration | Duration per Iteration | Overhead vs Baseline |
|:---|:---:|:---:|:---:|
| Native (unprotected baseline) | 2.380 ms | 119.0 ns | 1.00x |
| Control-Flow Flattened (Phase 5) | 2.641 ms | 132.1 ns | 1.11x |
| Bytecode VM (including per-call static verification) | 4.742 ms | 23,711.0 ns | ~199x |

### AES-256-GCM Cryptographic Throughput
- **1 KiB payload:** 433.2 MiB/s
- **64 KiB payload:** 1,736.4 MiB/s
- **1,024 KiB payload:** 1,471.5 MiB/s

---

## 8. Release Artifacts & Distribution

Release packaging is automated via [`tooling/package_release.ps1`](tooling/package_release.ps1):

```powershell
powershell -ExecutionPolicy Bypass -File tooling/package_release.ps1 -BuildDir build -OpenSslDir third_party/openssl
```

The script compiles all targets, validates CTest suites, smoke tests the consumer sample with the newly packaged SDK, and produces three standalone zip archives in `dist/`:

1. **`rtprotect-windows-x64.zip`**: Command-line protection tool (`rtprotect-tool.exe`), GUI wizard (`rtprotect-gui.exe`), benchmark tool (`rtprotect-bench.exe`), and runtime DLLs.
2. **`rtprotect-sdk-windows-x64.zip`**: Developer C++ SDK containing headers (`include/`), precompiled static libraries (`lib/`), CMake configuration modules, and example projects.
3. **`rtprotect-activation-server-windows-x64.zip`**: Standalone activation server daemon (`rtprotect-activation-server.exe`) and runtime dependencies.

---

## 9. Technical Documentation Directory

For in-depth operational and engineering references, consult the dedicated documentation:

| Document | Focus Area |
|:---|:---|
| [`docs/architecture.md`](docs/architecture.md) | Architectural decomposition, execution models, and data flows |
| [`docs/installation.md`](docs/installation.md) | Toolchain prerequisites, compiler configuration, and building from source |
| [`docs/configuration.md`](docs/configuration.md) | Security profiles, compile-time macros, and server environment variables |
| [`docs/api.md`](docs/api.md) | C++ SDK reference, C-ABI runtime API, CLI reference, and HTTP endpoints |
| [`docs/database.md`](docs/database.md) | Activation database schema, AES envelope encryption, and DPAPI integration |
| [`docs/security.md`](docs/security.md) | Cryptographic guarantees, anti-tamper mechanisms, and threat model |
| [`docs/development.md`](docs/development.md) | Coding guidelines, testing strategy, fuzz testing, and debugging |
| [`docs/deployment.md`](docs/deployment.md) | Production server deployment, TLS configuration, and client distribution |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Contribution standards, code style, and pull request procedures |
| [`CHANGELOG.md`](CHANGELOG.md) | Version history, security remediations, and architectural milestones |

---

## 10. License

This project is licensed under the [MIT License](LICENSE). Third-party library notices and license texts for OpenSSL are documented in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
