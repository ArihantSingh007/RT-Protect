# RTProtect

**Enterprise C++ Runtime Binary Protection, Anti-Tamper & Cryptographic Licensing Framework for Windows x64**

[![Platform](https://img.shields.io/badge/platform-Windows%20x64-blue.svg)](https://microsoft.com)
[![Standard](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://en.cppreference.com/w/cpp/20)
[![Compiler](https://img.shields.io/badge/compiler-MSVC%202022%20%7C%20MinGW--w64-green.svg)](https://visualstudio.microsoft.com/)
[![Cryptography](https://img.shields.io/badge/crypto-OpenSSL%203.4.0%20(AES--GCM%20%2F%20Ed25519)-purple.svg)](https://www.openssl.org/)
[![Tests](https://img.shields.io/badge/tests-22%2F22%20passing-brightgreen.svg)]()
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

---

## 1. Overview

RTProtect is a commercial-grade binary protection and cryptographic licensing framework designed specifically for native C and C++ applications on Windows x64. It raises the reverse-engineering barrier against static disassembly, interactive debugging, binary patching, and unauthorized distribution by combining **bytecode virtualization**, **Clang AST semantic instrumentation**, **active anti-debugging and anti-hooking watchdogs**, and a **hardware-bound node-locked licensing authority**.

RTProtect is engineered strictly with a **fail-closed, defense-in-depth architecture**:
- **Offline Asymmetric Authority:** Authorization decisions rely on vendor-signed Ed25519 certificates. Distributed client binaries embed only public verification keys; private signing keys reside strictly offline or inside secure licensing servers.
- **Tamper-Poisoned Key Derivation:** Centralized boolean gates (`if (tampered) exit()`) are eliminated in favor of HKDF-HMAC-SHA256 key poisoning (`DeriveTamperBoundKey`). Detected debuggers or memory hooks silently corrupt internal decryption keys, triggering cascaded cryptographic failures.
- **Transactional Integration:** Automated project instrumenters support dry-run previews, automated timestamped backups, and byte-for-byte rollback.
- **Native Windows Specialization:** Utilizes Windows Data Protection API (DPAPI), Structured Exception Handling (SEH), Hardware Breakpoint Debug Registers (`DR0`–`DR3`), PE dynamic API resolution, and Control Flow Guard (CFG).

---

## 2. Core Protection Modules

```
                           +----------------------------------------+
                           |           Target Application           |
                           +-------------------+--------------------+
                                               |
                     +-------------------------+-------------------------+
                     |                                                   |
                     v                                                   v
        +-------------------------+                         +-------------------------+
        |   bytecode_vm / VM IR   |                         |  antitamper / Integrity |
        |  - Stack & Threaded VMs |                         |  - Hardware Watchdog    |
        |  - Randomized Opcodes   |                         |  - PE Import Resolution |
        |  - Per-Call Verifier    |                         |  - Anti-Dump / Memory   |
        +------------+------------+                         +------------+------------+
                     |                                                   |
                     +-------------------------+-------------------------+
                                               |
                                               v
                           +----------------------------------------+
                           |         licensing / Authority          |
                           |  - Hardware ID (CPU, GUID, Disk)       |
                           |  - DPAPI Token Secure Storage          |
                           |  - Ephemeral AES-256 Transport         |
                           |  - Anti-Replay Challenge Nonces        |
                           +-------------------+--------------------+
                                               |
                                               v
                           +----------------------------------------+
                           |   crypto & integrity (OpenSSL 3.4.0)   |
                           |  - AES-256-GCM Authenticated Encrypt   |
                           |  - HKDF-SHA256 Key Derivation          |
                           |  - Ed25519 Manifest & Token Signatures |
                           +----------------------------------------+
```

### 2.1 Bytecode Virtualization (`bytecode_vm/`)
- **Virtual Instruction Set:** Custom closed virtual machine supporting register-threaded and stack-based execution architectures.
- **Static Bytecode Verifier:** Strict linear decode pass rejects malformed bytecode, out-of-bounds jumps, and instruction-boundary misalignments prior to execution.
- **Randomized Opcode Permutation:** Instructions are mapped to per-build randomized seeds, neutralizing universal bytecode decompilers across builds.
- **Execution Budget Safeguard:** Instruction counter backstop prevents algorithmic infinite-loop denial-of-service attacks.

### 2.2 Clang AST Scanner & Code Transformer (`tooling/`)
- **Compilation Database Parsing:** Consumes `compile_commands.json` to extract precise compiler flags, defines, and system include paths.
- **Semantic AST Analysis:** Invokes Clang AST JSON dump (`-Xclang -ast-dump=json`) to validate function parameter types, return values, and eligibility.
- **Type-Safe Function Wrappers:** Automatically transforms candidate C++ functions into encrypted bytecode blobs while preserving standard calling conventions and ABI boundaries.
- **Subprocess Safety:** Non-blocking pipe capture via `PeekNamedPipe` with a 30-second execution deadline, 64 MB capture ceiling, and process tree termination (`TerminateProcess`).

### 2.3 Anti-Tamper & Anti-Debugging (`antitamper/`)
- **Hardware Breakpoint Watchdog:** Background thread scans thread debug registers (`DR0`–`DR3`) periodically for hardware breakpoints.
- **Dynamic PE Import Resolution:** Critical Win32 APIs are resolved dynamically via hashed PE export table parsing, leaving zero static import entries in the PE header.
- **Anti-Dump Protection:** Tightens memory page permissions, strips executable headers in memory, and detects process memory dumps.
- **Timing Anomaly Detection:** Detects single-stepping and debugger trap latency via high-resolution performance counters.

### 2.4 Cryptographic Licensing Authority (`licensing/`)
- **Hardware-Bound Fingerprinting:** Derives 64-character composite machine fingerprints from CPU characteristics, motherboard GUID, and physical storage volume serials with configurable drift tolerance.
- **Credential Storage (DPAPI):** Encrypts stored activation tokens via Windows Data Protection API (`CryptProtectData`), tying secrets to the user logon session.
- **Standalone Activation Server (`rtprotect-activation-server`):** High-performance multithreaded HTTP/TLS server managing seat allocation, instant license revocation, anti-replay nonces, IP and license token-bucket rate limiting, and structured audit event telemetry.

---

## 3. Tooling and Binaries

| Binary / Tool | Target | Description |
|---|---|---|
| `bin/rtprotect-tool.exe` | CLI | Automated integration engine: plans, instruments, builds, and verifies projects. |
| `bin/rtprotect-gui.exe` | Win32 GUI | Graphical project inspector, security profiler, and integration wizard. |
| `bin/rtprotect-activation-server.exe` | Service | Standalone licensing authority serving `/activate`, `/renew`, and `/events`. |
| `bin/rtprotect-bench.exe` | Benchmark | Statistical benchmark suite measuring native vs. VM overhead and AEAD throughput. |

---

## 4. Quickstart Guide

### 4.1 Automated CLI Integration

To protect an existing CMake or Unreal Engine project:

```cmd
# 1. Preview changes and inspect candidate functions (dry run)
bin\rtprotect-tool.exe integrate C:\Projects\MyGame --profile balanced --dry-run

# 2. Execute transactional integration with automated backup
bin\rtprotect-tool.exe integrate C:\Projects\MyGame --profile balanced --product com.vendor.mygame --version 1.0.0

# 3. Validate compiled binaries against vendor-signed manifest
bin\rtprotect-tool.exe validate-build C:\Projects\MyGame\build\bin\MyGame.exe release.manifest release.sig release.pub
```

### 4.2 Graphical User Interface (`rtprotect-gui.exe`)
Launch `bin/rtprotect-gui.exe` to inspect project source trees visually, select security profiles (Dev, Balanced, Maximum), configure vendor keys, review candidate functions, and execute protection workflows.

### 4.3 Running the Licensing Activation Server
```cmd
# Run server on port 8080 (loopback interface)
bin\rtprotect-activation-server.exe --port 8080 --host 127.0.0.1 --db activations.db

# Register a 5-seat commercial license
bin\rtprotect-activation-server.exe --db activations.db --register-license "LIC-ENT-001" "com.vendor.mygame" 5

# Production TLS deployment with external interface binding
bin\rtprotect-activation-server.exe --port 8443 --host 0.0.0.0 --tls-cert cert.pem --tls-key key.pem --admin-token-file admin_key.txt
```

---

## 5. C++ Developer SDK Integration

Add the RTProtect SDK to any CMake project:

### 5.1 CMakeLists.txt
```cmake
cmake_minimum_required(VERSION 3.20)
project(MyProtectedApp CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find RTProtect package from SDK installation
find_package(RTProtect CONFIG REQUIRED)

add_executable(MyProtectedApp main.cpp)

# Link desired protection modules
target_link_libraries(MyProtectedApp PRIVATE
    RTProtect::rtprotect_licensing
    RTProtect::rtprotect_antitamper
    RTProtect::rtprotect_vm
    RTProtect::rtprotect_integrity
    RTProtect::rtprotect_crypto
)
```

### 5.2 Application Source Code (`main.cpp`)
```cpp
#include <iostream>
#include <antitamper/anti_debug.h>
#include <licensing/hardware_id.h>

int main() {
    // 1. Verify environment integrity (anti-debugging check)
    if (rtprotect::antitamper::CheckDebuggerPresent()) {
        std::cerr << "Debugger detected. Execution terminated.\n";
        return 1;
    }

    // 2. Query hardware node-locked identifier
    std::string hwid = rtprotect::licensing::GetLocalHardwareId();
    std::cout << "Machine Fingerprint: " << hwid << "\n";
    std::cout << "RTProtect initialized successfully.\n";
    return 0;
}
```

---

## 6. Building and Testing from Source

### Requirements
- **Operating System:** Windows 10 / 11 (x64)
- **Compiler:** Visual Studio 2022 (MSVC v143, Version 19.30+) or MinGW-W64 (GCC 15.2+)
- **Build System:** CMake 3.20+ and Ninja
- **Cryptography:** OpenSSL 3.4.0 (pre-bundled under `third_party/openssl/`)

### Build with MinGW-W64 / Ninja:
```powershell
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR="third_party/openssl"
cmake --build build --config Release
ctest --test-dir build --output-on-failure
```

### Build with Visual Studio 2022 (from Developer PowerShell for VS 2022):
```powershell
cmake -B build -G "Visual Studio 17 2022" -A x64 -DOPENSSL_ROOT_DIR="${PWD}/third_party/openssl" -DRTPROTECT_BUILD_TESTS=ON
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

### Automated Verification Status:
```
Test project build/
 1/22 Test  #1: test_aead ........................   Passed    0.04 sec
 2/22 Test  #2: test_kdf .........................   Passed    0.03 sec
 3/22 Test  #3: test_vm ..........................   Passed    0.02 sec
 4/22 Test  #4: test_protected_checksum ..........   Passed    0.03 sec
 5/22 Test  #5: test_manifest ....................   Passed    0.02 sec
 6/22 Test  #6: test_signing .....................   Passed    0.03 sec
 7/22 Test  #7: test_bound_key ...................   Passed    0.03 sec
 8/22 Test  #8: test_file_io .....................   Passed    0.02 sec
 9/22 Test  #9: test_checked_arith_fallback ......   Passed    0.15 sec
10/22 Test #10: test_secure_buffer ...............   Passed    0.02 sec
11/22 Test #11: test_obfuscated_string ...........   Passed    0.02 sec
12/22 Test #12: test_checksum_flattened ..........   Passed    0.03 sec
13/22 Test #13: test_license .....................   Passed    0.03 sec
14/22 Test #14: test_activation ..................   Passed    0.12 sec
15/22 Test #15: test_activation_service ..........   Passed    0.24 sec
16/22 Test #16: test_trusted_time ................   Passed    0.14 sec
17/22 Test #17: test_hardware_id .................   Passed    0.03 sec
18/22 Test #18: test_update_manifest .............   Passed    0.04 sec
19/22 Test #19: test_antitamper ..................   Passed    0.11 sec
20/22 Test #20: test_opcode_map ..................   Passed    0.02 sec
21/22 Test #21: test_integration_engine ..........   Passed   19.01 sec
22/22 Test #22: test_unreal_integration ..........   Passed    0.05 sec

100% tests passed, 0 tests failed out of 22
```

---

## 7. Release Packaging & Verification

Packaging is executed via `tooling/package_release.ps1`, producing three distinct release archives and running an automated consumer sample smoke test against the newly built SDK:

```powershell
powershell -ExecutionPolicy Bypass -File tooling\package_release.ps1 -BuildDir build
```

### Generated Artifacts (`dist/`):
- **`rtprotect-windows-x64.zip`** — CLI tool, GUI profiler, benchmark runner, runtime OpenSSL DLLs, and documentation.
- **`rtprotect-sdk-windows-x64.zip`** — Developer SDK: C++ headers, static libraries, `RTProtectConfig.cmake`, and consumer sample project.
- **`rtprotect-activation-server-windows-x64.zip`** — Standalone activation authority server executable and dependencies.
- **`SHA256SUMS.txt`** — Cryptographic checksum manifest.
- **`SBOM.spdx.json`** — Software Bill of Materials (SPDX 2.3 standard).
- **`BUILD_INFO.txt`** — Compilation environment and Git commit provenance.

---

## 8. Benchmark Results (Windows x64)

Statistical benchmarks captured via `rtprotect-bench.exe` (1000 warm-up iterations discarded, 15 independent trials, 20,000 iterations per trial):

| Implementation | Median Time | ns / iteration | Performance Relative to Native |
|---|---|---|---|
| Native (unprotected baseline) | 0.583 ms | 29.2 ns | 1.00x (Baseline) |
| Flattened (control-flow obfuscation) | 0.586 ms | 29.3 ns | 1.01x (~0% overhead) |
| Bytecode VM (with per-call static verification) | 1.106 ms | 5530.0 ns | ~190x |

### AES-256-GCM Cryptographic Throughput:
- **1 KiB payload:** 470.7 MiB/s
- **64 KiB payload:** 1,409.7 MiB/s
- **1024 KiB payload:** 1,151.3 MiB/s

---

## 9. Security & Compliance Notices

- **Threat Model:** Refer to [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the formal security boundaries and assumptions.
- **Security Audit:** Comprehensive audit findings and remediations are tracked in [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md).
- **Third-Party Licenses:** OpenSSL 3.4.0 license terms are detailed in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
- **Project License:** Licensed under the [MIT License](LICENSE).
