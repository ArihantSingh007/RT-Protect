# RTProtect Build, Hardening, and Release Guide

## 1. Build Requirements & Toolchain Prerequisites

RTProtect is engineered for reproducible compilation and hardened deployment on 64-bit Windows environments.

| Requirement | Supported Specifications | Verified In Baseline |
|---|---|---|
| **OS** | Windows 10 (x64) / Windows 11 (x64) / Windows Server 2019+ | Windows 11 Enterprise x64 |
| **Compiler** | MSVC 19.30+ (VS 2022) or MinGW-w64 GCC 12.0+ (UCRT) | MinGW-w64 GCC 15.2.0 (UCRT) |
| **C++ Standard** | ISO C++20 (`-std=c++20` or `/std:c++20`) | C++20 |
| **Build Generator** | CMake 3.20+ with Ninja or Visual Studio 17 2022 | CMake 4.1.2 + Ninja |
| **Cryptography** | OpenSSL 3.0.0+ (Headers, `libcrypto.lib`, `libcrypto-3-x64.dll`) | OpenSSL 3.4.0 (in `third_party/openssl/`) |

---

## 2. Standard Configuration Build

### 2.1 Configuring with CMake
From the repository root in PowerShell:
```powershell
$openssl_dir = "$((Get-Item .).FullName)\third_party\openssl"
$env:PATH = "C:\mingw64\bin;$openssl_dir\bin;$env:PATH"

cmake -B build -S . -G Ninja `
    -DOPENSSL_ROOT_DIR="$openssl_dir" `
    -DCMAKE_BUILD_TYPE=Release `
    -DRTPROTECT_HARDEN_RELEASE=ON
```

### 2.2 Compiling the Framework & Tooling
```powershell
cmake --build build
```
This builds all static libraries (`rtprotect_crypto`, `rtprotect_integrity`, `rtprotect_licensing`, `rtprotect_antitamper`, `rtprotect_vm`, `rtprotect_obfuscation`, `rtprotect_tooling`), the CLI integration tool (`rtprotect-tool.exe`), the benchmark runner (`rtprotect-bench.exe`), and all 18 standard test targets.

### 2.3 Running the Test Suite
```powershell
ctest --test-dir build --output-on-failure
```
All 18 tests must pass before proceeding to packaging or release.

---

## 3. Experimental Runtime Reconstruction Configuration

To compile the experimental self-modifying / runtime-reconstructing function engine (utilizing Windows Vectored Exception Handling and dynamic executable memory pages):
```powershell
cmake -B build_exp -S . -G Ninja `
    -DOPENSSL_ROOT_DIR="$openssl_dir" `
    -DCMAKE_BUILD_TYPE=Release `
    -DRTPROTECT_ENABLE_EXPERIMENTAL_RUNTIME_RECONSTRUCTION=ON

cmake --build build_exp
ctest --test-dir build_exp --output-on-failure
```
In this mode, all 20 tests (18 core + `test_executable_memory` + `test_reconstructed_function`) compile and pass.

---

## 4. Binary Hardening & Compiler Security Flags

RTProtect enforces aggressive compiler and linker defenses when `-DRTPROTECT_HARDEN_RELEASE=ON` (enabled by default):

### 4.1 MinGW / GCC Toolchain
- `-fstack-protector-strong`: Injects canary words into stack frames with buffers, preventing stack-based buffer overflows.
- `-fPIE`: Generates position-independent code for full Address Space Layout Randomization (ASLR).
- `-pie` (Linker): Enables ASLR dynamic base relocation.
- `-Wl,--nxcompat`: Marks binary as compatible with Data Execution Prevention (DEP / NX).
- `-Wl,--dynamicbase`: Enforces ASLR on PE executable headers.
- `rtprotect_strip_in_release`: Automatically strips debug symbols and relocation symbols from release binaries.

### 4.2 MSVC Toolchain
- `/GS`: Buffer security check (stack canary enforcement).
- `/DYNAMICBASE`: Enforces Address Space Layout Randomization (ASLR).
- `/NXCOMPAT`: Enforces Data Execution Prevention (DEP).
- `/guard:cf`: Enables Microsoft Control Flow Guard (CFG) for indirect call verification.
- `/O2 /GL`: Whole Program Optimization with Link-Time Code Generation (LTCG).

---

## 5. Deterministic & Reproducible Builds

RTProtect mitigates reverse-engineering pattern discovery through build-time variance:
1. **Opcode Map Permutation:** The Bytecode VM supports pseudo-random bijection permutation of its opcode dispatch table via `bytecode_vm/opcode_map.cpp`. Recompiling with a unique vendor seed generates a polymorphic bytecode instruction set unique to each product build.
2. **Deterministic Stripping:** `rtprotect_strip_in_release` removes source paths, local user names, and compilation artifacts.

---

## 6. Release Packaging Pipeline

To package a release for distribution:
```powershell
.\tooling\package_release.ps1
```
The packaging script:
1. Performs a fresh release build with hardening flags enabled.
2. Executes the complete automated test suite (`ctest`).
3. Assembles binary tools, libraries, headers, and documentation into `dist/rtprotect-<YYYYMMDD>-windows-x64/`.
4. Creates a release distribution archive: `dist/rtprotect-<YYYYMMDD>-windows-x64.zip`.
