# Installation and Environment Setup

## 1. System Requirements

RTProtect targets the Windows x64 platform.

| Component | Minimum Requirement | Recommended |
|:---|:---|:---|
| **Operating System** | Windows 10 (version 1809+, 64-bit) | Windows 11 / Windows Server 2022 |
| **Architecture** | x86-64 (AMD64) | x86-64 with AVX2 and AES-NI support |
| **RAM** | 4 GB | 8 GB or higher |
| **Disk Space** | 2 GB free disk space | 5 GB for full build and fuzz artifacts |

---

## 2. Toolchain Prerequisites

### 2.1 Microsoft Visual C++ (MSVC)
- **Required:** Visual Studio 2022 (Version 17.0 or newer) or Visual Studio Build Tools 2022.
- **Required Workloads / Components:**
  - *Desktop development with C++*
  - *MSVC v143 - VS 2022 C++ x64/x86 build tools*
  - *Windows 10 SDK (10.0.19041.0+) or Windows 11 SDK (10.0.22000.0+)*
  - *C++ CMake tools for Windows*

### 2.2 MinGW-w64 GCC
- **Required:** MinGW-w64 with GCC 11.2 or newer (GCC 15.2 verified).
- **Environment:** MSYS2 with `mingw-w64-x86_64-gcc` and `mingw-w64-x86_64-ninja`.
- Must support C++20 standard libraries (`<format>`, `<ranges>`, `<concepts>`).

### 2.3 LLVM Clang (Optional, for Fuzz Testing)
- **Required:** Clang 16.0 or newer with AddressSanitizer (ASan) runtime DLLs.
- Typically located at `C:\Program Files\LLVM\bin`.

### 2.4 CMake and Ninja
- **CMake:** Version 3.20 or newer. Verify installation with `cmake --version`.
- **Ninja:** Version 1.10 or newer (optional for MSVC, required for MinGW/Clang). Verify with `ninja --version`.

### 2.5 OpenSSL Cryptography Library
RTProtect includes a precompiled, verified OpenSSL distribution in the repository under:
```text
third_party/openssl/
|-- include/       # OpenSSL C headers (evp.h, aes.h, kdf.h, etc.)
|-- lib/           # Static and import libraries (libcrypto.lib, libssl.lib)
+-- bin/           # Runtime DLLs (libcrypto-*.dll, libssl-*.dll)
```
When running custom builds, configure `-DOPENSSL_ROOT_DIR` to point to this directory.

---

## 3. Building from Source

Clone the repository and initialize all submodules:
```powershell
git clone https://github.com/ArihantSingh007/RT-Protect.git
cd RT-Protect
```

### 3.1 Build using Visual Studio 2022 (MSVC)

Open a **Developer PowerShell for VS 2022** or run `vcvars64.bat` to initialize the 64-bit compilation environment:

```powershell
# 1. Configure the project
cmake -B build-vs2022 -G "Visual Studio 17 2022" -A x64 `
  -DOPENSSL_ROOT_DIR="${PWD}/third_party/openssl" `
  -DRTPROTECT_BUILD_TESTS=ON

# 2. Compile Release configuration
cmake --build build-vs2022 --config Release

# 3. Execute the full automated test suite
ctest --test-dir build-vs2022 -C Release --output-on-failure
```

### 3.2 Build using MinGW-w64 and Ninja

In an MSYS2 MinGW-w64 or standard PowerShell environment with GCC in `%PATH%`:

```powershell
# 1. Configure the project
cmake -B build -G Ninja `
  -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_CXX_COMPILER=g++ `
  -DCMAKE_C_COMPILER=gcc `
  -DOPENSSL_ROOT_DIR="third_party/openssl" `
  -DRTPROTECT_BUILD_TESTS=ON

# 2. Compile all targets
cmake --build build

# 3. Execute automated test suite
ctest --test-dir build -C Release --output-on-failure
```

### 3.3 Build with Clang and libFuzzer (Sanitizer Instrumentation)

For security fuzzing and undefined behavior verification:

```powershell
# 1. Configure with Clang compiler and fuzzing targets enabled
cmake -B build-fuzz -G Ninja `
  -DCMAKE_CXX_COMPILER=clang++ `
  -DCMAKE_C_COMPILER=clang `
  -DCMAKE_BUILD_TYPE=Release `
  -DOPENSSL_ROOT_DIR="${PWD}/third_party/openssl" `
  -DRTPROTECT_BUILD_FUZZERS=ON

# 2. Compile fuzz targets
cmake --build build-fuzz --target `
  fuzz_pe_protector `
  fuzz_json_parser `
  fuzz_manifest_deserialize `
  fuzz_vm_deserialize_and_verify `
  fuzz_encrypted_message_deserialize `
  fuzz_source_scanner
```

---

## 4. Packaging Release Distributions

To generate official standalone distribution packages, execute the release packaging script:

```powershell
powershell -ExecutionPolicy Bypass -File tooling/package_release.ps1 -BuildDir build-vs2022 -OpenSslDir third_party/openssl
```

### Packaging Execution Steps:
1. Reconfigures the build cleanly with multi-config optimization flags.
2. Compiles all production libraries, CLI tools, GUI applications, and services.
3. Executes all 26 automated unit and end-to-end regression tests.
4. Assembles three distinct distribution layouts:
   - `dist/rtprotect-windows-x64/` (Tools and GUI)
   - `dist/rtprotect-sdk-windows-x64/` (Developer SDK)
   - `dist/rtprotect-activation-server-windows-x64/` (Activation Authority Service)
5. Executes an end-to-end smoke test compiling and running `consumer_sample` linked against the packaged SDK.
6. Generates compressed ZIP archives and SHA-256 integrity checksums (`SHA256SUMS.txt`).

---

## 5. Integrating the Packaged SDK

Extract `rtprotect-sdk-windows-x64.zip` into a known directory (e.g. `C:\SDKs\RTProtect`).

### Integrating via CMake
In your application's `CMakeLists.txt`:
```cmake
cmake_minimum_required(VERSION 3.20)
project(ClientApplication CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Point CMake to the RTProtect SDK installation
list(APPEND CMAKE_PREFIX_PATH "C:/SDKs/RTProtect")
find_package(RTProtect CONFIG REQUIRED)

add_executable(ClientApplication main.cpp)

target_link_libraries(ClientApplication PRIVATE
    RTProtect::rtprotect_licensing
    RTProtect::rtprotect_antitamper
    RTProtect::rtprotect_vm
    RTProtect::rtprotect_integrity
    RTProtect::rtprotect_crypto
)
```

---

## 6. Troubleshooting Build Issues

### OpenSSL Linking Errors (`LNK1104` or `undefined reference to EVP_*`)
- Ensure `-DOPENSSL_ROOT_DIR` is set as an absolute path when running multi-config generators.
- On Windows, ensure `libcrypto-*.dll` and `libssl-*.dll` exist in the directory of the built executable or in the system `%PATH%`.

### Linker Iterator Debug Level Mismatches (`LNK2038`)
- Occurs when linking Debug application code against Release static libraries (e.g. `_ITERATOR_DEBUG_LEVEL` mismatch).
- Build the SDK in matching configurations (`-DCMAKE_BUILD_TYPE=Debug` or `-DCMAKE_BUILD_TYPE=Release`).

### Missing Windows SDK Headers (`windows.h not found`)
- Ensure the Windows 10/11 SDK component is selected in the Visual Studio Installer.
- Run CMake from a Developer PowerShell prompt or after invoking `vcvars64.bat`.
