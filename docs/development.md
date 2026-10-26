# Development and Engineering Guide

## 1. Engineering Principles

RTProtect enforces strict engineering and security coding standards:
- **Language Standard:** ISO C++20 (`-std=c++20` / `/std:c++20`).
- **Memory Safety:** Manual heap allocations (`new` / `delete`) and raw owning pointers are prohibited. Use modern smart pointers (`std::unique_ptr`, `std::shared_ptr`) or RAII containers.
- **Fail-Closed Design:** Any failure condition (missing file, invalid signature, corrupted memory, timeout, debugger detected) must terminate or reject execution. Never fail open.
- **Checked Arithmetic:** Calculations involving allocations, jump offsets, fuel counters, and slice indices must be guarded against integer overflow.
- **Documentation & Comments:** Code comments and docstrings must remain accurate, technically descriptive, and devoid of marketing language or informal expressions.

---

## 2. Local Environment Setup

### 2.1 Compiler and CMake Configuration
Ensure your development environment has:
- Visual Studio 2022 (MSVC v143) or MinGW-w64 GCC 11.2+
- CMake 3.20+
- Ninja 1.10+
- Bundled OpenSSL at `third_party/openssl/`

### 2.2 Configuring a Debug Build

#### With Visual Studio 2022 (MSVC)
```powershell
cmake -B build-debug -G "Visual Studio 17 2022" -A x64 `
  -DOPENSSL_ROOT_DIR="${PWD}/third_party/openssl" `
  -DRTPROTECT_BUILD_TESTS=ON `
  -DCMAKE_BUILD_TYPE=Debug

cmake --build build-debug --config Debug
```

#### With MinGW-w64 and Ninja
```powershell
cmake -B build-debug -G Ninja `
  -DCMAKE_BUILD_TYPE=Debug `
  -DCMAKE_CXX_COMPILER=g++ `
  -DCMAKE_C_COMPILER=gcc `
  -DOPENSSL_ROOT_DIR="third_party/openssl" `
  -DRTPROTECT_BUILD_TESTS=ON

cmake --build build-debug
```

---

## 3. Testing Strategy and Execution

RTProtect enforces test verification across four testing tiers:
1. **Unit Tests:** Individual cryptographic, hashing, AST, and VM instruction tests.
2. **Integration Tests:** Engine validation combining multiple components.
3. **End-to-End Tests:** Real-world project transformation, compilation, execution, and binary tampering tests.
4. **Fuzz Testing:** Coverage-guided LLVM libFuzzer suites with AddressSanitizer and UndefinedBehaviorSanitizer.

### 3.1 Executing Unit and Integration Tests

Run the complete test suite with CTest:
```powershell
ctest --test-dir build-debug -C Debug --output-on-failure
```

To run a specific test suite with verbose diagnostic logging:
```powershell
ctest --test-dir build-debug -C Debug -R test_vm -V
```

### 3.2 Executing the End-to-End Test Suite

`test_sample_e2e` exercises the full lifecycle:
1. Copies `examples/sample_client_app` to an isolated workspace.
2. Invokes `rtprotect-tool integrate` with `--profile balanced`.
3. Verifies AST function virtualization of `ComputeProtectedEntitlement`.
4. Compiles the protected client application.
5. Verifies digital signatures and hardware-bound license files.
6. Executes the protected binary and validates the virtualized return value (`57`).
7. Modifies executable bytes on disk and validates that startup integrity rejection halts execution.

To run `test_sample_e2e` independently:
```powershell
ctest --test-dir build-vs2022 -C Release -R test_sample_e2e -V
```

---

## 4. Fuzz Testing with LLVM libFuzzer

Fuzzing targets test parser and deserialization resilience against corrupted, malformed, or hostile inputs.

### 4.1 Compiling Fuzz Targets
Requires LLVM Clang:
```powershell
cmake -B build-fuzz -G Ninja `
  -DCMAKE_CXX_COMPILER=clang++ `
  -DCMAKE_C_COMPILER=clang `
  -DOPENSSL_ROOT_DIR="${PWD}/third_party/openssl" `
  -DRTPROTECT_BUILD_FUZZERS=ON `
  -DCMAKE_BUILD_TYPE=Release

cmake --build build-fuzz --target `
  fuzz_pe_protector `
  fuzz_json_parser `
  fuzz_manifest_deserialize `
  fuzz_vm_deserialize_and_verify `
  fuzz_encrypted_message_deserialize `
  fuzz_source_scanner
```

### 4.2 Executing Fuzzers
Run fuzz targets with AddressSanitizer runtime in `%PATH%`:
```powershell
$asanDll = (Get-ChildItem -Path "C:\Program Files\LLVM" -Filter "clang_rt.asan_dynamic-x86_64.dll" -Recurse | Select-Object -First 1).DirectoryName
$env:PATH = "$asanDll;${PWD}/third_party/openssl/bin;$env:PATH"

New-Item -ItemType Directory -Force -Path fuzz_artifacts | Out-Null

# Run bounded fuzzing pass (e.g. 30 seconds per target)
.\build-fuzz\fuzz\fuzz_vm_deserialize_and_verify.exe -artifact_prefix=fuzz_artifacts/ -max_total_time=30
```

---

## 5. Coding Standards and Best Practices

### 5.1 Memory Alignment on Windows x64
When interacting with low-level Windows context APIs (`GetThreadContext`), ensure `CONTEXT` structures are aligned to 16-byte boundaries to avoid stack corruption or AVX register faults:
```cpp
alignas(16) CONTEXT ctx{};
ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
if (::GetThreadContext(thread_handle, &ctx)) {
    // Process registers
}
```

### 5.2 Pre-Main Startup Hook Retention
On MSVC with Whole Program Optimization (`/GL`) and dead-code stripping (`/OPT:REF`), unreferenced static initializers will be eliminated unless explicitly retained:
```cpp
#if defined(_MSC_VER)
#pragma section(".CRT$XCU", read)
extern "C" __declspec(allocate(".CRT$XCU")) int (*g_rtprotect_init_hook)() = InitializeRtProtectStartupHook;
#if defined(_WIN64)
#pragma comment(linker, "/include:g_rtprotect_init_hook")
#else
#pragma comment(linker, "/include:_g_rtprotect_init_hook")
#endif
#endif
```
