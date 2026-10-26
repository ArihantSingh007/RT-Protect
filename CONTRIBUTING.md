# Contributing to RTProtect

## 1. Principles and Expectations

RTProtect is a security-sensitive binary protection and cryptographic licensing framework. All contributions must maintain strict engineering rigor, technical accuracy, and zero-warning compilation standards.

---

## 2. Development Workflow

1. **Fork and Branch:** Create a feature or bugfix branch originating from `master`.
   ```powershell
   git checkout -b feature/hardened-pe-parser
   ```
2. **Commit Message Format:** Follow Conventional Commits:
   - `fix(antitamper): eliminate watchdog stack corruption in thread inspection`
   - `feat(licensing): add monotonic time validation for evaluation licenses`
   - `docs(api): document REST activation endpoints`
   - `test(vm): add coverage for malformed branch offset decoding`
3. **Zero Warning Policy:** Code must compile with zero compiler warnings under both Microsoft Visual C++ (v143) and MinGW-w64 GCC.
4. **Automated Testing:** All 26 test suites must pass before submitting a pull request.
5. **No Undefined Behavior:** All integer arithmetic involving allocations, fuel budgets, or buffer slicing must use checked bounds or unsigned arithmetic to prevent undefined behavior.

---

## 3. Coding Guidelines

### 3.1 C++ Standard and Idioms
- Target **ISO C++20**.
- Do not introduce manual heap allocations (`new` / `delete`). Use RAII containers (`std::vector`, `std::string`) or smart pointers (`std::unique_ptr`).
- Wrap sensitive cryptographic keys and plaintexts in `rtprotect::crypto::SecureBuffer` to ensure zeroization on deallocation.

### 3.2 Platform-Specific Structures
- Windows x64 ABI mandates 16-byte alignment for `CONTEXT` structures. When calling `GetThreadContext`, always declare `alignas(16) CONTEXT ctx{}`.
- MSVC Whole Program Optimization (`/GL`) prunes unreferenced static initializers. Retain linker section pointers via `#pragma comment(linker, "/include:...")` and provide a C++ dynamic initializer fallback.

---

## 4. Verification Checklist

Before creating a Pull Request, verify all items:

- [ ] Code compiles without warnings on MSVC 2022 Release:
  ```powershell
  cmake -B build-vs2022 -G "Visual Studio 17 2022" -A x64 -DRTPROTECT_BUILD_TESTS=ON
  cmake --build build-vs2022 --config Release
  ```
- [ ] Code compiles without warnings on MinGW-w64 GCC Ninja:
  ```powershell
  cmake -B build-mingw -G Ninja -DCMAKE_BUILD_TYPE=Release -DRTPROTECT_BUILD_TESTS=ON
  cmake --build build-mingw
  ```
- [ ] All 26 automated tests pass under CTest:
  ```powershell
  ctest --test-dir build-vs2022 -C Release --output-on-failure
  ```
- [ ] Release packaging and consumer sample smoke test succeeds:
  ```powershell
  powershell -ExecutionPolicy Bypass -File tooling/package_release.ps1 -BuildDir build-vs2022 -OpenSslDir third_party/openssl
  ```
- [ ] If modifying parsers or VM bytecode decoders, run libFuzzer targets to verify resilience:
  ```powershell
  cmake -B build-fuzz -G Ninja -DCMAKE_CXX_COMPILER=clang++ -DRTPROTECT_BUILD_FUZZERS=ON
  cmake --build build-fuzz
  ```

---

## 5. Security Vulnerability Disclosure

If you discover a security vulnerability, do not open a public GitHub issue. Send details and proof of concept to the project security maintainers or report via GitHub Private Vulnerability Reporting.
