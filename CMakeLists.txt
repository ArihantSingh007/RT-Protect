cmake_minimum_required(VERSION 3.20)
project(rtprotect LANGUAGES CXX)

if(WIN32)
  add_compile_definitions(NOMINMAX)
endif()

if(NOT WIN32)
  message(FATAL_ERROR "RTProtect is supported exclusively on Windows platforms.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(RTPROTECT_BUILD_TESTS "Build unit tests" ON)
option(RTPROTECT_HARDEN_RELEASE
       "Apply Phase 5 release-hardening flags (symbol/visibility stripping, dead-code elimination) in Release builds"
       ON)
option(RTPROTECT_SANITIZE
       "Build with AddressSanitizer + UndefinedBehaviorSanitizer (GCC/Clang only; findings are fixed, never suppressed -- see docs/SECURITY_HARDENING.md)"
       OFF)
option(RTPROTECT_BUILD_FUZZERS
       "Build libFuzzer harnesses under fuzz/ (Clang only -- see fuzz/README.md). Not buildable or tested in this project's GCC-only development environment."
       OFF)
option(RTPROTECT_ENABLE_EXPERIMENTAL_RUNTIME_RECONSTRUCTION
       "Build Phase 6's experimental native-code-reconstruction module (runtime/). OFF by default per the brief's explicit instruction that this technique be an isolated, opt-in research experiment -- see docs/RUNTIME_RECONSTRUCTION.md before turning this on."
       OFF)

if(RTPROTECT_BUILD_FUZZERS AND WIN32)
  # LLVM on Windows ships libFuzzer static libraries linked against MT runtime
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# ---------------------------------------------------------------------------
# Toolchain notes
#
# Target platform: Windows 10/11 x64 (MSVC Visual Studio 2022 or MinGW-W64).
# RTProtect is built exclusively for Windows environments.
# ---------------------------------------------------------------------------

if(NOT DEFINED OPENSSL_ROOT_DIR AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/openssl")
  set(OPENSSL_ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/openssl")
endif()

find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto SSL)

# rtprotect_strip_in_release(target): applies full symbol-table stripping as
# a post-build step on a final Release executable. Defined unconditionally
# (as a no-op where it doesn't apply) so every add_executable() across the
# project can call it the same way regardless of platform/option state --
# see each module's CMakeLists.txt for the call sites.
find_program(RTPROTECT_STRIP_TOOL strip)

function(rtprotect_strip_in_release target)
  if(NOT MSVC AND RTPROTECT_HARDEN_RELEASE AND RTPROTECT_STRIP_TOOL)
    # Full symbol-table + debug-info stripping as a post-build step on
    # Release executables -- see docs/OBFUSCATION.md for the actual
    # before/after size measured in this environment.
    add_custom_command(TARGET ${target} POST_BUILD
      COMMAND $<$<CONFIG:Release>:${RTPROTECT_STRIP_TOOL}>
              $<$<CONFIG:Release>:--strip-all>
              $<$<CONFIG:Release>:$<TARGET_FILE:${target}>>
      COMMENT "Stripping symbols from $<TARGET_FILE:${target}> (Release only)"
    )
  endif()
  # On MSVC: stripping is a packaging-time PDB-exclusion step (MSVC never
  # embeds full debug info in the .exe/.dll itself), not a post-build
  # command -- see the MSVC branch below. When hardening is disabled or
  # `strip` isn't found, this function intentionally does nothing.
endfunction()

if(MSVC)
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
  add_compile_options(/W4 /permissive- /Zc:__cplusplus /EHsc)
  add_compile_options($<$<CONFIG:Release>:/guard:cf>)
  add_link_options($<$<CONFIG:Release>:/guard:cf>)
  # /DYNAMICBASE (ASLR) and /NXCOMPAT (DEP) are MSVC linker defaults for
  # modern toolsets, but set explicitly here so the mitigation is visible
  # in this file rather than relying on a default that could silently
  # change -- see docs/SECURITY_HARDENING.md's compiler-mitigations table
  # for the full list and what each one does and does not provide.
  add_link_options(/DYNAMICBASE /NXCOMPAT)
  if(RTPROTECT_HARDEN_RELEASE)
    # /Gw: eliminate unreferenced COMDAT data, paired with /OPT:REF below.
    # /OPT:REF, /OPT:ICF: linker-side dead-code elimination and identical-
    # COMDAT folding -- the MSVC equivalents of --gc-sections below.
    add_compile_options($<$<CONFIG:Release>:/Gw>)
    add_link_options($<$<CONFIG:Release>:/OPT:REF> $<$<CONFIG:Release>:/OPT:ICF>)
  endif()
else()
  add_compile_options(-Wall -Wextra -Wpedantic -fstack-protector-strong)
  if(MINGW)
    # Position-independent executable on MinGW
    add_compile_options($<$<STREQUAL:$<TARGET_PROPERTY:TYPE>,EXECUTABLE>:-fPIE>)
    add_link_options($<$<STREQUAL:$<TARGET_PROPERTY:TYPE>,EXECUTABLE>:-pie>)
  endif()
  if(RTPROTECT_HARDEN_RELEASE)
    # -fvisibility=hidden / -fvisibility-inlines-hidden: don't export symbols
    # from this project's libraries unless explicitly marked, so a release
    # binary's dynamic symbol table doesn't hand a reverse engineer a
    # pre-made map of every internal function name for free.
    # -ffunction-sections / -fdata-sections + --gc-sections: let the linker
    # discard unreferenced functions/data instead of keeping everything in
    # a translation unit just because one symbol from it was used.
    add_compile_options(
      $<$<CONFIG:Release>:-fvisibility=hidden>
      $<$<CONFIG:Release>:-fvisibility-inlines-hidden>
      $<$<CONFIG:Release>:-ffunction-sections>
      $<$<CONFIG:Release>:-fdata-sections>
    )
    add_link_options($<$<CONFIG:Release>:-Wl,--gc-sections>)
  endif()
  if(RTPROTECT_SANITIZE)
    # AddressSanitizer catches heap/stack/global buffer overflows,
    # use-after-free, use-after-return, and double-free.
    # UndefinedBehaviorSanitizer catches signed-integer-overflow, invalid
    # pointer arithmetic, misaligned/invalid pointer dereferences, and
    # other UB the standard permits a compiler to miscompile around.
    # Applied globally (not per-target) so every library, test, and tool
    # binary in this build is instrumented consistently -- see
    # docs/SECURITY_HARDENING.md for actual findings from running this and
    # how each was fixed (never suppressed).
    add_compile_options(-fsanitize=address,undefined -fno-sanitize-recover=all -g)
    add_link_options(-fsanitize=address,undefined)
  endif()
endif()

add_subdirectory(crypto)
add_subdirectory(bytecode_vm)
add_subdirectory(integrity)
add_subdirectory(licensing)
add_subdirectory(antitamper)
add_subdirectory(obfuscation)

add_subdirectory(runtime)

add_subdirectory(tooling)
add_subdirectory(bench)

if(RTPROTECT_BUILD_FUZZERS)
  add_subdirectory(fuzz)
endif()

if(RTPROTECT_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
