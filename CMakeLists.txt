cmake_minimum_required(VERSION 3.20)
project(rtprotect LANGUAGES CXX)

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

# ---------------------------------------------------------------------------
# Toolchain notes
#
# Primary target toolchain: MSVC (Visual Studio 2022), Windows 10/11 x64.
# This CMakeLists also builds cleanly on Linux/GCC/Clang so the cryptographic
# core can be developed and unit-tested in CI without a Windows machine.
# Nothing in this project is Windows-specific yet; no module has introduced
# Win32-specific code behind #ifdef _WIN32 (none has needed to).
# ---------------------------------------------------------------------------

find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)

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
  add_compile_options(/W4 /permissive- /Zc:__cplusplus)
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
  # Position-independent executable: required for ASLR to randomize the
  # main executable's own load address on Linux (shared libraries are
  # already relocatable; the main binary isn't, by default, unless built
  # as a PIE). Most modern distro toolchains default this on already, but
  # -- same reasoning as the MSVC linker flags above -- set explicitly so
  # it's a documented, audited property of this build rather than an
  # assumed distro default.
  add_compile_options(-fPIE)
  add_link_options(-pie)
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

if(RTPROTECT_ENABLE_EXPERIMENTAL_RUNTIME_RECONSTRUCTION)
  add_subdirectory(runtime)
endif()

add_subdirectory(tooling)
add_subdirectory(bench)

if(RTPROTECT_BUILD_FUZZERS)
  add_subdirectory(fuzz)
endif()

if(RTPROTECT_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
