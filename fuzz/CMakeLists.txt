# Only reached when RTPROTECT_BUILD_FUZZERS is explicitly turned ON (see
# top-level CMakeLists.txt) AND the compiler is Clang -- libFuzzer
# (-fsanitize=fuzzer) is a Clang/LLVM feature with no GCC equivalent. This
# project's development environment has only GCC available (confirmed:
# `clang --version` reports "not found" -- see docs/SECURITY_HARDENING.md
# for the exact check), so RTPROTECT_BUILD_FUZZERS has never actually been
# turned on and built in this environment; these targets exist, are
# believed correct against libFuzzer's documented harness contract
# (a single LLVMFuzzerTestOneInput entry point per translation unit,
# nothing else), and have not been compiled or run here. See
# fuzz/README.md for exact commands to build and run these for real on a
# Clang toolchain.

if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  message(WARNING "RTPROTECT_BUILD_FUZZERS is ON but the compiler is not Clang -- "
                   "libFuzzer (-fsanitize=fuzzer) requires Clang. Skipping fuzz targets.")
  return()
endif()

function(add_rtprotect_fuzzer name source)
  add_executable(${name} ${source})
  target_include_directories(${name} PRIVATE ${CMAKE_SOURCE_DIR})
  target_compile_options(${name} PRIVATE -fsanitize=fuzzer,address,undefined -g)
  target_link_options(${name} PRIVATE -fsanitize=fuzzer,address,undefined)
endfunction()

add_rtprotect_fuzzer(fuzz_manifest_deserialize fuzz_manifest_deserialize.cpp)
target_link_libraries(fuzz_manifest_deserialize PRIVATE rtprotect_integrity)

add_rtprotect_fuzzer(fuzz_vm_deserialize_and_verify fuzz_vm_deserialize_and_verify.cpp)
target_link_libraries(fuzz_vm_deserialize_and_verify PRIVATE rtprotect_vm)

add_rtprotect_fuzzer(fuzz_encrypted_message_deserialize fuzz_encrypted_message_deserialize.cpp)
target_link_libraries(fuzz_encrypted_message_deserialize PRIVATE rtprotect_crypto)

add_rtprotect_fuzzer(fuzz_source_scanner fuzz_source_scanner.cpp)
target_link_libraries(fuzz_source_scanner PRIVATE rtprotect_tooling)

add_rtprotect_fuzzer(fuzz_pe_protector fuzz_pe_protector.cpp)
target_link_libraries(fuzz_pe_protector PRIVATE rtprotect_tooling)

