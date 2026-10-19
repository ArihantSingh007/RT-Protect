add_executable(test_aead test_aead.cpp)
target_link_libraries(test_aead PRIVATE rtprotect_crypto)
target_include_directories(test_aead PRIVATE ${CMAKE_SOURCE_DIR})
add_test(NAME test_aead COMMAND test_aead)

add_executable(test_kdf test_kdf.cpp)
target_link_libraries(test_kdf PRIVATE rtprotect_crypto)
target_include_directories(test_kdf PRIVATE ${CMAKE_SOURCE_DIR})
add_test(NAME test_kdf COMMAND test_kdf)

add_executable(test_vm test_vm.cpp)
target_link_libraries(test_vm PRIVATE rtprotect_vm)
target_include_directories(test_vm PRIVATE ${CMAKE_SOURCE_DIR})
add_test(NAME test_vm COMMAND test_vm)

add_executable(test_protected_checksum test_protected_checksum.cpp)
# Links rtprotect_integrity_buildtools because this test must be able to
# PRODUCE a signed release (BuildVerifiedChecksumRelease) to test the
# fully-integrated verified pipeline against -- the same reasoning as
# tests/test_signing.cpp's note on why it's one of the few things in this
# project allowed to link that target.
target_link_libraries(test_protected_checksum PRIVATE rtprotect_vm rtprotect_crypto
                       rtprotect_integrity rtprotect_integrity_buildtools)
target_include_directories(test_protected_checksum PRIVATE ${CMAKE_SOURCE_DIR})
add_test(NAME test_protected_checksum COMMAND test_protected_checksum)

add_executable(test_manifest test_manifest.cpp)
target_link_libraries(test_manifest PRIVATE rtprotect_integrity)
target_include_directories(test_manifest PRIVATE ${CMAKE_SOURCE_DIR})
add_test(NAME test_manifest COMMAND test_manifest)

# Links rtprotect_integrity_buildtools because this test must be able to
# PRODUCE signatures to test verification against -- see this file's note
# at the top of test_signing.cpp and integrity/CMakeLists.txt's header
# comment. No other test or example in this project links that target.
add_executable(test_signing test_signing.cpp)
target_link_libraries(test_signing PRIVATE rtprotect_integrity rtprotect_integrity_buildtools)
target_include_directories(test_signing PRIVATE ${CMAKE_SOURCE_DIR})
add_test(NAME test_signing COMMAND test_signing)

add_executable(test_bound_key test_bound_key.cpp)
target_link_libraries(test_bound_key PRIVATE rtprotect_integrity rtprotect_crypto)
target_include_directories(test_bound_key PRIVATE ${CMAKE_SOURCE_DIR})
add_test(NAME test_bound_key COMMAND test_bound_key)

add_executable(test_file_io test_file_io.cpp)
target_include_directories(test_file_io PRIVATE ${CMAKE_SOURCE_DIR})
add_test(NAME test_file_io COMMAND test_file_io)

add_executable(test_checked_arith_fallback test_checked_arith_fallback.cpp)
target_include_directories(test_checked_arith_fallback PRIVATE ${CMAKE_SOURCE_DIR})
add_test(NAME test_checked_arith_fallback COMMAND test_checked_arith_fallback)

add_executable(test_secure_buffer test_secure_buffer.cpp)
target_link_libraries(test_secure_buffer PRIVATE rtprotect_crypto)
target_include_directories(test_secure_buffer PRIVATE ${CMAKE_SOURCE_DIR})
add_test(NAME test_secure_buffer COMMAND test_secure_buffer)

add_executable(test_obfuscated_string test_obfuscated_string.cpp)
target_link_libraries(test_obfuscated_string PRIVATE rtprotect_obfuscation)
target_include_directories(test_obfuscated_string PRIVATE ${CMAKE_SOURCE_DIR})
add_test(NAME test_obfuscated_string COMMAND test_obfuscated_string)

add_executable(test_checksum_flattened test_checksum_flattened.cpp)
target_include_directories(test_checksum_flattened PRIVATE ${CMAKE_SOURCE_DIR})
add_test(NAME test_checksum_flattened COMMAND test_checksum_flattened)

# Phase 6 tests only exist when the experimental module itself is built --
# see top-level CMakeLists.txt's RTPROTECT_ENABLE_EXPERIMENTAL_RUNTIME_RECONSTRUCTION.
if(RTPROTECT_ENABLE_EXPERIMENTAL_RUNTIME_RECONSTRUCTION)
  add_executable(test_executable_memory test_executable_memory.cpp)
  target_link_libraries(test_executable_memory PRIVATE rtprotect_runtime)
  target_include_directories(test_executable_memory PRIVATE ${CMAKE_SOURCE_DIR})
  add_test(NAME test_executable_memory COMMAND test_executable_memory)

  add_executable(test_reconstructed_function test_reconstructed_function.cpp)
  target_link_libraries(test_reconstructed_function PRIVATE rtprotect_runtime rtprotect_crypto)
  target_include_directories(test_reconstructed_function PRIVATE ${CMAKE_SOURCE_DIR})
  add_test(NAME test_reconstructed_function COMMAND test_reconstructed_function)
endif()
