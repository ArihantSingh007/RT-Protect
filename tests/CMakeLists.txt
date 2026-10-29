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

add_executable(test_license test_license.cpp)
target_link_libraries(test_license PRIVATE rtprotect_licensing rtprotect_licensing_buildtools rtprotect_integrity_buildtools)
target_include_directories(test_license PRIVATE ${CMAKE_SOURCE_DIR})
add_test(NAME test_license COMMAND test_license)

add_executable(test_activation test_activation.cpp)
target_link_libraries(test_activation PRIVATE rtprotect_licensing rtprotect_licensing_buildtools rtprotect_integrity_buildtools)
target_include_directories(test_activation PRIVATE ${CMAKE_SOURCE_DIR})
add_test(NAME test_activation COMMAND test_activation)

add_executable(test_activation_service test_activation_service.cpp)
target_link_libraries(test_activation_service PRIVATE
    rtprotect_licensing
    rtprotect_licensing_buildtools
    rtprotect_integrity_buildtools
    rtprotect_integrity
    rtprotect_crypto
)
if(WIN32)
    target_link_libraries(test_activation_service PRIVATE winhttp ws2_32)
endif()
target_include_directories(test_activation_service PRIVATE ${CMAKE_SOURCE_DIR})
add_test(NAME test_activation_service COMMAND test_activation_service)

add_executable(test_secrets_manager test_secrets_manager.cpp)
target_link_libraries(test_secrets_manager PRIVATE
    rtprotect_licensing
    rtprotect_licensing_buildtools
    rtprotect_integrity_buildtools
    rtprotect_integrity
    rtprotect_crypto
)
if(WIN32)
    target_link_libraries(test_secrets_manager PRIVATE crypt32 shell32)
endif()
target_include_directories(test_secrets_manager PRIVATE ${CMAKE_SOURCE_DIR})
add_test(NAME test_secrets_manager COMMAND test_secrets_manager)

add_executable(test_trusted_time test_trusted_time.cpp)
target_link_libraries(test_trusted_time PRIVATE rtprotect_licensing)
target_include_directories(test_trusted_time PRIVATE ${CMAKE_SOURCE_DIR})
add_test(NAME test_trusted_time COMMAND test_trusted_time)

add_executable(test_hardware_id test_hardware_id.cpp)
target_link_libraries(test_hardware_id PRIVATE rtprotect_licensing)
target_include_directories(test_hardware_id PRIVATE ${CMAKE_SOURCE_DIR})
add_test(NAME test_hardware_id COMMAND test_hardware_id)

add_executable(test_update_manifest test_update_manifest.cpp)
target_link_libraries(test_update_manifest PRIVATE rtprotect_licensing rtprotect_licensing_buildtools rtprotect_integrity_buildtools)
target_include_directories(test_update_manifest PRIVATE ${CMAKE_SOURCE_DIR})
add_test(NAME test_update_manifest COMMAND test_update_manifest)

add_executable(test_antitamper test_antitamper.cpp)
target_link_libraries(test_antitamper PRIVATE rtprotect_antitamper rtprotect_licensing)
target_include_directories(test_antitamper PRIVATE ${CMAKE_SOURCE_DIR})
add_test(NAME test_antitamper COMMAND test_antitamper)

add_executable(test_opcode_map test_opcode_map.cpp)
target_link_libraries(test_opcode_map PRIVATE rtprotect_vm)
target_include_directories(test_opcode_map PRIVATE ${CMAKE_SOURCE_DIR})
add_test(NAME test_opcode_map COMMAND test_opcode_map)

add_executable(test_integration_engine test_integration_engine.cpp)
target_link_libraries(test_integration_engine PRIVATE rtprotect_tooling)
target_include_directories(test_integration_engine PRIVATE ${CMAKE_SOURCE_DIR})
add_test(NAME test_integration_engine COMMAND test_integration_engine)

add_executable(test_unreal_integration test_unreal_integration.cpp)
target_link_libraries(test_unreal_integration PRIVATE rtprotect_tooling)
target_include_directories(test_unreal_integration PRIVATE ${CMAKE_SOURCE_DIR})
add_test(NAME test_unreal_integration COMMAND test_unreal_integration)

add_executable(test_pe_protector test_pe_protector.cpp)
target_link_libraries(test_pe_protector PRIVATE rtprotect_tooling rtprotect_antitamper)
target_include_directories(test_pe_protector PRIVATE ${CMAKE_SOURCE_DIR})
add_test(NAME test_pe_protector COMMAND test_pe_protector)

add_executable(test_c_api test_c_api.cpp)
target_link_libraries(test_c_api PRIVATE rtprotect_runtime)
target_include_directories(test_c_api PRIVATE ${CMAKE_SOURCE_DIR})
add_custom_command(TARGET test_c_api POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
  $<TARGET_FILE:rtprotect_runtime>
  $<TARGET_FILE_DIR:test_c_api>
)
if(WIN32)
  add_custom_command(TARGET test_c_api POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    $<TARGET_FILE:rtprotect_runtime>
    $<TARGET_FILE_DIR:test_c_api>/rtprotect_runtime.dll
  )
endif()
add_test(NAME test_c_api COMMAND test_c_api)

find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_FOUND)
  add_test(NAME test_python_sdk
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/test_python_sdk.py"
  )
  set_tests_properties(test_python_sdk PROPERTIES
    ENVIRONMENT "RTPROTECT_RUNTIME_DLL=$<TARGET_FILE:rtprotect_runtime>"
  )
endif()

find_program(RTPROTECT_CSC_EXECUTABLE NAMES csc PATHS "C:/Windows/Microsoft.NET/Framework64/v4.0.30319" "C:/Windows/Microsoft.NET/Framework/v4.0.30319")
if(RTPROTECT_CSC_EXECUTABLE)
  file(TO_NATIVE_PATH "${CMAKE_SOURCE_DIR}/sdk/dotnet/RTProtect.cs" RTPROTECT_CS_NATIVE)
  file(TO_NATIVE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/test_dotnet_sdk.cs" RTPROTECT_TEST_CS_NATIVE)
  file(TO_NATIVE_PATH "${CMAKE_CURRENT_BINARY_DIR}/test_dotnet_sdk.exe" RTPROTECT_TEST_DOTNET_EXE_NATIVE)
  add_custom_command(
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/test_dotnet_sdk.exe"
    COMMAND "${RTPROTECT_CSC_EXECUTABLE}" /nologo /target:exe
            /out:"${RTPROTECT_TEST_DOTNET_EXE_NATIVE}"
            "${RTPROTECT_CS_NATIVE}"
            "${RTPROTECT_TEST_CS_NATIVE}"
    DEPENDS "${CMAKE_SOURCE_DIR}/sdk/dotnet/RTProtect.cs" "${CMAKE_CURRENT_SOURCE_DIR}/test_dotnet_sdk.cs"
  )
  add_custom_target(build_test_dotnet_sdk ALL DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/test_dotnet_sdk.exe")
  add_test(NAME test_dotnet_sdk COMMAND "${CMAKE_CURRENT_BINARY_DIR}/test_dotnet_sdk.exe")
  set_tests_properties(test_dotnet_sdk PROPERTIES
    ENVIRONMENT "RTPROTECT_RUNTIME_DLL=$<TARGET_FILE:rtprotect_runtime>"
  )
endif()

# Exercise the shipped consumer sample through the actual integration CLI,
# generated VM wrapper, runtime authorization path, and tamper rejection.
find_program(RTPROTECT_POWERSHELL_EXECUTABLE NAMES pwsh powershell)
if(RTPROTECT_POWERSHELL_EXECUTABLE)
  add_test(NAME test_sample_e2e
    COMMAND "${RTPROTECT_POWERSHELL_EXECUTABLE}"
            -NoProfile -ExecutionPolicy Bypass
            -File "${CMAKE_CURRENT_SOURCE_DIR}/test_sample_e2e.ps1"
            -Tool "$<TARGET_FILE:rtprotect-tool>"
            -SampleSource "${CMAKE_SOURCE_DIR}/examples/sample_client_app"
            -RtprotectRoot "${CMAKE_SOURCE_DIR}"
            -BuildRoot "${CMAKE_BINARY_DIR}"
            -Generator "${CMAKE_GENERATOR}"
            -Config "$<CONFIG>")
  set_tests_properties(test_sample_e2e PROPERTIES TIMEOUT 180)
endif()

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

if(WIN32 AND EXISTS "${CMAKE_SOURCE_DIR}/third_party/openssl/bin")
  file(GLOB OPENSSL_DLLS "${CMAKE_SOURCE_DIR}/third_party/openssl/bin/*.dll")
  if(OPENSSL_DLLS)
    file(COPY ${OPENSSL_DLLS} DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
    file(COPY ${OPENSSL_DLLS} DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/Debug")
    file(COPY ${OPENSSL_DLLS} DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/Release")
  endif()
endif()
