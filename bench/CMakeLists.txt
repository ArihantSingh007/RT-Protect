add_executable(rtprotect-bench main.cpp)
target_include_directories(rtprotect-bench PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(rtprotect-bench PRIVATE rtprotect_vm rtprotect_crypto)
rtprotect_strip_in_release(rtprotect-bench)

if(WIN32 AND EXISTS "${CMAKE_SOURCE_DIR}/third_party/openssl/bin")
  file(COPY "${CMAKE_SOURCE_DIR}/third_party/openssl/bin/libcrypto-3-x64.dll"
            "${CMAKE_SOURCE_DIR}/third_party/openssl/bin/libssl-3-x64.dll"
       DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
  file(COPY "${CMAKE_SOURCE_DIR}/third_party/openssl/bin/libcrypto-3-x64.dll"
            "${CMAKE_SOURCE_DIR}/third_party/openssl/bin/libssl-3-x64.dll"
       DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/Debug")
  file(COPY "${CMAKE_SOURCE_DIR}/third_party/openssl/bin/libcrypto-3-x64.dll"
            "${CMAKE_SOURCE_DIR}/third_party/openssl/bin/libssl-3-x64.dll"
       DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/Release")
endif()
