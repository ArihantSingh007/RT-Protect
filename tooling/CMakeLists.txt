add_library(rtprotect_tooling STATIC
    integration_engine.cpp
    cxx_ast_scanner.cpp
    unreal_integration.cpp
)
target_include_directories(rtprotect_tooling PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(rtprotect_tooling PUBLIC
    rtprotect_crypto
    rtprotect_integrity
    rtprotect_integrity_buildtools
    rtprotect_licensing
    rtprotect_licensing_buildtools
    rtprotect_antitamper
    rtprotect_vm
    rtprotect_obfuscation
)

add_executable(rtprotect-tool main.cpp)
target_include_directories(rtprotect-tool PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(rtprotect-tool PRIVATE
    rtprotect_tooling
)
rtprotect_strip_in_release(rtprotect-tool)

add_executable(rtprotect-activation-server activation_server_main.cpp)
target_include_directories(rtprotect-activation-server PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(rtprotect-activation-server PRIVATE
    rtprotect_tooling
    rtprotect_licensing_buildtools
)
rtprotect_strip_in_release(rtprotect-activation-server)

if(WIN32 AND EXISTS "${CMAKE_SOURCE_DIR}/third_party/openssl/bin")
  file(COPY "${CMAKE_SOURCE_DIR}/third_party/openssl/bin/libcrypto-3-x64.dll"
            "${CMAKE_SOURCE_DIR}/third_party/openssl/bin/libssl-3-x64.dll"
       DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
endif()
