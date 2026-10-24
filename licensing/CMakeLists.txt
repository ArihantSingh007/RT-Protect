add_library(rtprotect_licensing STATIC
    license.cpp
    license_verifier.cpp
    hardware_id.cpp
    update_manifest.cpp
    activation.cpp
    activation_client.cpp
    countermeasure_config.cpp
    secure_storage.cpp
    trusted_time.cpp
)
target_include_directories(rtprotect_licensing PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(rtprotect_licensing PUBLIC rtprotect_integrity rtprotect_crypto OpenSSL::Crypto OpenSSL::SSL winhttp ws2_32 crypt32)

add_library(rtprotect_licensing_buildtools STATIC
    license_signer.cpp
    activation_server.cpp
    activation_database.cpp
    activation_service.cpp
    activation_server_http.cpp
    secrets_manager.cpp
    abuse_analytics.cpp
)
target_include_directories(rtprotect_licensing_buildtools PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(rtprotect_licensing_buildtools PUBLIC rtprotect_licensing rtprotect_integrity_buildtools OpenSSL::SSL ws2_32 crypt32)
