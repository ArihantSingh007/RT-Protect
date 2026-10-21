add_library(rtprotect_licensing STATIC
    license.cpp
    license_verifier.cpp
    hardware_id.cpp
    update_manifest.cpp
    activation.cpp
    activation_client.cpp
)
target_include_directories(rtprotect_licensing PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(rtprotect_licensing PUBLIC rtprotect_integrity rtprotect_crypto OpenSSL::Crypto)
if(WIN32)
    target_link_libraries(rtprotect_licensing PUBLIC winhttp ws2_32)
endif()

add_library(rtprotect_licensing_buildtools STATIC
    license_signer.cpp
    activation_server.cpp
    activation_database.cpp
    activation_service.cpp
    activation_server_http.cpp
)
target_include_directories(rtprotect_licensing_buildtools PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(rtprotect_licensing_buildtools PUBLIC rtprotect_licensing rtprotect_integrity_buildtools)
if(WIN32)
    target_link_libraries(rtprotect_licensing_buildtools PUBLIC ws2_32)
endif()
