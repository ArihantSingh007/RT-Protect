add_library(rtprotect_licensing STATIC
    license.cpp
    license_verifier.cpp
    hardware_id.cpp
    update_manifest.cpp
    activation.cpp
)
target_include_directories(rtprotect_licensing PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(rtprotect_licensing PUBLIC rtprotect_integrity rtprotect_crypto OpenSSL::Crypto)

add_library(rtprotect_licensing_buildtools STATIC
    license_signer.cpp
    activation_server.cpp
)
target_include_directories(rtprotect_licensing_buildtools PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(rtprotect_licensing_buildtools PUBLIC rtprotect_licensing rtprotect_integrity_buildtools)
