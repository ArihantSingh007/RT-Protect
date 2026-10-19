add_library(rtprotect_crypto STATIC
    aead.cpp
    kdf.cpp
)

target_include_directories(rtprotect_crypto PUBLIC
    ${CMAKE_SOURCE_DIR}
)

target_link_libraries(rtprotect_crypto PUBLIC OpenSSL::Crypto)
