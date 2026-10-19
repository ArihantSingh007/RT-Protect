cmake_minimum_required(VERSION 3.20)
project(SampleClientApp CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(sample_client_app
    main.cpp
)

# --- Added by RTProtect Integration Tool ---
include_directories("C:/Users/Arihant Singh/Downloads/rtprotect_hardening_WIP")
include_directories("C:/Users/Arihant Singh/Downloads/rtprotect_hardening_WIP/third_party/openssl/include")
target_link_directories(sample_client_app PRIVATE
    "C:/Users/Arihant Singh/Downloads/rtprotect_hardening_WIP/build/integrity"
    "C:/Users/Arihant Singh/Downloads/rtprotect_hardening_WIP/build/licensing"
    "C:/Users/Arihant Singh/Downloads/rtprotect_hardening_WIP/build/antitamper"
    "C:/Users/Arihant Singh/Downloads/rtprotect_hardening_WIP/build/crypto"
    "C:/Users/Arihant Singh/Downloads/rtprotect_hardening_WIP/third_party/openssl/lib"
)
target_sources(sample_client_app PRIVATE rtprotect_runtime_glue.cpp)
target_link_libraries(sample_client_app PRIVATE
    rtprotect_licensing
    rtprotect_integrity
    rtprotect_antitamper
    rtprotect_crypto
    "C:/Users/Arihant Singh/Downloads/rtprotect_hardening_WIP/third_party/openssl/lib/libcrypto.lib"
    iphlpapi
    ws2_32
)

# Compiler Hardening Profile: balanced
if(NOT MSVC)
  add_compile_options(-fstack-protector)
endif()
