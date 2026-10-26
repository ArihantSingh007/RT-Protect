add_library(rtprotect_runtime SHARED
    c_api.cpp
)

target_compile_definitions(rtprotect_runtime PRIVATE RTPROTECT_RUNTIME_EXPORTS)
target_include_directories(rtprotect_runtime PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(rtprotect_runtime PRIVATE
    rtprotect_licensing
    rtprotect_integrity
    rtprotect_antitamper
    rtprotect_crypto
    rtprotect_tooling
    OpenSSL::Crypto
    OpenSSL::SSL
    $<$<PLATFORM_ID:Windows>:iphlpapi>
    $<$<PLATFORM_ID:Windows>:ws2_32>
    $<$<PLATFORM_ID:Windows>:winhttp>
    $<$<PLATFORM_ID:Windows>:crypt32>
)

rtprotect_strip_in_release(rtprotect_runtime)

# Optional experimental runtime reconstruction target
if(RTPROTECT_ENABLE_EXPERIMENTAL_RUNTIME_RECONSTRUCTION)
  add_library(rtprotect_runtime_reconstruction STATIC
      executable_memory.cpp
  )
  target_include_directories(rtprotect_runtime_reconstruction PUBLIC ${CMAKE_SOURCE_DIR})
  target_link_libraries(rtprotect_runtime_reconstruction PUBLIC rtprotect_crypto)
  if(MSVC)
    target_compile_options(rtprotect_runtime_reconstruction PUBLIC $<$<CONFIG:Release>:/guard:cf->)
    target_link_options(rtprotect_runtime_reconstruction PUBLIC $<$<CONFIG:Release>:/guard:cf->)
  endif()
endif()
