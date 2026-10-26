cmake_minimum_required(VERSION 3.20)
project(ConsumerSample CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(WIN32)
  add_compile_definitions(NOMINMAX)
endif()

# Find RTProtect package exported targets
find_package(RTProtect CONFIG REQUIRED)

add_executable(consumer_sample main.cpp)

target_link_libraries(consumer_sample PRIVATE
    RTProtect::rtprotect_licensing
    RTProtect::rtprotect_antitamper
    RTProtect::rtprotect_vm
    RTProtect::rtprotect_integrity
    RTProtect::rtprotect_crypto
)

if(WIN32)
  # Automatically locate and deploy bundled OpenSSL runtime DLLs to output directory
  set(RTPROTECT_OPENSSL_SEARCH_PATHS
    "${CMAKE_CURRENT_SOURCE_DIR}/../../third_party/openssl/bin"
    "${RTProtect_DIR}/../../../third_party/openssl/bin"
    "${RTProtect_DIR}/../../third_party/openssl/bin"
    "${OPENSSL_ROOT_DIR}/bin"
  )
  foreach(dir IN LISTS RTPROTECT_OPENSSL_SEARCH_PATHS)
    if(EXISTS "${dir}")
      file(GLOB CONSUMER_OPENSSL_DLLS "${dir}/*.dll")
      if(CONSUMER_OPENSSL_DLLS)
        add_custom_command(TARGET consumer_sample POST_BUILD
          COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CONSUMER_OPENSSL_DLLS} $<TARGET_FILE_DIR:consumer_sample>
        )
        break()
      endif()
    endif()
  endforeach()
endif()
