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
