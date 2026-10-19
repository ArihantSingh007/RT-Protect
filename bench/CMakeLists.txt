add_executable(rtprotect-bench main.cpp)
target_include_directories(rtprotect-bench PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(rtprotect-bench PRIVATE rtprotect_vm rtprotect_crypto)
rtprotect_strip_in_release(rtprotect-bench)
