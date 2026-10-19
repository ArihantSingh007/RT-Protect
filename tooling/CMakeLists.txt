add_executable(rtprotect-tool main.cpp)
target_include_directories(rtprotect-tool PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(rtprotect-tool PRIVATE
    rtprotect_crypto
    rtprotect_integrity
    rtprotect_integrity_buildtools
)
rtprotect_strip_in_release(rtprotect-tool)
