add_library(rtprotect_tooling STATIC
    integration_engine.cpp
)
target_include_directories(rtprotect_tooling PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(rtprotect_tooling PUBLIC
    rtprotect_crypto
    rtprotect_integrity
    rtprotect_integrity_buildtools
    rtprotect_licensing
    rtprotect_licensing_buildtools
    rtprotect_antitamper
)

add_executable(rtprotect-tool main.cpp)
target_include_directories(rtprotect-tool PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(rtprotect-tool PRIVATE
    rtprotect_tooling
)
rtprotect_strip_in_release(rtprotect-tool)
