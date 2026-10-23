add_library(rtprotect_antitamper STATIC
    anti_debug.cpp
    anti_dump.cpp
    dynamic_import.cpp
    env_detect.cpp
    risk_policy.cpp
    section_protector.cpp
)
target_include_directories(rtprotect_antitamper PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(rtprotect_antitamper PUBLIC rtprotect_crypto rtprotect_integrity)
