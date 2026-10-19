add_library(rtprotect_antitamper STATIC
    anti_debug.cpp
    env_detect.cpp
    risk_policy.cpp
)
target_include_directories(rtprotect_antitamper PUBLIC ${CMAKE_SOURCE_DIR})
