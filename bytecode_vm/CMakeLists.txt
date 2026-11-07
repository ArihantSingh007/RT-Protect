add_library(rtprotect_vm STATIC
    verifier.cpp
    vm.cpp
    serialize.cpp
    opcode_map.cpp
    compiler.cpp
    program_registry.cpp
)

target_include_directories(rtprotect_vm PUBLIC
    ${CMAKE_SOURCE_DIR}
)

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    # Scoped warning suppression: silence libstdc++ false positives under -O3 during std::vector reallocation
    target_compile_options(rtprotect_vm PRIVATE -Wno-stringop-overflow -Wno-free-nonheap-object)
endif()
