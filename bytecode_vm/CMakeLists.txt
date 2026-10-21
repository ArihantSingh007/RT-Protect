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
