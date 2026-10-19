# obfuscation/ is currently header-only (obfuscated_string.h,
# checksum_flattened.h), so there's no .cpp to compile into a static
# library -- this INTERFACE target exists purely so other targets can
# depend on it uniformly (target_link_libraries(... rtprotect_obfuscation))
# the same way they depend on rtprotect_crypto or rtprotect_vm, and so the
# include path is set in one place.
add_library(rtprotect_obfuscation INTERFACE)
target_include_directories(rtprotect_obfuscation INTERFACE ${CMAKE_SOURCE_DIR})

# Demo binaries for docs/OBFUSCATION.md's empirical "does this actually
# hide the string" check (see that doc for the real, as-run `strings`
# output). Built with the same optimization/visibility settings whichever
# CMAKE_BUILD_TYPE is active, so the two are a fair comparison -- the point
# is to compare them to EACH OTHER at matching settings, not to claim a
# specific absolute result independent of build type.
add_executable(demo_plain_secret demo/plain_secret_demo.cpp)
rtprotect_strip_in_release(demo_plain_secret)

add_executable(demo_obfuscated_secret demo/obfuscated_secret_demo.cpp)
target_link_libraries(demo_obfuscated_secret PRIVATE rtprotect_obfuscation)
rtprotect_strip_in_release(demo_obfuscated_secret)
