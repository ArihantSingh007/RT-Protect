# This whole directory is only ever reached when
# RTPROTECT_ENABLE_EXPERIMENTAL_RUNTIME_RECONSTRUCTION is explicitly turned
# ON (see top-level CMakeLists.txt) -- implementing the brief's instruction
# that this technique be "an isolated, opt-in research experiment" at the
# strongest level available: it is not even compiled into a default build.

add_library(rtprotect_runtime STATIC
    executable_memory.cpp
)
target_include_directories(rtprotect_runtime PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(rtprotect_runtime PUBLIC rtprotect_crypto)

if(MSVC)
  # Control Flow Guard (/guard:cf, enabled process-wide for Release builds
  # by the top-level CMakeLists.txt) will fail-fast-crash an indirect call
  # into memory that was made executable at runtime, unless that region's
  # entry point is registered as a valid CFG call target via
  # SetProcessValidCallTargetsForMappedView -- which this experimental
  # module does not implement (see docs/RUNTIME_RECONSTRUCTION.md's CFG
  # section). Rather than ship a target that would silently crash under
  # CFG enforcement, CFG is explicitly disabled for this target and
  # anything linking it. This is itself a real, documented security
  # trade-off (losing CFG's protection to gain this questionable
  # capability) -- exactly the kind of cost this phase's documentation is
  # supposed to surface, not hide.
  target_compile_options(rtprotect_runtime PUBLIC $<$<CONFIG:Release>:/guard:cf->)
  target_link_options(rtprotect_runtime PUBLIC $<$<CONFIG:Release>:/guard:cf->)
endif()
