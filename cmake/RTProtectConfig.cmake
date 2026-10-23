# cmake/RTProtectConfig.cmake
#
# CMake Package Configuration for RTProtect SDK (Windows x64)

cmake_minimum_required(VERSION 3.20)

get_filename_component(RTPROTECT_PACKAGE_PREFIX "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)

set(RTProtect_INCLUDE_DIRS "${RTPROTECT_PACKAGE_PREFIX}/include")
set(RTProtect_LIBRARIES_DIR "${RTPROTECT_PACKAGE_PREFIX}/lib")

macro(_rtprotect_add_target target_name lib_name deps sys_libs)
  if(NOT TARGET RTProtect::${target_name})
    find_library(_RTPROTECT_${target_name}_LIB
      NAMES ${lib_name} lib${lib_name}
      PATHS "${RTProtect_LIBRARIES_DIR}"
      NO_DEFAULT_PATH
    )

    add_library(RTProtect::${target_name} STATIC IMPORTED)
    set_target_properties(RTProtect::${target_name} PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${RTProtect_INCLUDE_DIRS}"
      INTERFACE_COMPILE_FEATURES "cxx_std_20"
    )

    if(_RTPROTECT_${target_name}_LIB)
      set_target_properties(RTProtect::${target_name} PROPERTIES
        IMPORTED_LOCATION "${_RTPROTECT_${target_name}_LIB}"
      )
    endif()

    if(WIN32)
      target_compile_definitions(RTProtect::${target_name} INTERFACE NOMINMAX)
    endif()

    if(NOT "${deps}" STREQUAL "")
      target_link_libraries(RTProtect::${target_name} INTERFACE ${deps})
    endif()

    if(NOT "${sys_libs}" STREQUAL "")
      target_link_libraries(RTProtect::${target_name} INTERFACE ${sys_libs})
    endif()
  endif()
endmacro()

# Locate OpenSSL if packaged or in system
if(EXISTS "${RTPROTECT_PACKAGE_PREFIX}/third_party/openssl")
  set(OPENSSL_ROOT_DIR "${RTPROTECT_PACKAGE_PREFIX}/third_party/openssl")
endif()
find_package(OpenSSL QUIET)

set(_OPENSSL_CRYPTO_TARGET "")
if(TARGET OpenSSL::Crypto)
  set(_OPENSSL_CRYPTO_TARGET "OpenSSL::Crypto")
endif()

# Define imported targets
_rtprotect_add_target(rtprotect_crypto rtprotect_crypto "" "${_OPENSSL_CRYPTO_TARGET}")
_rtprotect_add_target(rtprotect_integrity rtprotect_integrity "RTProtect::rtprotect_crypto" "${_OPENSSL_CRYPTO_TARGET}")
_rtprotect_add_target(rtprotect_vm rtprotect_vm "" "")
_rtprotect_add_target(rtprotect_licensing rtprotect_licensing "RTProtect::rtprotect_crypto;RTProtect::rtprotect_integrity" "ws2_32;crypt32;iphlpapi;wbemuuid;ntdll;shlwapi")
_rtprotect_add_target(rtprotect_antitamper rtprotect_antitamper "RTProtect::rtprotect_integrity" "ntdll;psapi;advapi32;iphlpapi")
_rtprotect_add_target(rtprotect_tooling rtprotect_tooling "RTProtect::rtprotect_integrity;RTProtect::rtprotect_crypto" "")

if(NOT TARGET RTProtect::rtprotect_obfuscation)
  add_library(RTProtect::rtprotect_obfuscation INTERFACE IMPORTED)
  set_target_properties(RTProtect::rtprotect_obfuscation PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${RTProtect_INCLUDE_DIRS}"
    INTERFACE_COMPILE_FEATURES "cxx_std_20"
  )
endif()

set(RTProtect_FOUND TRUE)
