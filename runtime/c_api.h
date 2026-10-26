#pragma once

#include <cstdint>
#include <cstddef>

#if defined(_WIN32) || defined(__CYGWIN__)
  #if defined(RTPROTECT_RUNTIME_EXPORTS)
    #define RTPROTECT_API __declspec(dllexport)
  #else
    #define RTPROTECT_API __declspec(dllimport)
  #endif
#else
  #if defined(RTPROTECT_RUNTIME_EXPORTS)
    #define RTPROTECT_API __attribute__((visibility("default")))
  #else
    #define RTPROTECT_API
  #endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Retrieves the local machine-bound 64-character hardware fingerprint.
 * @param buffer Output buffer to receive the null-terminated hex string.
 * @param buffer_len Size of buffer in bytes (must be at least 65 bytes).
 * @return Number of characters written (excluding null terminator), or -1 on error.
 */
RTPROTECT_API int rtprotect_get_hardware_id(char* buffer, int buffer_len);

/**
 * @brief Assesses the runtime host environment for debuggers, dumpers, and hooks.
 * @return Normalized risk score between 0.0 (clean) and 1.0 (compromised).
 */
RTPROTECT_API double rtprotect_assess_environment_risk(void);

/**
 * @brief Verifies a signed release manifest against a 32-byte Ed25519 vendor public key.
 * Looks for <manifest_path>.sig adjacent to the manifest.
 * @param manifest_path Null-terminated path to the release.manifest file.
 * @param pub_key 32-byte array containing the Ed25519 public key.
 * @return 1 if valid, 0 if invalid or file not found.
 */
RTPROTECT_API int rtprotect_verify_manifest(const char* manifest_path, const uint8_t* pub_key);

/**
 * @brief Validates a machine-bound client license file.
 * @param license_path Null-terminated path to client.license.
 * @param pub_key 32-byte array containing the Ed25519 vendor license verification key.
 * @param expected_product_id Null-terminated string containing expected product ID.
 * @return 1 if valid, 0 if invalid/expired/hardware mismatch.
 */
RTPROTECT_API int rtprotect_verify_license(const char* license_path, const uint8_t* pub_key, const char* expected_product_id);

#ifdef __cplusplus
}
#endif
