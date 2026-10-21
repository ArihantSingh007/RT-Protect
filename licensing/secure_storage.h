// licensing/secure_storage.h
//
// Platform-native secure storage for sensitive cryptographic credentials and activation tokens.
// Uses Windows DPAPI (CryptProtectData/CryptUnprotectData) on Windows,
// macOS Keychain Services on Apple platforms, libsecret on desktop Linux,
// and hardware-bound AEAD authenticated encryption as headless/container fallback.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace rtprotect::licensing {

enum class SecureStorageBackend : std::uint8_t {
  kWindowsDpapi = 1,
  kMacKeychain = 2,
  kLinuxLibsecret = 3,
  kFallbackHwBoundEncryptedFile = 4
};

class SecureStorage {
 public:
  // Stores raw payload bytes securely bound to the OS user/vault under key_name.
  // Returns true on success, false otherwise.
  static bool Store(const std::string& key_name,
                    const std::vector<std::uint8_t>& data,
                    const std::string& description = "rtprotect_token");

  // Retrieves decrypted payload bytes stored under key_name.
  // Returns std::nullopt if not found, corrupted, or decryption fails.
  static std::optional<std::vector<std::uint8_t>> Load(const std::string& key_name);

  // Deletes the stored credential/file for key_name.
  // Returns true if removed (or already absent), false on filesystem/vault error.
  static bool Delete(const std::string& key_name);

  // Returns the active secure storage backend on this platform/environment.
  static SecureStorageBackend GetActiveBackend();

  // Resolves the file storage path on disk for file-backed storage mechanisms
  static std::string GetStorageFilePath(const std::string& key_name);

  // Fallback hardware-bound AES-256-GCM encryption helpers (accessible for headless fallback and tests)
  static std::optional<std::vector<std::uint8_t>> EncryptFallback(
      const std::string& key_name,
      const std::vector<std::uint8_t>& plaintext);
  static std::optional<std::vector<std::uint8_t>> DecryptFallback(
      const std::string& key_name,
      const std::vector<std::uint8_t>& ciphertext);
};

}  // namespace rtprotect::licensing
