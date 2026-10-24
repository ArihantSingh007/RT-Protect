// licensing/secure_storage.cpp
//
// Windows Data Protection API (DPAPI) secure storage implementation.
// Protects activation tokens and cryptographic roots bound to user credentials.

#include "licensing/secure_storage.h"

#include <chrono>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <vector>

#include "crypto/aead.h"
#include "crypto/kdf.h"
#include "integrity/sha256.h"
#include "licensing/hardware_id.h"
#include "tooling/file_io.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>

namespace rtprotect::licensing {

namespace {

constexpr std::uint8_t kMagic[4] = {'R', 'T', 'S', 'S'};
constexpr std::uint8_t kStorageVersion = 1;

bool s_require_dpapi = false;

std::string BytesToHex(const std::uint8_t* data, std::size_t len) {
  std::ostringstream ss;
  for (std::size_t i = 0; i < len; ++i) {
    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
  }
  return ss.str();
}

std::string SanitizeKeyNameLegacy(const std::string& key_name) {
  std::string s = key_name.empty() ? "default" : key_name;
  for (char& c : s) {
    if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_') {
      c = '_';
    }
  }
  return s;
}

std::string SanitizeKeyName(const std::string& key_name) {
  std::string prefix;
  for (char c : key_name) {
    if (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_') {
      prefix += c;
      if (prefix.size() >= 24) break;
    }
  }
  if (prefix.empty()) prefix = "item";
  auto hash = integrity::Sha256(reinterpret_cast<const std::uint8_t*>(key_name.data()), key_name.size());
  std::string hash_hex = hash.has_value() ? BytesToHex(hash->data(), 16) : "0000000000000000";
  return prefix + "_" + hash_hex;
}

std::vector<std::uint8_t> PackContainer(SecureStorageBackend backend, const std::vector<std::uint8_t>& payload) {
  std::vector<std::uint8_t> out;
  out.reserve(12 + payload.size());
  out.push_back(kMagic[0]);
  out.push_back(kMagic[1]);
  out.push_back(kMagic[2]);
  out.push_back(kMagic[3]);
  out.push_back(kStorageVersion);
  out.push_back(static_cast<std::uint8_t>(backend));
  out.push_back(0);  // reserved
  out.push_back(0);  // reserved

  std::uint32_t len = static_cast<std::uint32_t>(payload.size());
  out.push_back(static_cast<std::uint8_t>(len & 0xFF));
  out.push_back(static_cast<std::uint8_t>((len >> 8) & 0xFF));
  out.push_back(static_cast<std::uint8_t>((len >> 16) & 0xFF));
  out.push_back(static_cast<std::uint8_t>((len >> 24) & 0xFF));

  out.insert(out.end(), payload.begin(), payload.end());
  return out;
}

struct ParsedContainer {
  SecureStorageBackend backend;
  std::vector<std::uint8_t> payload;
};

std::optional<ParsedContainer> UnpackContainer(const std::vector<std::uint8_t>& bytes) {
  if (bytes.size() < 12) return std::nullopt;
  if (std::memcmp(bytes.data(), kMagic, 4) != 0) return std::nullopt;
  if (bytes[4] != kStorageVersion) return std::nullopt;

  SecureStorageBackend backend = static_cast<SecureStorageBackend>(bytes[5]);
  std::uint32_t len = static_cast<std::uint32_t>(bytes[8]) |
                      (static_cast<std::uint32_t>(bytes[9]) << 8) |
                      (static_cast<std::uint32_t>(bytes[10]) << 16) |
                      (static_cast<std::uint32_t>(bytes[11]) << 24);

  if (bytes.size() != 12 + len) return std::nullopt;
  std::vector<std::uint8_t> payload(bytes.begin() + 12, bytes.begin() + 12 + len);
  return ParsedContainer{backend, std::move(payload)};
}

std::optional<crypto::Aes256Key> DeriveFallbackKey(const std::string& key_name, const std::string& info_tag) {
  std::string hwid = GetLocalHardwareId();
  crypto::SecureBuffer sec_hwid(reinterpret_cast<const std::uint8_t*>(hwid.data()), hwid.size());
  std::vector<std::uint8_t> salt;
  if (!key_name.empty()) {
    salt.assign(reinterpret_cast<const std::uint8_t*>(key_name.data()),
                reinterpret_cast<const std::uint8_t*>(key_name.data()) + key_name.size());
  } else {
    salt = {'R', 'T', 'P', 'r', 'o', 't', 'e', 'c', 't', 'S', 'e', 'c', 'u', 'r', 'e'};
  }
  auto derived = crypto::Hkdf::DeriveKey(sec_hwid, salt, info_tag, crypto::kAes256KeyLen);
  if (!derived.has_value()) return std::nullopt;
  return crypto::Aes256Key::FromBytes(derived->data(), derived->size());
}

}  // namespace

std::string SecureStorage::GetStorageFilePath(const std::string& key_name) {
  std::string sanitized = SanitizeKeyName(key_name);
  std::filesystem::path base_dir;
  const char* override_dir = std::getenv("RTPROTECT_ACTIVATION_DIR");
  if (override_dir && override_dir[0] != '\0') {
    base_dir = std::filesystem::path(override_dir);
  } else {
    const char* local_app_data = std::getenv("LOCALAPPDATA");
    if (local_app_data && local_app_data[0] != '\0') {
      base_dir = std::filesystem::path(local_app_data) / "RTProtect";
    } else {
      const char* user_prof = std::getenv("USERPROFILE");
      if (user_prof && user_prof[0] != '\0') {
        base_dir = std::filesystem::path(user_prof) / "AppData" / "Local" / "RTProtect";
      } else {
        base_dir = std::filesystem::path(".rtprotect_activation");
      }
    }
  }

  std::error_code ec;
  std::filesystem::create_directories(base_dir, ec);
  return (base_dir / (sanitized + ".dat")).string();
}

std::string SecureStorage::GetLegacyStorageFilePath(const std::string& key_name) {
  std::string sanitized = SanitizeKeyNameLegacy(key_name);
  std::filesystem::path base_dir;
  const char* override_dir = std::getenv("RTPROTECT_ACTIVATION_DIR");
  if (override_dir && override_dir[0] != '\0') {
    base_dir = std::filesystem::path(override_dir);
  } else {
    const char* local_app_data = std::getenv("LOCALAPPDATA");
    if (local_app_data && local_app_data[0] != '\0') {
      base_dir = std::filesystem::path(local_app_data) / "RTProtect";
    } else {
      const char* user_prof = std::getenv("USERPROFILE");
      if (user_prof && user_prof[0] != '\0') {
        base_dir = std::filesystem::path(user_prof) / "AppData" / "Local" / "RTProtect";
      } else {
        base_dir = std::filesystem::path(".rtprotect_activation");
      }
    }
  }

  std::error_code ec;
  std::filesystem::create_directories(base_dir, ec);
  return (base_dir / (sanitized + ".dat")).string();
}

void SecureStorage::SetRequireDpapi(bool require) {
  s_require_dpapi = require;
}

bool SecureStorage::IsRequireDpapi() {
  const char* env = std::getenv("RTPROTECT_REQUIRE_DPAPI");
  if (env && (std::strcmp(env, "1") == 0 || std::strcmp(env, "true") == 0)) {
    return true;
  }
  return s_require_dpapi;
}

SecureStorageBackend SecureStorage::GetActiveBackend() {
  DATA_BLOB in_blob{};
  std::uint8_t probe_byte = 0x5A;
  in_blob.pbData = &probe_byte;
  in_blob.cbData = sizeof(probe_byte);
  DATA_BLOB out_blob{};
  BOOL ok = ::CryptProtectData(&in_blob, L"probe", nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out_blob);
  if (ok && out_blob.pbData != nullptr) {
    ::LocalFree(out_blob.pbData);
    return SecureStorageBackend::kWindowsDpapi;
  }
  return SecureStorageBackend::kFallbackHwBoundEncryptedFile;
}

std::optional<std::vector<std::uint8_t>> SecureStorage::EncryptFallback(
    const std::string& key_name,
    const std::vector<std::uint8_t>& plaintext) {
  auto enc_key = DeriveFallbackKey(key_name, "rtprotect/secure-storage-fallback/v1");
  if (!enc_key.has_value()) return std::nullopt;

  auto encrypted = crypto::Encrypt(*enc_key, plaintext.data(), plaintext.size());
  if (!encrypted.has_value()) return std::nullopt;

  return encrypted->Serialize();
}

std::optional<std::vector<std::uint8_t>> SecureStorage::DecryptFallback(
    const std::string& key_name,
    const std::vector<std::uint8_t>& ciphertext) {
  auto msg = crypto::EncryptedMessage::Deserialize(ciphertext.data(), ciphertext.size());
  if (!msg.has_value()) return std::nullopt;

  auto enc_key = DeriveFallbackKey(key_name, "rtprotect/secure-storage-fallback/v1");
  if (!enc_key.has_value()) return std::nullopt;

  crypto::AeadError err = crypto::AeadError::kNone;
  return crypto::Decrypt(*enc_key, *msg, nullptr, 0, &err);
}

bool SecureStorage::Store(const std::string& key_name,
                          const std::vector<std::uint8_t>& data,
                          const std::string& description) {
  std::string file_path = GetStorageFilePath(key_name);

  DATA_BLOB in_blob;
  in_blob.pbData = const_cast<BYTE*>(reinterpret_cast<const BYTE*>(data.data()));
  in_blob.cbData = static_cast<DWORD>(data.size());

  std::string entropy = "rtprotect:" + key_name;
  DATA_BLOB entropy_blob;
  entropy_blob.pbData = reinterpret_cast<BYTE*>(entropy.data());
  entropy_blob.cbData = static_cast<DWORD>(entropy.size());

  std::wstring descr_w(description.begin(), description.end());
  DATA_BLOB out_blob{};

  BOOL ok = ::CryptProtectData(
      &in_blob,
      descr_w.c_str(),
      &entropy_blob,
      nullptr,
      nullptr,
      CRYPTPROTECT_UI_FORBIDDEN,
      &out_blob);

  if (ok && out_blob.pbData != nullptr) {
    std::vector<std::uint8_t> dpapi_bytes(out_blob.pbData, out_blob.pbData + out_blob.cbData);
    ::LocalFree(out_blob.pbData);
    auto container = PackContainer(SecureStorageBackend::kWindowsDpapi, dpapi_bytes);
    return tooling::WriteFile(file_path, container.data(), container.size());
  }

  // Production security policy: fail closed if DPAPI is unavailable and DPAPI is required
  if (IsRequireDpapi()) {
    return false;
  }

  // Fallback to hardware-bound AEAD authenticated encrypted file
  auto fallback_ciphertext = EncryptFallback(key_name, data);
  if (!fallback_ciphertext.has_value()) return false;

  auto container = PackContainer(SecureStorageBackend::kFallbackHwBoundEncryptedFile, *fallback_ciphertext);
  return tooling::WriteFile(file_path, container.data(), container.size());
}

std::optional<std::vector<std::uint8_t>> SecureStorage::Load(const std::string& key_name) {
  std::string file_path = GetStorageFilePath(key_name);
  if (!std::filesystem::exists(file_path)) {
    std::string legacy_path = GetLegacyStorageFilePath(key_name);
    if (std::filesystem::exists(legacy_path)) {
      file_path = legacy_path;
    } else {
      return std::nullopt;
    }
  }

  auto raw_bytes = tooling::ReadFile(file_path);
  if (!raw_bytes.has_value() || raw_bytes->empty()) {
    return std::nullopt;
  }

  // 1. Try unpacking RTSS container
  auto container = UnpackContainer(*raw_bytes);
  if (container.has_value()) {
    switch (container->backend) {
      case SecureStorageBackend::kWindowsDpapi: {
        DATA_BLOB in_blob;
        in_blob.pbData = const_cast<BYTE*>(reinterpret_cast<const BYTE*>(container->payload.data()));
        in_blob.cbData = static_cast<DWORD>(container->payload.size());

        std::string entropy = "rtprotect:" + key_name;
        DATA_BLOB entropy_blob;
        entropy_blob.pbData = reinterpret_cast<BYTE*>(entropy.data());
        entropy_blob.cbData = static_cast<DWORD>(entropy.size());

        DATA_BLOB out_blob{};
        BOOL ok = ::CryptUnprotectData(
            &in_blob,
            nullptr,
            &entropy_blob,
            nullptr,
            nullptr,
            CRYPTPROTECT_UI_FORBIDDEN,
            &out_blob);

        if (ok && out_blob.pbData != nullptr) {
          std::vector<std::uint8_t> plain(out_blob.pbData, out_blob.pbData + out_blob.cbData);
          ::LocalFree(out_blob.pbData);
          return plain;
        }
        return std::nullopt;
      }

      case SecureStorageBackend::kFallbackHwBoundEncryptedFile: {
        return DecryptFallback(key_name, container->payload);
      }
    }
  }

  // 2. Backward compatibility: check if raw file is legacy raw EncryptedMessage (WIP 4/5 format)
  auto msg = crypto::EncryptedMessage::Deserialize(raw_bytes->data(), raw_bytes->size());
  if (msg.has_value()) {
    // Primary legacy path: exact salt used by WIP 4/5 token store
    std::string hwid = GetLocalHardwareId();
    crypto::SecureBuffer sec_hwid(reinterpret_cast<const std::uint8_t*>(hwid.data()), hwid.size());
    std::vector<std::uint8_t> salt = {'R', 'T', 'P', 'r', 'o', 't', 'e', 'c', 't', 'A', 'c', 't', 'i', 'v', 'a', 't', 'i', 'o', 'n', 'K', 'e', 'y'};
    auto derived = crypto::Hkdf::DeriveKey(sec_hwid, salt, "rtprotect/activation-token-store/v1", crypto::kAes256KeyLen);
    if (derived.has_value()) {
      auto legacy_key = crypto::Aes256Key::FromBytes(derived->data(), derived->size());
      if (legacy_key.has_value()) {
        crypto::AeadError err = crypto::AeadError::kNone;
        auto plaintext = crypto::Decrypt(*legacy_key, *msg, nullptr, 0, &err);
        if (plaintext.has_value()) {
          return plaintext;
        }
      }
    }

    // Secondary legacy fallback: key_name based salt
    auto alt_key = DeriveFallbackKey(key_name, "rtprotect/activation-token-store/v1");
    if (alt_key.has_value()) {
      crypto::AeadError err = crypto::AeadError::kNone;
      auto plaintext = crypto::Decrypt(*alt_key, *msg, nullptr, 0, &err);
      if (plaintext.has_value()) {
        return plaintext;
      }
    }
  }

  // 3. Last resort fallback: direct fallback decryption
  return DecryptFallback(key_name, *raw_bytes);
}

bool SecureStorage::Delete(const std::string& key_name) {
  std::string file_path = GetStorageFilePath(key_name);
  std::error_code ec;
  std::filesystem::remove(file_path, ec);
  if (ec) return false;
  std::string legacy_path = GetLegacyStorageFilePath(key_name);
  if (legacy_path != file_path) {
    std::filesystem::remove(legacy_path, ec);
    if (ec) return false;
  }
  return true;
}

}  // namespace rtprotect::licensing
