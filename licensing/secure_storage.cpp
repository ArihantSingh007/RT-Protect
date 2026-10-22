// licensing/secure_storage.cpp

#include "licensing/secure_storage.h"

#include <chrono>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <vector>

#include "crypto/aead.h"
#include "crypto/kdf.h"
#include "licensing/hardware_id.h"
#include "tooling/file_io.h"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#elif defined(__APPLE__)
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#elif defined(__linux__)
#include <dlfcn.h>
#endif

namespace rtprotect::licensing {

namespace {

constexpr std::uint8_t kMagic[4] = {'R', 'T', 'S', 'S'};
constexpr std::uint8_t kStorageVersion = 1;

std::string SanitizeKeyName(const std::string& key_name) {
  std::string s = key_name.empty() ? "default" : key_name;
  for (char& c : s) {
    if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_') {
      c = '_';
    }
  }
  return s;
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

  if (bytes.size() < 12 + len) return std::nullopt;
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
#if defined(_WIN32)
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
#else
    const char* xdg_config = std::getenv("XDG_CONFIG_HOME");
    if (xdg_config && xdg_config[0] != '\0') {
      base_dir = std::filesystem::path(xdg_config) / "rtprotect";
    } else {
      const char* home = std::getenv("HOME");
      if (home && home[0] != '\0') {
        base_dir = std::filesystem::path(home) / ".config" / "rtprotect";
      } else {
        base_dir = std::filesystem::path(".rtprotect_activation");
      }
    }
#endif
  }

  std::error_code ec;
  std::filesystem::create_directories(base_dir, ec);
  return (base_dir / (sanitized + ".dat")).string();
}

SecureStorageBackend SecureStorage::GetActiveBackend() {
#if defined(_WIN32)
  return SecureStorageBackend::kWindowsDpapi;
#elif defined(__APPLE__)
  return SecureStorageBackend::kMacKeychain;
#elif defined(__linux__)
  static bool checked = false;
  static bool has_libsecret = false;
  if (!checked) {
    void* handle = dlopen("libsecret-1.so.0", RTLD_LAZY);
    if (!handle) {
      handle = dlopen("libsecret-1.so", RTLD_LAZY);
    }
    if (handle) {
      has_libsecret = true;
      dlclose(handle);
    }
    checked = true;
  }
  return has_libsecret ? SecureStorageBackend::kLinuxLibsecret : SecureStorageBackend::kFallbackHwBoundEncryptedFile;
#else
  return SecureStorageBackend::kFallbackHwBoundEncryptedFile;
#endif
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

#if defined(_WIN32)
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

  // If DPAPI failed (e.g. running under specialized non-interactive service account without profile),
  // fall back to hardware-bound AEAD.
#endif

#if defined(__APPLE__)
  // macOS Keychain integration
  CFStringRef account_cf = CFStringCreateWithCString(kCFAllocatorDefault, key_name.c_str(), kCFStringEncodingUTF8);
  CFStringRef service_cf = CFStringCreateWithCString(kCFAllocatorDefault, "rtprotect", kCFStringEncodingUTF8);
  CFDataRef data_cf = CFDataCreate(kCFAllocatorDefault, data.data(), static_cast<CFIndex>(data.size()));

  if (account_cf && service_cf && data_cf) {
    // Delete existing item first if present
    const void* keys_del[] = {kSecClass, kSecAttrService, kSecAttrAccount};
    const void* values_del[] = {kSecClassGenericPassword, service_cf, account_cf};
    CFDictionaryRef query_del = CFDictionaryCreate(
        kCFAllocatorDefault, keys_del, values_del, 3,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (query_del) {
      SecItemDelete(query_del);
      CFRelease(query_del);
    }

    const void* keys_add[] = {kSecClass, kSecAttrService, kSecAttrAccount, kSecValueData};
    const void* values_add[] = {kSecClassGenericPassword, service_cf, account_cf, data_cf};
    CFDictionaryRef query_add = CFDictionaryCreate(
        kCFAllocatorDefault, keys_add, values_add, 4,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    OSStatus status = errSecInternalError;
    if (query_add) {
      status = SecItemAdd(query_add, nullptr);
      CFRelease(query_add);
    }

    CFRelease(data_cf);
    CFRelease(service_cf);
    CFRelease(account_cf);

    if (status == errSecSuccess) {
      // Store marker in file path
      auto container = PackContainer(SecureStorageBackend::kMacKeychain, {});
      tooling::WriteFile(file_path, container.data(), container.size());
      return true;
    }
  }
#endif

#if defined(__linux__)
  // Desktop Linux libsecret dynamic binding
  void* handle = dlopen("libsecret-1.so.0", RTLD_LAZY);
  if (!handle) handle = dlopen("libsecret-1.so", RTLD_LAZY);

  if (handle) {
    using StoreFn = int (*)(const void*, const char*, const char*, const char*, void*, void**, ...);
    StoreFn secret_store = reinterpret_cast<StoreFn>(dlsym(handle, "secret_password_store_sync"));
    if (secret_store) {
      // Encode data as hex/base64 or string for secret_password_store_sync
      std::string hex_data;
      hex_data.reserve(data.size() * 2);
      static const char hex_digits[] = "0123456789abcdef";
      for (std::uint8_t b : data) {
        hex_data.push_back(hex_digits[(b >> 4) & 0x0F]);
        hex_data.push_back(hex_digits[b & 0x0F]);
      }

      void* error = nullptr;
      int res = secret_store(nullptr, nullptr, description.c_str(), hex_data.c_str(),
                             nullptr, &error, "product", key_name.c_str(), nullptr);
      dlclose(handle);
      if (res != 0 && error == nullptr) {
        auto container = PackContainer(SecureStorageBackend::kLinuxLibsecret, {});
        tooling::WriteFile(file_path, container.data(), container.size());
        return true;
      }
    } else {
      dlclose(handle);
    }
  }
#endif

  // Fallback to hardware-bound AEAD authenticated encrypted file
  auto fallback_ciphertext = EncryptFallback(key_name, data);
  if (!fallback_ciphertext.has_value()) return false;

  auto container = PackContainer(SecureStorageBackend::kFallbackHwBoundEncryptedFile, *fallback_ciphertext);
  return tooling::WriteFile(file_path, container.data(), container.size());
}

std::optional<std::vector<std::uint8_t>> SecureStorage::Load(const std::string& key_name) {
  std::string file_path = GetStorageFilePath(key_name);
  if (!std::filesystem::exists(file_path)) {
    return std::nullopt;
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
#if defined(_WIN32)
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
#endif
        return std::nullopt;
      }

      case SecureStorageBackend::kMacKeychain: {
#if defined(__APPLE__)
        CFStringRef account_cf = CFStringCreateWithCString(kCFAllocatorDefault, key_name.c_str(), kCFStringEncodingUTF8);
        CFStringRef service_cf = CFStringCreateWithCString(kCFAllocatorDefault, "rtprotect", kCFStringEncodingUTF8);

        if (account_cf && service_cf) {
          const void* keys[] = {kSecClass, kSecAttrService, kSecAttrAccount, kSecReturnData, kSecMatchLimit};
          const void* values[] = {kSecClassGenericPassword, service_cf, account_cf, kCFBooleanTrue, kSecMatchLimitOne};
          CFDictionaryRef query = CFDictionaryCreate(
              kCFAllocatorDefault, keys, values, 5,
              &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

          CFTypeRef result = nullptr;
          OSStatus status = errSecInternalError;
          if (query) {
            status = SecItemCopyMatching(query, &result);
            CFRelease(query);
          }

          CFRelease(service_cf);
          CFRelease(account_cf);

          if (status == errSecSuccess && result) {
            CFDataRef data_ref = static_cast<CFDataRef>(result);
            const UInt8* ptr = CFDataGetBytePtr(data_ref);
            CFIndex len = CFDataGetLength(data_ref);
            std::vector<std::uint8_t> plain(ptr, ptr + len);
            CFRelease(result);
            return plain;
          }
        }
#endif
        return std::nullopt;
      }

      case SecureStorageBackend::kLinuxLibsecret: {
#if defined(__linux__)
        void* handle = dlopen("libsecret-1.so.0", RTLD_LAZY);
        if (!handle) handle = dlopen("libsecret-1.so", RTLD_LAZY);
        if (handle) {
          using LookupFn = char* (*)(const void*, void*, void**, ...);
          using FreeFn = void (*)(char*);
          LookupFn lookup = reinterpret_cast<LookupFn>(dlsym(handle, "secret_password_lookup_sync"));
          FreeFn free_pass = reinterpret_cast<FreeFn>(dlsym(handle, "secret_password_free"));
          if (lookup && free_pass) {
            void* error = nullptr;
            char* password = lookup(nullptr, nullptr, &error, "product", key_name.c_str(), nullptr);
            dlclose(handle);
            if (password && error == nullptr) {
              std::string hex_str(password);
              free_pass(password);
              std::vector<std::uint8_t> plain;
              for (std::size_t i = 0; i + 1 < hex_str.size(); i += 2) {
                unsigned int byte_val = 0;
                if (std::sscanf(hex_str.c_str() + i, "%02x", &byte_val) == 1) {
                  plain.push_back(static_cast<std::uint8_t>(byte_val));
                }
              }
              return plain;
            }
          } else {
            dlclose(handle);
          }
        }
#endif
        return std::nullopt;
      }

      case SecureStorageBackend::kFallbackHwBoundEncryptedFile:
        return DecryptFallback(key_name, container->payload);

      default:
        return std::nullopt;
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

  return std::nullopt;
}

bool SecureStorage::Delete(const std::string& key_name) {
  std::string file_path = GetStorageFilePath(key_name);
  std::error_code ec;
  std::filesystem::remove(file_path, ec);

#if defined(__APPLE__)
  CFStringRef account_cf = CFStringCreateWithCString(kCFAllocatorDefault, key_name.c_str(), kCFStringEncodingUTF8);
  CFStringRef service_cf = CFStringCreateWithCString(kCFAllocatorDefault, "rtprotect", kCFStringEncodingUTF8);
  if (account_cf && service_cf) {
    const void* keys[] = {kSecClass, kSecAttrService, kSecAttrAccount};
    const void* values[] = {kSecClassGenericPassword, service_cf, account_cf};
    CFDictionaryRef query = CFDictionaryCreate(
        kCFAllocatorDefault, keys, values, 3,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (query) {
      SecItemDelete(query);
      CFRelease(query);
    }
    CFRelease(service_cf);
    CFRelease(account_cf);
  }
#elif defined(__linux__)
  void* handle = dlopen("libsecret-1.so.0", RTLD_LAZY);
  if (!handle) handle = dlopen("libsecret-1.so", RTLD_LAZY);
  if (handle) {
    using ClearFn = int (*)(const void*, void*, void**, ...);
    ClearFn clear = reinterpret_cast<ClearFn>(dlsym(handle, "secret_password_clear_sync"));
    if (clear) {
      void* error = nullptr;
      clear(nullptr, nullptr, &error, "product", key_name.c_str(), nullptr);
    }
    dlclose(handle);
  }
#endif

  return true;
}

}  // namespace rtprotect::licensing
