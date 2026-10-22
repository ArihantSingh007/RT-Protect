// tooling/file_io.h
//
// Minimal binary file I/O helpers for the CLI tool. Not a general-purpose
// utility library -- just enough to read/write the raw key, signature,
// manifest, and resource files the tool's subcommands operate on.
//
// WriteFile() is for ordinary, non-secret outputs (manifests, signatures,
// encrypted ciphertext blobs -- none of these need restrictive
// permissions on their own merits, since a manifest and signature are
// meant to be public/distributed, and a ciphertext blob's confidentiality
// comes from the AEAD construction, not from file permissions).
//
// WriteSecretFile() is for private-key and symmetric-key material and
// creates the file with owner-only permissions FROM THE MOMENT OF
// CREATION -- not via a chmod() call after an ordinary create.

#pragma once

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <optional>
#include <random>
#include <string>
#include <vector>

#include <windows.h>
#include <aclapi.h>

namespace rtprotect::tooling {

inline constexpr std::size_t kMaxFileReadBytes = 64 * 1024 * 1024;  // 64 MB

inline std::optional<std::vector<std::uint8_t>> ReadFile(const std::string& path) {
  std::ifstream f(path, std::ios::binary | std::ios::ate);
  if (!f) return std::nullopt;
  std::streamsize size = f.tellg();
  if (size < 0 || static_cast<std::size_t>(size) > kMaxFileReadBytes) return std::nullopt;
  f.seekg(0, std::ios::beg);
  std::vector<std::uint8_t> data(static_cast<std::size_t>(size));
  if (size > 0 && !f.read(reinterpret_cast<char*>(data.data()), size)) return std::nullopt;
  return data;
}

inline bool WriteFile(const std::string& path, const std::uint8_t* data, std::size_t len) {
  if (!data && len > 0) return false;

  // Generate unique, unguessable temporary filename suffix to prevent symlink attacks and race collisions
  static thread_local std::mt19937_64 rng([]() {
    std::random_device rd;
    auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    return (static_cast<std::uint64_t>(rd()) << 32) ^ static_cast<std::uint64_t>(now);
  }());
  std::uint64_t rand_id = rng();

  char suffix[32];
  std::snprintf(suffix, sizeof(suffix), ".tmp.%016llx", static_cast<unsigned long long>(rand_id));
  std::string tmp_path = path + suffix;

  HANDLE h = CreateFileA(tmp_path.c_str(), GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE) {
    return false;
  }
  DWORD written = 0;
  bool write_ok = true;
  if (len > 0) {
    write_ok = (::WriteFile(h, data, static_cast<DWORD>(len), &written, NULL) != 0) && (written == len);
  }
  CloseHandle(h);
  if (!write_ok) {
    DeleteFileA(tmp_path.c_str());
    return false;
  }
  if (!MoveFileExA(tmp_path.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING)) {
    DeleteFileA(tmp_path.c_str());
    return false;
  }
  return true;
}

inline bool WriteFile(const std::string& path, const std::vector<std::uint8_t>& data) {
  return WriteFile(path, data.data(), data.size());
}

inline std::optional<std::string> ReadTextFile(const std::string& path) {
  auto bytes = ReadFile(path);
  if (!bytes.has_value()) return std::nullopt;
  return std::string(reinterpret_cast<const char*>(bytes->data()), bytes->size());
}

inline bool WriteTextFile(const std::string& path, const std::string& content) {
  return WriteFile(path, reinterpret_cast<const std::uint8_t*>(content.data()), content.size());
}

// Windows path: build a security descriptor whose DACL grants full control
// ONLY to the current process's owning user SID (no inherited ACEs from
// the parent directory), then pass it to CreateFileA with CREATE_NEW.
inline bool WriteSecretFile(const std::string& path, const std::uint8_t* data, std::size_t len) {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;

  DWORD user_info_len = 0;
  GetTokenInformation(token, TokenUser, nullptr, 0, &user_info_len);
  std::vector<std::uint8_t> user_info_buf(user_info_len);
  bool got_user = GetTokenInformation(token, TokenUser, user_info_buf.data(), user_info_len,
                                       &user_info_len) != 0;
  CloseHandle(token);
  if (!got_user) return false;
  PSID user_sid = reinterpret_cast<TOKEN_USER*>(user_info_buf.data())->User.Sid;

  EXPLICIT_ACCESSA ea{};
  ea.grfAccessPermissions = GENERIC_ALL;
  ea.grfAccessMode = SET_ACCESS;
  ea.grfInheritance = NO_INHERITANCE;
  ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
  ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
  ea.Trustee.ptstrName = reinterpret_cast<LPSTR>(user_sid);

  PACL acl = nullptr;
  if (SetEntriesInAclA(1, &ea, nullptr, &acl) != ERROR_SUCCESS) return false;

  SECURITY_DESCRIPTOR sd;
  bool sd_ok = InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION) &&
               SetSecurityDescriptorDacl(&sd, TRUE, acl, FALSE);
  if (!sd_ok) {
    LocalFree(acl);
    return false;
  }

  SECURITY_ATTRIBUTES sa{};
  sa.nLength = sizeof(sa);
  sa.lpSecurityDescriptor = &sd;
  sa.bInheritHandle = FALSE;

  HANDLE file = CreateFileA(path.c_str(), GENERIC_WRITE, 0 /* no sharing */, &sa,
                             CREATE_NEW /* fail if the file already exists */,
                             FILE_ATTRIBUTE_NORMAL, nullptr);
  LocalFree(acl);
  if (file == INVALID_HANDLE_VALUE) return false;

  DWORD written = 0;
  BOOL write_ok =
      len == 0 || ::WriteFile(file, data, static_cast<DWORD>(len), &written, nullptr);
  bool ok = write_ok && written == len;
  CloseHandle(file);
  if (!ok) DeleteFileA(path.c_str());  // best-effort cleanup of a partial write
  return ok;
}

inline bool WriteSecretFile(const std::string& path, const std::vector<std::uint8_t>& data) {
  return WriteSecretFile(path, data.data(), data.size());
}

inline std::string ToHex(const std::uint8_t* data, std::size_t len) {
  static const char* kHexDigits = "0123456789abcdef";
  std::string out;
  out.reserve(len * 2);
  for (std::size_t i = 0; i < len; ++i) {
    out.push_back(kHexDigits[(data[i] >> 4) & 0xF]);
    out.push_back(kHexDigits[data[i] & 0xF]);
  }
  return out;
}

}  // namespace rtprotect::tooling
