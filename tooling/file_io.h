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
// CREATION -- not via a chmod() call after an ordinary create, which
// would leave a real (if brief) window where the file exists with
// default, typically world-readable, permissions before being
// restricted. See that function's comment for the exact mechanism on each
// platform and what's actually been verified vs. written-to-spec-but-
// untested.

#pragma once

#include <cstdint>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#include <aclapi.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#endif

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
  // Atomic write via temporary file + rename
  std::string tmp_path = path + ".tmp";
  {
    std::ofstream f(tmp_path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    if (len > 0) f.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(len));
    if (!f) {
      std::remove(tmp_path.c_str());
      return false;
    }
  }
#if defined(_WIN32)
  if (!MoveFileExA(tmp_path.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING)) {
    std::remove(tmp_path.c_str());
    return false;
  }
  return true;
#else
  if (std::rename(tmp_path.c_str(), path.c_str()) != 0) {
    std::remove(tmp_path.c_str());
    return false;
  }
  return true;
#endif
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

#if defined(_WIN32)

// Windows path: written to the documented Win32 security-descriptor
// contract but NOT executed on Windows in this environment (no Windows
// runtime available here) -- same standing caveat as every other
// Windows-specific code path in this project (see the main README's
// Windows-verification notes). Please run this for real on Windows before
// relying on it for anything production-sensitive.
//
// Mechanism: build a security descriptor whose DACL grants full control
// ONLY to the current process's owning user SID (no inherited ACEs from
// the parent directory, which is the Windows equivalent of "don't rely on
// umask" -- a default-inherited ACL could be far more permissive than
// intended, the same risk category as relying on umask on POSIX), then
// pass it to CreateFileA with CREATE_NEW (fails if the file already
// exists, the same safety property O_EXCL provides on POSIX below).
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

#else

// POSIX path: open() with O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW and mode
// 0600 passed directly to open(), not a separate chmod() afterward --
// O_CREAT|mode sets the permissions atomically at creation, with no
// window where the file briefly exists at a more permissive default mode
// (the race a two-step create-then-chmod has). O_EXCL rejects an
// already-existing path instead of silently truncating/overwriting
// whatever's there (which could be a legitimate existing key the caller
// didn't mean to clobber, or could be attacker-planted). O_NOFOLLOW
// refuses to write through a symlink -- without it, an attacker who can
// place a symlink at the target path before this call runs could redirect
// the write to an arbitrary file this process has permission to write,
// which is exactly the kind of local symlink-attack class this flag
// exists to close. The requested mode (0600) is itself still subject to
// the process umask being ANDed against it by the OS (that part of POSIX
// semantics can't be bypassed from inside open() -- only the reverse risk,
// a permissive umask producing a too-open file, is what O_CREAT's
// explicit mode argument avoids, by never relying on umask alone to
// produce 0600; if umask is unusually permissive, see this function's
// return value and the explicit permission check this project's tests
// perform rather than assuming 0600 was achieved).
inline bool WriteSecretFile(const std::string& path, const std::uint8_t* data, std::size_t len) {
  int fd = open(path.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0600);
  if (fd < 0) return false;  // covers: already exists, is a symlink,
                             // permission denied, etc. -- all treated as
                             // "could not write" by this function's caller

  std::size_t total_written = 0;
  bool ok = true;
  while (total_written < len) {
    ssize_t n = write(fd, data + total_written, len - total_written);
    if (n < 0) {
      if (errno == EINTR) continue;  // interrupted by a signal -- retry,
                                      // not a real failure
      ok = false;
      break;
    }
    total_written += static_cast<std::size_t>(n);
  }

  if (ok) fsync(fd);  // cheap insurance against a partially-flushed file
                       // if the process is killed immediately after this
                       // call returns
  close(fd);

  if (!ok) {
    unlink(path.c_str());  // best-effort cleanup of a partial write --
                            // don't leave a truncated secret file behind
    return false;
  }
  return true;
}

#endif

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
