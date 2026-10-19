// crypto/kdf.h
//
// HKDF (RFC 5869) key derivation, used to turn one long-term master secret
// into distinct per-session / per-purpose keys without reusing the master
// secret directly as an encryption key anywhere. Built on OpenSSL's EVP_KDF
// (3.0+) API. Implements no cryptographic primitives itself.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "crypto/secure_buffer.h"

namespace rtprotect::crypto {

// RFC 5869 §2.3's documented maximum output length for HKDF: 255 *
// HashLen. For HMAC-SHA256, HashLen = 32, giving 8160. OpenSSL's own
// EVP_KDF already enforces this internally (confirmed empirically: a
// request for 8161 bytes is rejected by the provider, not merely
// "untested"), so this constant and the explicit check in DeriveKey()
// below are a defense-in-depth restatement of a limit that already holds
// -- making it a documented, directly-tested contract of THIS module
// rather than behavior this module merely happens to inherit from
// whatever the linked OpenSSL version's provider does internally.
inline constexpr std::size_t kMaxHkdfOutputLen = 255 * 32;

class Hkdf {
 public:
  // Derives `out_len` bytes from `secret` using HMAC-SHA256-based HKDF
  // (extract-then-expand), per RFC 5869. `salt` should be unique per
  // deployment or build (e.g. stored in the manifest, not secret); an
  // empty salt is valid per RFC 5869 §2.2 (treated as HashLen zero bytes)
  // -- see kdf.cpp for how this module passes an empty salt/info to
  // OpenSSL without relying on std::vector/std::string's
  // implementation-defined behavior for what data() returns when empty.
  // `info` binds the derived key to its purpose (e.g.
  // "rtprotect/resource-key/v1") so the same secret can safely produce
  // unrelated keys for different uses.
  //
  // Returns std::nullopt on an internal OpenSSL failure, if out_len is 0
  // (a zero-length key is never a meaningful request from any caller in
  // this project), or if out_len exceeds kMaxHkdfOutputLen.
  static std::optional<SecureBuffer> DeriveKey(const SecureBuffer& secret,
                                                const std::vector<std::uint8_t>& salt,
                                                const std::string& info,
                                                std::size_t out_len);
};

}  // namespace rtprotect::crypto
