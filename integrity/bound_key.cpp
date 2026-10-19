#include "integrity/bound_key.h"

#include <stdexcept>

#include "crypto/kdf.h"

namespace rtprotect::integrity {

crypto::Aes256Key DeriveBoundResourceKey(const crypto::Aes256Key& master_secret,
                                          const Sha256Digest& expected_hash,
                                          const std::string& resource_name) {
  std::vector<std::uint8_t> salt(expected_hash.begin(), expected_hash.end());
  std::string info = "rtprotect/bound-resource/" + resource_name;

  auto derived = crypto::Hkdf::DeriveKey(master_secret.bytes(), salt, info, crypto::kAes256KeyLen);
  if (!derived.has_value()) {
    // Same reasoning as crypto::Aes256Key::Generate()'s RNG-failure path:
    // HKDF over HMAC-SHA256 failing indicates something is fundamentally
    // broken in the OpenSSL installation, not a recoverable condition this
    // function's caller could sensibly handle -- there is no safe
    // "fall back to a weaker key" option.
    throw std::runtime_error("DeriveBoundResourceKey: HKDF derivation failed");
  }

  auto key = crypto::Aes256Key::FromBytes(derived->data(), derived->size());
  // HKDF with out_len == kAes256KeyLen always produces exactly
  // kAes256KeyLen bytes on success, so FromBytes (which only rejects wrong
  // lengths) cannot fail here -- this check exists so a future change to
  // either constant doesn't silently produce an invalid key.
  if (!key.has_value()) {
    throw std::runtime_error("DeriveBoundResourceKey: internal length mismatch");
  }
  // Aes256Key is deliberately non-copyable (it wraps a SecureBuffer, which
  // is non-copyable by design -- see crypto/secure_buffer.h) -- must move,
  // not copy, out of the optional.
  return std::move(*key);
}

}  // namespace rtprotect::integrity
