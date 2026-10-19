// integrity/keys.h
//
// Ed25519 key generation and raw-byte representations.
//
// TRUST BOUNDARY, stated plainly (see docs/THREAT_MODEL.md §7):
//   - Ed25519PrivateKey must NEVER be embedded in, or shipped as part of,
//     the distributed client application. It exists here only for the
//     offline build-time signing tool and for tests that need to produce
//     a signed fixture. Signing happens once, at build/release time, on
//     infrastructure the attacker does not control.
//   - Ed25519PublicKey IS safe to embed in the client -- that's the whole
//     point of asymmetric signing: the client can verify a signature
//     without being able to produce one.
//
// This module implements no cryptographic primitives itself; key
// generation and signing both go through OpenSSL's EVP_PKEY interface for
// the Ed25519 algorithm (RFC 8032).

#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>

#include <openssl/crypto.h>

namespace rtprotect::integrity {

inline constexpr std::size_t kEd25519PrivateKeyLen = 32;
inline constexpr std::size_t kEd25519PublicKeyLen = 32;
inline constexpr std::size_t kEd25519SignatureLen = 64;

using Ed25519PublicKey = std::array<std::uint8_t, kEd25519PublicKeyLen>;

// Non-copyable, wipe-on-destruction, wipe-on-move-from. A fixed-size
// (32-byte) secret, so unlike crypto::SecureBuffer this never reallocates
// -- a plain in-place std::array is wiped directly, with no heap
// management needed. The safety properties (no silent copies, reliable
// cleanse on every path out of scope) are the same ones SecureBuffer
// provides for variable-length secrets; this type exists because
// Ed25519PrivateKey's previous version was a bare struct wrapping a plain
// std::array with no destructor and no copy protection at all -- directly
// copyable, and never wiped, by any code that happened to hold one.
//
// TRUST BOUNDARY, stated plainly (see docs/THREAT_MODEL.md §7): this type
// must NEVER be embedded in, or shipped as part of, the distributed
// client application -- not copy protection (which this class now
// provides) but the actual reason the type exists at all: it exists only
// for the offline build-time signing tool and for tests that need to
// produce a signed fixture. Signing happens once, at build/release time,
// on infrastructure the attacker does not control. Ed25519PublicKey (a
// plain std::array, no wipe needed) IS safe to embed in the client --
// that's the whole point of asymmetric signing: the client can verify a
// signature without being able to produce one.
class Ed25519PrivateKey {
 public:
  Ed25519PrivateKey() = default;  // zero-initialized; see
                                   // MutableDataForGeneration() for the one
                                   // caller allowed to fill it in afterward

  // Validates length and copies `data` in. Returns std::nullopt if `len`
  // isn't exactly kEd25519PrivateKeyLen.
  static std::optional<Ed25519PrivateKey> FromBytes(const std::uint8_t* data, std::size_t len) {
    if (len != kEd25519PrivateKeyLen) return std::nullopt;
    Ed25519PrivateKey key;
    std::memcpy(key.bytes_.data(), data, kEd25519PrivateKeyLen);
    return key;
  }

  Ed25519PrivateKey(const Ed25519PrivateKey&) = delete;
  Ed25519PrivateKey& operator=(const Ed25519PrivateKey&) = delete;

  Ed25519PrivateKey(Ed25519PrivateKey&& other) noexcept {
    bytes_ = other.bytes_;
    other.Wipe();
  }
  Ed25519PrivateKey& operator=(Ed25519PrivateKey&& other) noexcept {
    if (this != &other) {
      Wipe();
      bytes_ = other.bytes_;
      other.Wipe();
    }
    return *this;
  }

  ~Ed25519PrivateKey() { Wipe(); }

  const std::uint8_t* data() const { return bytes_.data(); }
  std::size_t size() const { return bytes_.size(); }

  // Mutable raw access for the ONE caller allowed to fill this key's
  // bytes after construction: GenerateEd25519KeyPair(), which must hand
  // OpenSSL's EVP_PKEY_get_raw_private_key a writable output buffer of
  // known size. This is a named function rather than a public mutable
  // data() overload specifically so every other call site in this
  // codebase is forced through the read-only accessor and FromBytes(),
  // making "who is allowed to write into this key's storage" visible and
  // grep-able at every call site, not just documented in a comment.
  std::uint8_t* MutableDataForGeneration() { return bytes_.data(); }

 private:
  void Wipe() { OPENSSL_cleanse(bytes_.data(), bytes_.size()); }

  std::array<std::uint8_t, kEd25519PrivateKeyLen> bytes_{};
};

struct Ed25519KeyPair {
  Ed25519PrivateKey private_key;  // build-tool-only -- see file header
  Ed25519PublicKey public_key;    // safe to embed client-side
};

// Generates a fresh Ed25519 keypair using OpenSSL's CSPRNG. Returns
// std::nullopt only on an internal OpenSSL failure.
std::optional<Ed25519KeyPair> GenerateEd25519KeyPair();

}  // namespace rtprotect::integrity
