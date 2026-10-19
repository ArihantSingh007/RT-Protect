// crypto/aead.h
//
// Authenticated encryption (AES-256-GCM) built on OpenSSL's EVP interface.
// This module implements NO cryptographic primitives itself -- it is a thin,
// misuse-resistant wrapper around libcrypto. See docs/THREAT_MODEL.md for
// what AEAD protection of embedded data does and does not achieve (it does
// NOT make the binary's own instructions un-reverse-engineerable; the key
// needed to decrypt necessarily ships with the client).

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "crypto/secure_buffer.h"

namespace rtprotect::crypto {

inline constexpr std::size_t kAes256KeyLen = 32;
inline constexpr std::size_t kGcmNonceLen = 12;  // 96-bit, per NIST SP 800-38D
inline constexpr std::size_t kGcmTagLen = 16;    // 128-bit authentication tag

enum class AeadError {
  kNone = 0,
  kInvalidKeyLength,
  kInvalidNonceLength,
  kInputTooShort,       // ciphertext shorter than the tag
  kAuthenticationFailed,  // tag mismatch -- ciphertext or AAD was modified,
                          // or the wrong key was used
  kOpenSslInternalError,
  kMessageTooLarge,  // plaintext, ciphertext, or AAD exceeds kMaxAeadMessageLen
                      // -- see that constant's comment for why this check
                      // exists even though real messages are far smaller
};

// Hard upper bound this module will process in a single Encrypt/Decrypt
// call, checked BEFORE any length is narrowed to the `int` OpenSSL's
// EVP_Encrypt/DecryptUpdate expects. Two independent reasons this exists,
// not one:
//
//   1. int narrowing safety: std::size_t is 64-bit on every platform this
//      project targets; EVP_EncryptUpdate/EVP_DecryptUpdate take `int`
//      length parameters (OpenSSL's own API, not something this project
//      can change). A length above INT_MAX (2^31-1) would silently
//      truncate/wrap when cast to `int` -- passing a wrong, possibly
//      negative, possibly small-and-wrong length into OpenSSL rather than
//      the caller's actual intended length. kMaxAeadMessageLen is set far
//      below INT_MAX specifically so the cast is always exact, never a
//      truncation, for every length this module accepts.
//   2. Sanity bound: AES-GCM's own documented limit (NIST SP 800-38D) is
//      roughly 64 GiB of plaintext per (key, nonce) pair -- far larger
//      than any resource this project's actual use cases (game resources,
//      small bytecode blobs) need. 1 GiB is a generous but finite cap that
//      catches a corrupted or maliciously-crafted length field in a
//      serialized blob before this module attempts to allocate or process
//      based on it, rather than only relying on the caller's own buffer
//      size to bound things implicitly.
inline constexpr std::size_t kMaxAeadMessageLen = 1ull << 30;  // 1 GiB

const char* ToString(AeadError error);

// Fixed-size symmetric key. Construction validates length.
class Aes256Key {
 public:
  static std::optional<Aes256Key> FromBytes(const std::uint8_t* data, std::size_t len);

  // Generates a key using OpenSSL's CSPRNG (RAND_bytes). Aborts the process
  // (via std::terminate through an uncaught exception path) only if the
  // platform RNG is itself unseeded/broken, which OpenSSL treats as fatal.
  static Aes256Key Generate();

  const SecureBuffer& bytes() const { return bytes_; }

 private:
  explicit Aes256Key(SecureBuffer bytes) : bytes_(std::move(bytes)) {}
  SecureBuffer bytes_;
};

struct GcmNonce {
  std::uint8_t bytes[kGcmNonceLen];

  static GcmNonce Generate();  // CSPRNG-generated, random per-message nonce.
};

// Result of a successful encryption: nonce || ciphertext || tag, plus the
// nonce broken out separately for callers that store it alongside
// (e.g. in a manifest) rather than concatenated.
struct EncryptedMessage {
  GcmNonce nonce;
  std::vector<std::uint8_t> ciphertext;        // same length as plaintext
  std::uint8_t tag[kGcmTagLen];

  // Serialized wire format: nonce(12) || ciphertext(N) || tag(16).
  std::vector<std::uint8_t> Serialize() const;
  static std::optional<EncryptedMessage> Deserialize(
      const std::uint8_t* data, std::size_t len);
};

// Encrypts `plaintext` under `key`, authenticating `aad` (additional
// authenticated data, e.g. a resource ID or version number) without
// encrypting it. A fresh random nonce is generated internally -- callers
// must never supply or reuse a nonce manually, which is the single most
// common GCM misuse.
//
// Returns std::nullopt only on an internal OpenSSL failure (e.g. RNG
// failure); encryption of well-formed input with a valid key cannot fail
// for any other reason.
std::optional<EncryptedMessage> Encrypt(const Aes256Key& key,
                                         const std::uint8_t* plaintext,
                                         std::size_t plaintext_len,
                                         const std::uint8_t* aad = nullptr,
                                         std::size_t aad_len = 0);

// Decrypts and authenticates `msg` under `key` with the given `aad`.
// On success, returns the plaintext. On any failure (wrong key, modified
// ciphertext, modified tag, modified aad, truncated input), returns the
// specific AeadError via `out_error` and does NOT return partial or
// unauthenticated plaintext -- callers must fail closed.
std::optional<std::vector<std::uint8_t>> Decrypt(const Aes256Key& key,
                                                   const EncryptedMessage& msg,
                                                   const std::uint8_t* aad,
                                                   std::size_t aad_len,
                                                   AeadError* out_error);

}  // namespace rtprotect::crypto
