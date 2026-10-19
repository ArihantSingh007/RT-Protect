// integrity/sha256.h
//
// SHA-256 digest, used to bind a manifest to the exact bytes of each
// resource it describes. Like crypto/aead.h, this implements no hash
// primitive itself -- it's a thin wrapper around OpenSSL's EVP_Digest.
//
// SHA-256 here provides INTEGRITY binding within a signed manifest, not
// secrecy and not standalone authentication -- a hash alone can be
// recomputed by anyone, including an attacker who also forges a
// replacement manifest entry to match a tampered resource. The signature
// in integrity/verifier.h is what makes the hash meaningful: it's the
// *manifest*, not the bare hash, that's authenticated.

#pragma once

#include <array>
#include <cstdint>
#include <optional>

namespace rtprotect::integrity {

inline constexpr std::size_t kSha256DigestLen = 32;
using Sha256Digest = std::array<std::uint8_t, kSha256DigestLen>;

// Returns std::nullopt only on an internal OpenSSL failure (digest fetch).
std::optional<Sha256Digest> Sha256(const std::uint8_t* data, std::size_t len);

}  // namespace rtprotect::integrity
