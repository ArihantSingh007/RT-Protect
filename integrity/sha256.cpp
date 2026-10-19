#include "integrity/sha256.h"

#include <openssl/evp.h>

namespace rtprotect::integrity {

std::optional<Sha256Digest> Sha256(const std::uint8_t* data, std::size_t len) {
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) return std::nullopt;

  Sha256Digest digest{};
  unsigned int out_len = 0;
  bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
            EVP_DigestUpdate(ctx, data, len) == 1 &&
            EVP_DigestFinal_ex(ctx, digest.data(), &out_len) == 1;
  EVP_MD_CTX_free(ctx);

  if (!ok || out_len != kSha256DigestLen) return std::nullopt;
  return digest;
}

}  // namespace rtprotect::integrity
