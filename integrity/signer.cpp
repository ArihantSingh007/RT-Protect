#include "integrity/signer.h"

#include <openssl/evp.h>

namespace rtprotect::integrity {

std::optional<std::array<std::uint8_t, kEd25519SignatureLen>> SignManifestBytes(
    const std::vector<std::uint8_t>& manifest_bytes, const Ed25519PrivateKey& private_key) {
  EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
      EVP_PKEY_ED25519, nullptr, private_key.data(), kEd25519PrivateKeyLen);
  if (!pkey) return std::nullopt;

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) {
    EVP_PKEY_free(pkey);
    return std::nullopt;
  }

  std::array<std::uint8_t, kEd25519SignatureLen> signature{};
  std::size_t sig_len = kEd25519SignatureLen;

  // Ed25519 is a "one-shot" signature scheme in OpenSSL's EVP interface --
  // no separate Update() calls; DigestSign does the whole message at once
  // (Ed25519 internally hashes the message as part of the algorithm, so no
  // EVP_DigestSignUpdate is needed or supported here).
  bool ok = EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) == 1 &&
            EVP_DigestSign(ctx, signature.data(), &sig_len, manifest_bytes.data(),
                            manifest_bytes.size()) == 1 &&
            sig_len == kEd25519SignatureLen;

  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);

  if (!ok) return std::nullopt;
  return signature;
}

}  // namespace rtprotect::integrity
