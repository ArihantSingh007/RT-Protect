#include "integrity/keys.h"

#include <openssl/evp.h>

namespace rtprotect::integrity {

std::optional<Ed25519KeyPair> GenerateEd25519KeyPair() {
  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
  if (!pctx) return std::nullopt;

  EVP_PKEY* pkey = nullptr;
  bool ok = EVP_PKEY_keygen_init(pctx) == 1 && EVP_PKEY_keygen(pctx, &pkey) == 1;
  EVP_PKEY_CTX_free(pctx);
  if (!ok || !pkey) return std::nullopt;

  Ed25519KeyPair kp;
  std::size_t priv_len = kEd25519PrivateKeyLen;
  std::size_t pub_len = kEd25519PublicKeyLen;

  ok = EVP_PKEY_get_raw_private_key(pkey, kp.private_key.MutableDataForGeneration(), &priv_len) == 1 &&
       priv_len == kEd25519PrivateKeyLen &&
       EVP_PKEY_get_raw_public_key(pkey, kp.public_key.data(), &pub_len) == 1 &&
       pub_len == kEd25519PublicKeyLen;

  EVP_PKEY_free(pkey);
  if (!ok) return std::nullopt;
  return kp;
}

}  // namespace rtprotect::integrity
