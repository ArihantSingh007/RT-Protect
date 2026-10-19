#include "crypto/kdf.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

namespace rtprotect::crypto {

namespace {

// A single static, valid, zero-length buffer used as the octet-string
// pointer for an empty salt or info field, instead of salt.data() /
// info.data(). std::string::data() is guaranteed non-null even when
// empty (C++11 onward), but std::vector<uint8_t>::data() is NOT
// guaranteed non-null for an empty vector -- it's implementation-defined,
// and this project's own code should not depend on what a specific
// libstdc++/libc++ version happens to do for that case, even though it
// was confirmed empirically (cross-checked against RFC 5869 Test Case 3's
// published known-answer vector, see tests/test_kdf.cpp) to work
// correctly on this project's actual build. Passing a real, valid,
// non-null pointer with length 0 is unambiguous per OSSL_PARAM's
// documented octet-string semantics regardless of what any particular
// empty-container implementation would have handed us.
constexpr std::uint8_t kEmptyOctetStringSentinel = 0;

}  // namespace

std::optional<SecureBuffer> Hkdf::DeriveKey(const SecureBuffer& secret,
                                             const std::vector<std::uint8_t>& salt,
                                             const std::string& info,
                                             std::size_t out_len) {
  if (out_len == 0 || out_len > kMaxHkdfOutputLen) {
    return std::nullopt;
  }

  EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
  if (!kdf) return std::nullopt;

  EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
  EVP_KDF_free(kdf);
  if (!kctx) return std::nullopt;

  // "mode" = extract-and-expand (the default, standard HKDF per RFC 5869,
  // as opposed to EXTRACT_ONLY or EXPAND_ONLY used for specialized
  // protocols we don't need here).
  const char* digest_name = "SHA256";
  int mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;

  // Never pass a pointer that could be null for a nonzero-looking
  // OSSL_PARAM octet-string -- see kEmptyOctetStringSentinel's comment
  // above. This originally covered only salt/info; an empty `secret`
  // (zero-length IKM, which RFC 5869 and OpenSSL's own HKDF both permit --
  // confirmed directly via `openssl kdf ... -kdfopt hexkey:` with an
  // explicitly empty key, which succeeds) hits the exact same hazard via
  // crypto::SecureBuffer::data(), which returns nullptr for a zero-size
  // buffer by design (see secure_buffer.h's Allocate()). Passing that
  // nullptr with length 0 for OSSL_KDF_PARAM_KEY specifically was found,
  // empirically, to be rejected by this OpenSSL provider even though the
  // equivalent null+zero-length pattern for SALT/INFO is accepted --
  // caught by a test expecting empty-secret derivation to succeed (since
  // the CLI cross-check above confirmed it should) and finding it didn't,
  // not assumed safe because the salt/info cases already worked.
  const std::uint8_t* secret_ptr =
      secret.empty() ? &kEmptyOctetStringSentinel : secret.data();
  const std::uint8_t* salt_ptr =
      salt.empty() ? &kEmptyOctetStringSentinel : salt.data();
  const void* info_ptr =
      info.empty() ? static_cast<const void*>(&kEmptyOctetStringSentinel) : info.data();

  OSSL_PARAM params[6];
  std::size_t p = 0;
  params[p++] = OSSL_PARAM_construct_utf8_string(
      OSSL_KDF_PARAM_DIGEST, const_cast<char*>(digest_name), 0);
  params[p++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
  params[p++] = OSSL_PARAM_construct_octet_string(
      OSSL_KDF_PARAM_KEY, const_cast<std::uint8_t*>(secret_ptr), secret.size());
  params[p++] = OSSL_PARAM_construct_octet_string(
      OSSL_KDF_PARAM_SALT, const_cast<std::uint8_t*>(salt_ptr), salt.size());
  params[p++] = OSSL_PARAM_construct_octet_string(
      OSSL_KDF_PARAM_INFO, const_cast<void*>(info_ptr), info.size());
  params[p++] = OSSL_PARAM_construct_end();

  SecureBuffer out(out_len);
  int rc = EVP_KDF_derive(kctx, out.data(), out_len, params);
  EVP_KDF_CTX_free(kctx);

  if (rc != 1) {
    return std::nullopt;
  }
  return out;
}

}  // namespace rtprotect::crypto
