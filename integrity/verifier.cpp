#include "integrity/verifier.h"

#include <openssl/evp.h>

namespace rtprotect::integrity {

const char* ToString(IntegrityError error) {
  switch (error) {
    case IntegrityError::kNone: return "none";
    case IntegrityError::kManifestDeserializationFailed: return "manifest bytes malformed";
    case IntegrityError::kSignatureInvalid: return "manifest signature invalid";
    case IntegrityError::kResourceNotInManifest: return "resource not listed in manifest";
    case IntegrityError::kResourceSizeMismatch: return "resource size does not match manifest";
    case IntegrityError::kResourceHashMismatch: return "resource hash does not match manifest";
  }
  return "unknown IntegrityError";
}

bool VerifyManifestSignature(const std::vector<std::uint8_t>& manifest_bytes,
                              const std::array<std::uint8_t, kEd25519SignatureLen>& signature,
                              const Ed25519PublicKey& public_key) {
  EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, public_key.data(),
                                                kEd25519PublicKeyLen);
  if (!pkey) return false;

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) {
    EVP_PKEY_free(pkey);
    return false;
  }

  bool ok = EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1;
  int verify_rc = 0;
  if (ok) {
    verify_rc = EVP_DigestVerify(ctx, signature.data(), signature.size(), manifest_bytes.data(),
                                  manifest_bytes.size());
  }

  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);

  // EVP_DigestVerify returns 1 for a valid signature, 0 for an invalid one,
  // and a negative value for an internal error -- all non-1 outcomes are
  // treated identically as "not verified" (fail closed), never as "assume
  // valid".
  return ok && verify_rc == 1;
}

IntegrityError CheckResource(const Manifest& manifest, const std::string& resource_name,
                              const std::uint8_t* resource_data, std::size_t resource_len) {
  const ResourceEntry* entry = manifest.Find(resource_name);
  if (!entry) return IntegrityError::kResourceNotInManifest;

  if (entry->size != resource_len) return IntegrityError::kResourceSizeMismatch;

  auto actual_hash = Sha256(resource_data, resource_len);
  if (!actual_hash.has_value() || *actual_hash != entry->sha256) {
    return IntegrityError::kResourceHashMismatch;
  }

  return IntegrityError::kNone;
}

IntegrityError VerifyAndCheckResource(const std::vector<std::uint8_t>& manifest_bytes,
                                       const std::array<std::uint8_t, kEd25519SignatureLen>& signature,
                                       const Ed25519PublicKey& public_key,
                                       const std::string& resource_name,
                                       const std::uint8_t* resource_data, std::size_t resource_len) {
  // Signature check FIRST, on the raw bytes, before any parsing -- parsing
  // untrusted bytes before authenticating them is itself a common source of
  // vulnerabilities (a malformed-but-unsigned manifest could otherwise
  // exercise deserialization code paths on attacker-controlled input before
  // being rejected).
  if (!VerifyManifestSignature(manifest_bytes, signature, public_key)) {
    return IntegrityError::kSignatureInvalid;
  }

  auto manifest = DeserializeManifest(manifest_bytes.data(), manifest_bytes.size());
  if (!manifest.has_value()) {
    // A signature can be valid over bytes that still fail to deserialize
    // only if those exact bytes were legitimately signed in that broken
    // state (e.g. a build-tool bug) -- this is a defensive check, not an
    // expected path in normal operation.
    return IntegrityError::kManifestDeserializationFailed;
  }

  return CheckResource(*manifest, resource_name, resource_data, resource_len);
}

}  // namespace rtprotect::integrity
