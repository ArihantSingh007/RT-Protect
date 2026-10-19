// examples/protected_checksum.h
//
// Demonstrates two pipelines, in increasing order of what they actually
// enforce:
//
//   CallProtectedChecksum() -- the original Phase 1-3 pipeline. A
//   function's logic exists only as bytecode (checksum_program.h),
//   authenticated-encrypted at rest with crypto::Encrypt under a fixed
//   key, and decrypted+verified+interpreted only at call time. This never
//   consults Phase 4's manifest/signature system at all -- a tampered or
//   substituted blob is still rejected (AEAD authentication fails
//   closed), but there is no cryptographic binding to a specific signed
//   release, so an attacker holding a validly-AEAD-encrypted blob from a
//   DIFFERENT release (one legitimately produced with this same fixed
//   key, e.g. an older, vulnerable build) could substitute it undetected.
//
//   CallProtectedChecksumVerified() -- the fully-integrated pipeline this
//   hardening pass added, closing exactly that gap. It verifies a signed
//   manifest FIRST, then derives the decryption key from the manifest's
//   OWN pinned content hash via integrity::DeriveBoundResourceKey (see
//   integrity/bound_key.h) rather than using a fixed key at all. This
//   means "decrypts successfully" and "matches what the signed release
//   committed to" are the same fact, enforced by AEAD's own authentication
//   tag check, not a separate comparison an attacker with code-patching
//   ability could target in isolation. This is the pipeline a real
//   deployment should use; CallProtectedChecksum() is kept for backward
//   compatibility and because it's still a useful, simpler illustration of
//   Phase 1-3 alone.
//
// TARGET LINKING NOTE: BuildVerifiedChecksumRelease() (build-time, signs a
// manifest) requires linking rtprotect_integrity_buildtools in addition to
// rtprotect_integrity/rtprotect_crypto/rtprotect_vm. CallProtectedChecksum()
// and CallProtectedChecksumVerified() (client-time, verification only)
// require only rtprotect_integrity. Because this is one header covering
// both, a translation unit that only ever CALLS the client-time functions
// does not need to link rtprotect_integrity_buildtools at all (inline
// functions are only linked if actually ODR-used) -- but the header itself
// does declare both, unlike integrity/'s own two-target split (Phase 4),
// which separates build-time and client-time code at the file level, not
// just by what's called. Splitting this header the same way is reasonable
// further work, noted here rather than done in this pass to keep this
// specific hardening change's diff focused on closing the integration gap
// itself.
//
// IMPORTANT -- read docs/THREAT_MODEL.md before treating either pipeline
// as "the function is now unbreakably protected": the key (fixed, for
// CallProtectedChecksum(), or the master_secret bound keys are derived
// from, for CallProtectedChecksumVerified()) must itself be reachable by
// the client process to decrypt before running, exactly like any other
// client-side secret (see THREAT_MODEL.md §4). What CallProtectedChecksumVerified()
// genuinely adds over the original pipeline is closing the
// wholesale-blob-substitution gap described above -- it does not change
// the fundamental limits docs/THREAT_MODEL.md §5 already states about an
// attacker with full local process control.

#pragma once

#include <cstdint>
#include <optional>
#include <stdexcept>

#include <openssl/crypto.h>

#include "bytecode_vm/serialize.h"
#include "bytecode_vm/vm.h"
#include "crypto/aead.h"
#include "examples/checksum_program.h"
#include "integrity/bound_key.h"
#include "integrity/manifest.h"
#include "integrity/signer.h"
#include "integrity/verifier.h"

namespace rtprotect::examples {

enum class ProtectedCallError {
  kNone = 0,
  kDecryptionFailed,     // wrong key or tampered blob -- see crypto::AeadError
  kMalformedBlob,        // decrypted but didn't deserialize to a valid Program shape
  kVerificationFailed,   // deserialized but failed bytecode_vm::VerifyProgram
  kExecutionFailed,      // verified but the VM reported a runtime fault
};

struct ProtectedCallResult {
  ProtectedCallError error = ProtectedCallError::kNone;
  std::int64_t value = 0;
};

// Produces the ciphertext blob that would ship alongside the binary (or be
// embedded as a resource). In this demo it's generated on the fly for
// tests; a real build pipeline would run this once at build time and embed
// the resulting bytes.
inline std::vector<std::uint8_t> BuildEncryptedChecksumBlob(
    const rtprotect::crypto::Aes256Key& key) {
  auto program = BuildChecksumProgram();
  auto plaintext = rtprotect::vm::Serialize(program);
  auto enc = rtprotect::crypto::Encrypt(key, plaintext.data(), plaintext.size());
  // Encrypt() only fails on an internal CSPRNG failure (see crypto/aead.h) --
  // for a build-time tool, treating that as fatal is correct (there's no
  // sensible way to ship a protected build if the machine's RNG is broken).
  if (!enc.has_value()) {
    throw std::runtime_error("BuildEncryptedChecksumBlob: Encrypt failed (broken RNG?)");
  }
  return enc->Serialize();
}

// Decrypts, verifies, and runs the checksum function on `x`. This is the
// actual call site a real application would use -- decrypt-per-call keeps
// the plaintext bytecode's lifetime as short as possible (see
// crypto::SecureBuffer's discussion of plaintext lifetime in
// docs/THREAT_MODEL.md §6) at the cost of re-decrypting and re-verifying on
// every call. For a hot path, a deployment could decrypt once into a
// SecureBuffer-backed cache and re-verify only on first use -- not done
// here, so this demo's performance should not be read as representative.
inline ProtectedCallResult CallProtectedChecksum(
    const rtprotect::crypto::Aes256Key& key,
    const std::vector<std::uint8_t>& encrypted_blob,
    std::int64_t x) {
  ProtectedCallResult result;

  auto wire_msg = rtprotect::crypto::EncryptedMessage::Deserialize(
      encrypted_blob.data(), encrypted_blob.size());
  if (!wire_msg.has_value()) {
    result.error = ProtectedCallError::kDecryptionFailed;
    return result;
  }

  rtprotect::crypto::AeadError aead_err = rtprotect::crypto::AeadError::kNone;
  auto plaintext = rtprotect::crypto::Decrypt(key, *wire_msg, nullptr, 0, &aead_err);
  if (!plaintext.has_value()) {
    result.error = ProtectedCallError::kDecryptionFailed;
    return result;
  }

  auto program = rtprotect::vm::Deserialize(plaintext->data(), plaintext->size());
  // Explicitly wipe the decrypted bytecode buffer in place now that it's
  // been parsed into a Program -- it's no longer needed in serialized form,
  // and this plaintext is exactly the kind of transient secret
  // SecureBuffer's Wipe() pattern exists for (see crypto/secure_buffer.h).
  // We wipe `plaintext`'s own storage directly (rather than copying it into
  // a SecureBuffer first) so there is no window where a second, unwiped
  // copy of the plaintext also exists on the heap.
  OPENSSL_cleanse(plaintext->data(), plaintext->size());

  if (!program.has_value()) {
    result.error = ProtectedCallError::kMalformedBlob;
    return result;
  }

  auto run = rtprotect::vm::Run(*program, {x});
  if (run.error == rtprotect::vm::VmError::kVerificationFailed) {
    result.error = ProtectedCallError::kVerificationFailed;
    return result;
  }
  if (run.error != rtprotect::vm::VmError::kNone) {
    result.error = ProtectedCallError::kExecutionFailed;
    return result;
  }

  result.error = ProtectedCallError::kNone;
  result.value = run.value;
  return result;
}

// ---------------------------------------------------------------------
// Fully-integrated pipeline: signed manifest + bound-key encryption.
// ---------------------------------------------------------------------

inline constexpr const char* kChecksumResourceName = "checksum_program";

struct VerifiedChecksumRelease {
  std::vector<std::uint8_t> manifest_bytes;
  std::array<std::uint8_t, integrity::kEd25519SignatureLen> signature{};
  std::vector<std::uint8_t> encrypted_blob;
};

// BUILD-TIME (links rtprotect_integrity_buildtools -- see this file's
// header comment). Implements the release pipeline's producing half:
// serialize the bytecode, commit its hash into a manifest, derive a key
// bound to that exact hash, encrypt under the bound key, sign the
// manifest. `master_secret` is the long-term symmetric secret
// DeriveBoundResourceKey() derives per-resource keys from (see
// integrity/bound_key.h) -- it must be available to the client at call
// time too, exactly like CallProtectedChecksum()'s fixed key, and is
// subject to the same client-side-secret limitations
// docs/THREAT_MODEL.md §4 describes.
inline VerifiedChecksumRelease BuildVerifiedChecksumRelease(
    const crypto::Aes256Key& master_secret, const integrity::Ed25519PrivateKey& signing_key,
    const std::string& release_version) {
  auto program = BuildChecksumProgram();
  auto plaintext = vm::Serialize(program);

  integrity::Manifest manifest;
  manifest.release_version = release_version;
  if (!manifest.AddResource(kChecksumResourceName, plaintext.data(), plaintext.size())) {
    throw std::runtime_error("BuildVerifiedChecksumRelease: AddResource failed");
  }
  const integrity::ResourceEntry* entry = manifest.Find(kChecksumResourceName);
  // entry is guaranteed non-null: AddResource just succeeded for this
  // exact name, and nothing between here and there could have removed it.

  auto bound_key =
      integrity::DeriveBoundResourceKey(master_secret, entry->sha256, kChecksumResourceName);
  auto enc = crypto::Encrypt(bound_key, plaintext.data(), plaintext.size());
  if (!enc.has_value()) {
    throw std::runtime_error("BuildVerifiedChecksumRelease: Encrypt failed (broken RNG?)");
  }

  auto manifest_bytes = integrity::SerializeManifest(manifest);
  auto sig = integrity::SignManifestBytes(manifest_bytes, signing_key);
  if (!sig.has_value()) {
    throw std::runtime_error("BuildVerifiedChecksumRelease: signing failed");
  }

  VerifiedChecksumRelease release;
  release.manifest_bytes = std::move(manifest_bytes);
  release.signature = *sig;
  release.encrypted_blob = enc->Serialize();
  return release;
}

enum class VerifiedCallError {
  kNone = 0,
  kManifestSignatureInvalid,  // covers both "signature doesn't verify"
                               // and "signed bytes don't even deserialize
                               // as a manifest" -- both mean the manifest
                               // cannot be trusted, which is the only fact
                               // that matters to the caller
  kResourceNotInManifest,
  kDecryptionFailed,  // covers genuine tampering/corruption AND a
                      // substituted blob from a different (even
                      // validly-signed-at-the-time) release -- both fail
                      // identically here because the decryption key is
                      // bound to THIS manifest's pinned hash, not a fixed
                      // key; see integrity/bound_key.h
  kMalformedBlob,
  kVerificationFailed,
  kExecutionFailed,
};

struct VerifiedCallResult {
  VerifiedCallError error = VerifiedCallError::kNone;
  std::int64_t value = 0;
};

// CLIENT-TIME (requires only rtprotect_integrity -- see this file's header
// comment; never links rtprotect_integrity_buildtools). The recommended
// entry point for this project's VM-protected-function pattern. Verifies
// the manifest signature against `trusted_public_key` -- a key the CALLER
// is responsible for having obtained through a channel it trusts (e.g.
// embedded as a compiled-in constant at build time), never a key read
// from alongside the manifest/blob being verified. See
// docs/THREAT_MODEL.md §7 and integrity/keys.h for why an untrusted public
// key supplied alongside its own "proof" is not a proof of anything.
inline VerifiedCallResult CallProtectedChecksumVerified(
    const std::vector<std::uint8_t>& manifest_bytes,
    const std::array<std::uint8_t, integrity::kEd25519SignatureLen>& signature,
    const integrity::Ed25519PublicKey& trusted_public_key, const crypto::Aes256Key& master_secret,
    const std::vector<std::uint8_t>& encrypted_blob, std::int64_t x) {
  VerifiedCallResult result;

  // Step 1: signature verified on the raw bytes BEFORE any parsing -- same
  // ordering principle as integrity::VerifyAndCheckResource (Phase 4),
  // for the same reason: don't exercise a parser on unauthenticated input.
  if (!integrity::VerifyManifestSignature(manifest_bytes, signature, trusted_public_key)) {
    result.error = VerifiedCallError::kManifestSignatureInvalid;
    return result;
  }

  auto manifest = integrity::DeserializeManifest(manifest_bytes.data(), manifest_bytes.size());
  if (!manifest.has_value()) {
    result.error = VerifiedCallError::kManifestSignatureInvalid;
    return result;
  }

  const integrity::ResourceEntry* entry = manifest->Find(kChecksumResourceName);
  if (!entry) {
    result.error = VerifiedCallError::kResourceNotInManifest;
    return result;
  }

  // Step 2: derive the bound key from the SIGNED manifest's pinned hash,
  // never from a hash freshly computed off `encrypted_blob` -- deriving
  // from a freshly-computed hash would turn this back into a separate,
  // patchable "does this match?" branch, exactly what
  // integrity/bound_key.h's design exists to avoid. The hash that matters
  // is the one the signature already vouches for.
  auto key = integrity::DeriveBoundResourceKey(master_secret, entry->sha256, kChecksumResourceName);

  auto wire_msg =
      crypto::EncryptedMessage::Deserialize(encrypted_blob.data(), encrypted_blob.size());
  if (!wire_msg.has_value()) {
    result.error = VerifiedCallError::kDecryptionFailed;
    return result;
  }
  crypto::AeadError aead_err = crypto::AeadError::kNone;
  auto plaintext = crypto::Decrypt(key, *wire_msg, nullptr, 0, &aead_err);
  if (!plaintext.has_value()) {
    // Step 3 (implicit): "decryption succeeded" and "matches the signed
    // release" are the same fact here, not two facts that could disagree
    // -- see this file's header comment and integrity/bound_key.h.
    result.error = VerifiedCallError::kDecryptionFailed;
    return result;
  }

  auto program = vm::Deserialize(plaintext->data(), plaintext->size());
  OPENSSL_cleanse(plaintext->data(), plaintext->size());
  if (!program.has_value()) {
    result.error = VerifiedCallError::kMalformedBlob;
    return result;
  }

  // Step 4: only verified, authenticated bytecode ever reaches the VM.
  auto run = vm::Run(*program, {x});
  if (run.error == vm::VmError::kVerificationFailed) {
    result.error = VerifiedCallError::kVerificationFailed;
    return result;
  }
  if (run.error != vm::VmError::kNone) {
    result.error = VerifiedCallError::kExecutionFailed;
    return result;
  }

  result.error = VerifiedCallError::kNone;
  result.value = run.value;
  return result;
}

}  // namespace rtprotect::examples
