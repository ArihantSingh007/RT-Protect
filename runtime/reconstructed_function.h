// runtime/reconstructed_function.h
//
// The intended public entry point for Phase 6's experiment: the ONE way
// this project ever executes native code reconstructed at runtime is
// through CallReconstructedFunction below, which only ever decrypts and
// runs native_payload.h's fixed, reviewed payload -- never arbitrary
// bytes from any other source. This mirrors examples/protected_checksum.h's
// pattern from Phase 3 (encrypt-at-rest, decrypt-verify-execute,
// wipe/unmap immediately after), applied to architecture option 4 (native
// code reconstruction) instead of option 5 (bytecode VM).
//
// SECURITY NOTE, restated because it matters more here than anywhere else
// in this project: unlike Phase 3's VM, there is no verifier that can make
// arbitrary decrypted bytes safe to execute as native code. The ONLY
// safety property this pipeline has is that AEAD decryption fails closed
// on anything that isn't exactly the bytes that were encrypted under the
// caller's key (see crypto/aead.h) -- it is NOT a general-purpose
// "download and run signed code" mechanism, and extending it to accept
// payloads from any source other than this file's embedded constant would
// require re-deriving this entire module's safety reasoning from scratch.
// See docs/RUNTIME_RECONSTRUCTION.md for the full discussion.

#pragma once

#include <cstdint>
#include <stdexcept>
#include <vector>

#include <openssl/crypto.h>

#include "crypto/aead.h"
#include "runtime/executable_memory.h"
#include "runtime/native_payload.h"

namespace rtprotect::runtime {

enum class ReconstructedCallError {
  kNone = 0,
  kDecryptionFailed,    // wrong key or tampered blob
  kUnexpectedPayloadSize,  // decrypted to something other than exactly
                           // sizeof(kPayload) bytes -- rejected unconditionally,
                           // since this pipeline supports exactly one payload
  kLoadFailed,          // ExecutableMemoryRegion::Create failed (see LoadError)
  kExecutionFaulted,    // the loaded code raised a hardware fault when called
};

struct ReconstructedCallResult {
  ReconstructedCallError error = ReconstructedCallError::kNone;
  std::int64_t value = 0;
};

// Produces the ciphertext blob a build pipeline would embed/ship. Always
// encrypts exactly kPayload -- there is deliberately no parameter to
// supply different bytes; see this file's header comment for why.
inline std::vector<std::uint8_t> BuildEncryptedPayloadBlob(const crypto::Aes256Key& key) {
  auto enc = crypto::Encrypt(key, kPayload.data(), kPayload.size());
  if (!enc.has_value()) {
    throw std::runtime_error("BuildEncryptedPayloadBlob: Encrypt failed (broken RNG?)");
  }
  return enc->Serialize();
}

// Decrypts `encrypted_blob` under `key`, loads the result into fresh
// RW->RX memory (runtime/executable_memory.h), calls it with `arg`, and
// unmaps the memory immediately afterward -- minimizing how long the
// native code exists as a resident, executable mapping, the same
// decrypt-per-call principle Phase 3's CallProtectedChecksum uses for its
// bytecode.
inline ReconstructedCallResult CallReconstructedFunction(
    const crypto::Aes256Key& key, const std::vector<std::uint8_t>& encrypted_blob,
    std::int64_t arg) {
  ReconstructedCallResult result;

  auto wire_msg = crypto::EncryptedMessage::Deserialize(encrypted_blob.data(), encrypted_blob.size());
  if (!wire_msg.has_value()) {
    result.error = ReconstructedCallError::kDecryptionFailed;
    return result;
  }

  crypto::AeadError aead_err = crypto::AeadError::kNone;
  auto plaintext = crypto::Decrypt(key, *wire_msg, nullptr, 0, &aead_err);
  if (!plaintext.has_value()) {
    result.error = ReconstructedCallError::kDecryptionFailed;
    return result;
  }

  // This pipeline supports exactly one payload shape. Anything else --
  // even though it already passed AEAD authentication, meaning it was
  // encrypted by someone holding `key` -- is rejected unconditionally.
  // This is deliberate defense in depth: AEAD proves authenticity, not
  // that the authenticated content is safe to execute, and this module
  // never trusts "authenticated" as a substitute for "is the one reviewed
  // payload."
  if (plaintext->size() != kPayload.size()) {
    OPENSSL_cleanse(plaintext->data(), plaintext->size());
    result.error = ReconstructedCallError::kUnexpectedPayloadSize;
    return result;
  }

  LoadError load_err = LoadError::kNone;
  auto region = ExecutableMemoryRegion::Create(plaintext->data(), plaintext->size(), &load_err);
  OPENSSL_cleanse(plaintext->data(), plaintext->size());  // wipe the RW-side
                                                           // copy now that it's
                                                           // either loaded or
                                                           // failed to load

  if (!region.has_value()) {
    result.error = ReconstructedCallError::kLoadFailed;
    return result;
  }

  auto call_result = region->Call(arg);
  if (call_result.faulted) {
    result.error = ReconstructedCallError::kExecutionFaulted;
    return result;
  }

  result.error = ReconstructedCallError::kNone;
  result.value = call_result.value;
  return result;
}

}  // namespace rtprotect::runtime
