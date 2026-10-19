// integrity/bound_key.h
//
// FIX for a real, specific weakness in how Phases 3 and 6 used Phase 4's
// manifest system: `verifier.cpp`'s CheckResource and the VM's
// VerifyProgram are both ordinary boolean gates ("if this check fails,
// return an error") guarding a SEPARATE decryption/execution step that
// uses a fixed, independent key. An attacker capable of patching compiled
// code (the same attacker class docs/THREAT_MODEL.md §5 already assumes)
// can flip or NOP exactly one conditional branch and skip the check
// entirely -- the decryption step underneath doesn't care, because
// nothing about its own key material depended on the check having passed.
//
// THE FIX: derive the resource's actual decryption key FROM the manifest's
// committed hash for that resource, via HKDF, instead of checking the hash
// as a separate step after decrypting with some other fixed key. This
// doesn't add a new check to bypass -- it removes the bypassable step
// entirely by making "used the right key" and "matches the signed
// manifest" the same fact instead of two facts an attacker could make
// disagree:
//
//   OLD: decrypt(fixed_key, blob) -> plaintext; if sha256(plaintext) !=
//        manifest.hash: reject.  <- this `if` is one patchable branch.
//
//   NEW: key = HKDF(master_secret, salt=manifest.hash, info=resource_name);
//        decrypt(key, blob) -> plaintext or AEAD-authentication-failure.
//        There is no separate hash comparison to patch -- if `blob` wasn't
//        encrypted under the key derived from the hash the signed manifest
//        actually commits to (because it's the wrong resource, an older
//        release's resource, or tampered), AEAD's own tag check fails,
//        the same hard-to-patch, deep-inside-OpenSSL mechanism
//        crypto/aead.h already relies on for ciphertext tampering -- not
//        one of our own top-level `if` statements.
//
// WHAT THIS DOES NOT FIX, stated with the same honesty as every other
// limitation in this project: the manifest's SIGNATURE still has to be
// verified before its claimed hash can be trusted at all (see
// integrity::VerifyManifestSignature) -- that remains a boolean gate,
// because establishing initial trust in a public key's authority is not
// something key-derivation can bootstrap away. This fix eliminates the
// REDUNDANT, separately-patchable post-decrypt comparison that Phase 3 and
// 6's original pattern had; it does not, and cannot, eliminate every
// boolean check in the system -- docs/THREAT_MODEL.md §5's point that an
// attacker with full process control can still potentially patch the
// signature-verification call itself stands exactly as before. See
// docs/SECURITY_FIXES.md for the full before/after analysis and the test
// that proves the specific bypass scenario this closes.

#pragma once

#include "crypto/aead.h"
#include "integrity/sha256.h"

namespace rtprotect::integrity {

// Derives a resource-specific AES-256 key. `expected_hash` must come from
// an ALREADY-SIGNATURE-VERIFIED manifest (see
// integrity::VerifyManifestSignature) -- deriving a key from an
// unauthenticated hash provides no protection at all, since an attacker
// who can supply an arbitrary hash can simply derive whatever key matches
// their own tampered resource. `resource_name` binds the derived key to
// one specific manifest entry, so the same master secret safely produces
// unrelated keys for every resource in a manifest (the same
// info-parameter principle crypto::Hkdf's header already documents).
crypto::Aes256Key DeriveBoundResourceKey(const crypto::Aes256Key& master_secret,
                                          const Sha256Digest& expected_hash,
                                          const std::string& resource_name);

}  // namespace rtprotect::integrity
