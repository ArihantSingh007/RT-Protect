// integrity/verifier.h
//
// CLIENT-SIDE. This is the half of the integrity system that ships with
// the distributed application: it only ever needs the public key (safe to
// embed, per keys.h) and never touches a private key.
//
// Two checks, used together (VerifyAndCheckResource does both in the
// correct order -- signature first, then hash):
//   1. VerifyManifestSignature: is this manifest's content exactly what the
//      release signing key authorized, unmodified?
//   2. CheckResource: does this specific resource's current bytes match
//      what the (now-authenticated) manifest says they should be?
//
// Checking a resource's hash against an manifest whose signature was never
// verified is worse than useless -- an attacker who can replace the
// resource can just as easily replace the manifest to match. Every
// function here that performs check #2 requires having already passed
// check #1; see VerifyAndCheckResource's single entry point, which is the
// one callers should actually use.
//
// Per docs/THREAT_MODEL.md §5: this is an in-process check. An attacker
// with full control of the process can patch out the call to this
// verifier entirely, or patch its result. What this module provides is
// detection of tampering that happened to the shipped artifacts
// themselves (resources modified on disk, or substituted from a different
// release) -- not a guarantee that the verification call itself cannot be
// bypassed by an attacker who controls the running process.

#pragma once

#include <cstdint>
#include <vector>

#include "integrity/keys.h"
#include "integrity/manifest.h"

namespace rtprotect::integrity {

enum class IntegrityError {
  kNone = 0,
  kManifestDeserializationFailed,
  kSignatureInvalid,
  kResourceNotInManifest,
  kResourceSizeMismatch,   // cheap check, fails before the full hash comparison
  kResourceHashMismatch,
};

const char* ToString(IntegrityError error);

// Checks a raw Ed25519 signature over `manifest_bytes` (the exact output of
// SerializeManifest -- not a re-serialization, to avoid any ambiguity about
// what was actually signed) against `public_key`. This function alone does
// NOT parse or trust the manifest's content; it only says whether the
// bytes were signed by the holder of the matching private key.
bool VerifyManifestSignature(const std::vector<std::uint8_t>& manifest_bytes,
                              const std::array<std::uint8_t, kEd25519SignatureLen>& signature,
                              const Ed25519PublicKey& public_key);

// Checks `resource_data` against the entry named `resource_name` in an
// ALREADY-AUTHENTICATED `manifest`. Does not itself verify the manifest's
// signature -- callers must have done that first (or use
// VerifyAndCheckResource below, which enforces the order).
IntegrityError CheckResource(const Manifest& manifest, const std::string& resource_name,
                              const std::uint8_t* resource_data, std::size_t resource_len);

// The single recommended entry point: verifies the manifest's signature,
// deserializes it only if the signature is valid, and checks the named
// resource against it. Fails closed at every step -- any failure returns a
// specific IntegrityError and CheckResource is never reached unless the
// signature check passed first.
IntegrityError VerifyAndCheckResource(const std::vector<std::uint8_t>& manifest_bytes,
                                       const std::array<std::uint8_t, kEd25519SignatureLen>& signature,
                                       const Ed25519PublicKey& public_key,
                                       const std::string& resource_name,
                                       const std::uint8_t* resource_data, std::size_t resource_len);

}  // namespace rtprotect::integrity
