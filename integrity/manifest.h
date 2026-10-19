// integrity/manifest.h
//
// A Manifest names the exact set of resources that belong to one signed
// release: for each resource, its name and SHA-256 hash. The manifest
// itself is what gets signed (integrity/signer.h) and verified
// (integrity/verifier.h) -- individual resources are checked against it by
// recomputing their hash and comparing, never trusted on their own.
//
// This binds resources to a *release*, which is a different and
// complementary guarantee to crypto/aead.h's per-blob authentication:
// AEAD proves a given ciphertext wasn't modified relative to the key used
// to check it; the manifest additionally proves *that exact ciphertext* is
// the one that shipped with *this* signed release, so an attacker cannot
// substitute a different, validly-encrypted-under-the-same-key blob from
// another build (e.g. an older, vulnerable version) without the swap being
// detected. See docs/THREAT_MODEL.md §5 for what "detected" does and does
// not mean against a fully capable local attacker.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "integrity/sha256.h"

namespace rtprotect::integrity {

inline constexpr std::size_t kMaxResourceNameLen = 255;
inline constexpr std::size_t kMaxResourcesPerManifest = 4096;

// Validates that a resource identifier is a safe, relative path identifier
// (no leading slashes, drive specifiers, ".." traversal, or unsafe characters).
bool IsValidResourceIdentifier(const std::string& name);

struct ResourceEntry {
  std::string name;       // logical name, e.g. "checksum.bin" -- not a filesystem path
  Sha256Digest sha256{};
  std::uint64_t size = 0;  // redundant with sha256 but cheap to check first,
                            // and useful for diagnostics without a full hash
};

struct Manifest {
  std::string release_version;  // e.g. "1.4.0" -- opaque to this module, caller-defined

  // Monotonic release sequence number, intended to let a client reject a
  // validly-signed but OLDER manifest presented alongside its own
  // correctly-matching (also validly-signed, also older) resources -- a
  // scenario Phase 4's original hash-binding does NOT catch, since an old
  // resource paired with its OWN old, correctly-signed manifest passes
  // every check this module performs on its own. See CheckRollback()
  // below and docs/THREAT_MODEL.md for what this field does and -- more
  // importantly -- does NOT achieve by itself. Defaults to 0, which this
  // module treats as "sequence not set by the caller" (never rejected on
  // its own for that reason -- CheckRollback()'s caller decides what
  // minimum sequence to require).
  std::uint64_t release_sequence = 0;

  std::vector<ResourceEntry> resources;

  // Adds an entry computed from the resource's actual bytes. Returns false
  // (and adds nothing) only on an internal hashing failure or if `name`
  // exceeds kMaxResourceNameLen or the manifest is already at
  // kMaxResourcesPerManifest.
  bool AddResource(const std::string& name, const std::uint8_t* data, std::size_t len);

  // Finds an entry by name, or nullptr if absent.
  const ResourceEntry* Find(const std::string& name) const;
};

// Canonical, deterministic wire format -- this is exactly what gets signed
// and what the signature is verified over. Byte-for-byte identical input
// (same version string, same resources, same order) always serializes
// identically; changing any field, including a single hash byte, changes
// every subsequent signature verification for that manifest.
std::vector<std::uint8_t> SerializeManifest(const Manifest& manifest);

std::optional<Manifest> DeserializeManifest(const std::uint8_t* data, std::size_t len);

// FORMAT NOTE: adding `release_sequence` to the wire format (see
// manifest.cpp's SerializeManifest/DeserializeManifest) is a breaking
// change from the format this project shipped before this hardening
// pass -- a manifest serialized by the old code will fail to deserialize
// under the new code (and vice versa), rather than silently defaulting
// `release_sequence` to some value that could be misread as a real
// freshness guarantee for data that never had one. This project has no
// production deployments depending on the old format to stay compatible
// with (see docs/ARCHITECTURE.md's phase history), so a clean break was
// chosen over introducing a dual-format parser whose old-format branch
// would have no rollback protection at all and could be a silent
// downgrade target for an attacker who simply presents an old-format
// blob. A project that DOES have deployed old-format manifests would need
// an explicit, visible migration step instead of this kind of silent
// dual-format support -- see this project's own
// docs/RUNTIME_RECONSTRUCTION.md and docs/OBFUSCATION.md for the general
// standard this project holds itself to: a security-relevant format
// change should fail closed and be documented, not quietly degrade.

// Checks `manifest.release_sequence` against `minimum_acceptable_sequence`,
// returning true if the manifest's sequence is new enough to accept.
//
// READ THIS BEFORE USING: this function is a one-line comparison. The
// entire security value of a rollback check lives in where
// `minimum_acceptable_sequence` comes from and how IT is protected from
// being rolled back itself -- a question this function deliberately does
// not answer, because this library cannot answer it in general. If
// `minimum_acceptable_sequence` is read from a local file or registry key
// that an attacker with the same local access as the one this threat
// model already assumes (see docs/THREAT_MODEL.md) can also modify, this
// check provides NO real rollback resistance: the attacker downgrades the
// manifest AND the locally-stored "minimum acceptable" value together,
// and this function has no way to detect that both moved backward in
// lockstep. This is true no matter how the comparison itself is
// implemented -- it is not a bug this function could fix by being
// written differently.
//
// What would actually provide rollback resistance: a minimum-acceptable
// value obtained from a source a purely-local attacker cannot also roll
// back -- a server round-trip (an online license/entitlement check, if
// the product already has one), a hardware monotonic counter (a TPM's,
// for instance), or platform-specific anti-rollback storage where one
// exists and is actually trustworthy against the threat model in
// docs/THREAT_MODEL.md. None of those are implemented by this project;
// wiring one in is real, product-specific work this library does not
// attempt to do generically. See docs/THREAT_MODEL.md's rollback section
// for the full discussion.
inline bool CheckRollback(const Manifest& manifest, std::uint64_t minimum_acceptable_sequence) {
  return manifest.release_sequence >= minimum_acceptable_sequence;
}

}  // namespace rtprotect::integrity
