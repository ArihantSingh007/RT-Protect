// licensing/update_manifest.h
//
// Cryptographically-signed software update package manifest and downgrade
// protection.
//
// Verifies release authenticity using Ed25519 digital signatures, enforces
// strict sequence monotonicity (anti-downgrade), and validates SHA-256
// hashes of all payload files before allowing installation.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "integrity/keys.h"
#include "integrity/manifest.h"

namespace rtprotect::licensing {

enum class UpdateStatus {
  kValid = 0,
  kInvalidSignature,
  kDowngradeDetected,       // Sequence <= currently installed sequence
  kProductMismatch,
  kPayloadHashMismatch,
  kMalformedManifest,
  kFileNotFound
};

const char* ToString(UpdateStatus status);

struct UpdatePackage {
  std::string target_product;
  std::string target_version;
  std::uint64_t sequence_number = 0;  // Strictly monotonic; must increase on each release
  std::uint64_t timestamp = 0;
  std::vector<integrity::ResourceEntry> files;

  integrity::Ed25519Signature signature{};
};

// Serializes the update package metadata for Ed25519 signing.
std::vector<std::uint8_t> SerializeUpdateForSigning(const UpdatePackage& pkg);

// Signs update package with vendor private key (build-time / server-side).
bool SignUpdatePackage(UpdatePackage& pkg, const integrity::Ed25519PrivateKey& privkey);

// Serializes update package into binary format.
std::vector<std::uint8_t> SerializeUpdatePackage(const UpdatePackage& pkg);

// Deserializes update package.
std::optional<UpdatePackage> DeserializeUpdatePackage(const std::uint8_t* data, std::size_t len);

// Verifies the update package metadata, signature, and monotonicity.
UpdateStatus VerifyUpdateMetadata(const UpdatePackage& pkg,
                                  const integrity::Ed25519PublicKey& pubkey,
                                  const std::string& expected_product,
                                  std::uint64_t current_installed_sequence);

// Validates that each file declared in the update package exists in `update_dir`
// with the expected size and SHA-256 hash. Enforces strict identifier validation.
UpdateStatus VerifyUpdatePayload(const UpdatePackage& pkg, const std::string& update_dir);

// Validates both update metadata/signature and file payload contents.
UpdateStatus VerifyUpdate(const UpdatePackage& pkg,
                         const integrity::Ed25519PublicKey& pubkey,
                         const std::string& expected_product,
                         std::uint64_t current_installed_sequence,
                         const std::string& update_dir);

}  // namespace rtprotect::licensing
