// licensing/license.h
//
// Structured, versioned software license model, canonical wire serialization,
// and validation logic.
//
// A License represents an authorization issued by the software vendor to a
// licensee, entitling them to use a specific product/edition and authorized
// feature set within defined temporal and machine constraints.
//
// Every license is cryptographically signed using Ed25519 asymmetric signatures.
// The client application contains ONLY the vendor's Ed25519 public key.
// The private signing key resides strictly on the vendor build/licensing server.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "integrity/keys.h"

namespace rtprotect::licensing {

inline constexpr std::uint32_t kLicenseMagic = 0x5254504C;  // 'RTPL'
inline constexpr std::uint32_t kLicenseSchemaVersion = 1;
inline constexpr std::size_t kMaxLicenseSize = 64 * 1024;     // 64 KB safety limit
inline constexpr std::size_t kMaxLicenseFieldLen = 256;

// Standard capability flags (bitmask in capabilities)
inline constexpr std::uint64_t kCapCoreExecution    = 1ULL << 0;
inline constexpr std::uint64_t kCapAdvancedFeatures = 1ULL << 1;
inline constexpr std::uint64_t kCapExportData       = 1ULL << 2;
inline constexpr std::uint64_t kCapCommercialUse    = 1ULL << 3;
inline constexpr std::uint64_t kCapTrialMode        = 1ULL << 4;
inline constexpr std::uint64_t kCapOfflineAllowed   = 1ULL << 5;

enum class LicenseStatus {
  kValid = 0,
  kInvalidSignature,
  kExpired,
  kNotYetValid,             // System time earlier than issued_at
  kHardwareMismatch,
  kProductMismatch,
  kEditionMismatch,
  kClockRollbackDetected,
  kMalformed,
  kOversized
};

const char* ToString(LicenseStatus status);

struct License {
  std::uint32_t schema_version = kLicenseSchemaVersion;
  std::string license_id;       // UUID or unique tracking token
  std::string product_id;       // Canonical product identifier (e.g. "com.vendor.rtprotect")
  std::string edition;          // e.g. "Standard", "Enterprise"
  std::string customer_id;      // Licensee identifier / email
  std::uint64_t capabilities = kCapCoreExecution;
  std::vector<std::string> feature_flags;  // Named custom features
  std::uint64_t issued_at = 0;             // Unix timestamp seconds
  std::uint64_t expires_at = 0;            // Unix timestamp seconds (0 = perpetual)
  std::uint64_t grace_period_seconds = 0;  // Allowed offline extension after expires_at
  std::string hardware_id;                 // Bound machine fingerprint (or empty if un-bound)
  std::string metadata;                    // Optional vendor payload / policy notes

  integrity::Ed25519Signature signature{}; // 64-byte Ed25519 signature
};

// Serializes the license fields (EXCLUDING signature) into canonical binary wire format
// for signing and signature verification.
std::vector<std::uint8_t> SerializeLicenseForSigning(const License& lic);

// Serializes the complete license (including signature) into binary format.
std::vector<std::uint8_t> SerializeLicense(const License& lic);

// Deserializes a binary license payload. Rejects malformed or oversized buffers.
std::optional<License> DeserializeLicense(const std::uint8_t* data, std::size_t len);

// Convenience JSON-like text export/import for human inspection and configuration files.
std::string LicenseToText(const License& lic);
std::optional<License> LicenseFromText(const std::string& text);

// Checks if license has a capability bit set.
inline bool HasCapability(const License& lic, std::uint64_t cap) {
  return (lic.capabilities & cap) == cap;
}

// Checks if license contains a named feature string.
bool HasFeature(const License& lic, const std::string& feature);

}  // namespace rtprotect::licensing
