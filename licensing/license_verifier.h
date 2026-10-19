// licensing/license_verifier.h
//
// Client-side license verification. Verifies cryptographic signature using
// vendor public key, validates temporal windows, prevents clock rollback,
// and enforces product and hardware binding.

#pragma once

#include <cstdint>
#include <string>

#include "integrity/keys.h"
#include "licensing/license.h"

namespace rtprotect::licensing {

struct LicenseVerificationContext {
  std::uint64_t current_time = 0;           // Unix timestamp (0 to bypass temporal checks in tests)
  std::uint64_t last_recorded_time = 0;     // Last known system/app timestamp (for rollback check)
  std::string current_hardware_id;          // Current machine fingerprint (for HWID bound licenses)
  std::string expected_product_id;          // E.g. "com.vendor.rtprotect"
  std::string expected_edition;             // E.g. "Enterprise" (empty = any)
  double min_hw_match_score = 0.75;         // Required hardware similarity (0.0 to 1.0)
};

// Verifies the license against the vendor public key and verification context.
// Returns LicenseStatus::kValid if all checks pass; otherwise specific failure reason.
LicenseStatus VerifyLicense(const License& lic,
                            const integrity::Ed25519PublicKey& pubkey,
                            const LicenseVerificationContext& ctx);

// Verifies a raw serialized license buffer directly.
LicenseStatus VerifyLicenseBytes(const std::uint8_t* data,
                                 std::size_t len,
                                 const integrity::Ed25519PublicKey& pubkey,
                                 const LicenseVerificationContext& ctx,
                                 License* out_license = nullptr);

}  // namespace rtprotect::licensing
