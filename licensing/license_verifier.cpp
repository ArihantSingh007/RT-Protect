// licensing/license_verifier.cpp

#include "licensing/license_verifier.h"

#include "integrity/verifier.h"
#include "licensing/hardware_id.h"

namespace rtprotect::licensing {

LicenseStatus VerifyLicense(const License& lic,
                            const integrity::Ed25519PublicKey& pubkey,
                            const LicenseVerificationContext& ctx) {
  // 1. Schema version check
  if (lic.schema_version != kLicenseSchemaVersion) {
    return LicenseStatus::kMalformed;
  }

  // 2. Product ID match (if expected product specified)
  if (!ctx.expected_product_id.empty() && lic.product_id != ctx.expected_product_id) {
    return LicenseStatus::kProductMismatch;
  }

  // 3. Edition match (if expected edition specified)
  if (!ctx.expected_edition.empty() && lic.edition != ctx.expected_edition) {
    return LicenseStatus::kEditionMismatch;
  }

  // 4. Cryptographic signature check
  auto bytes_to_verify = SerializeLicenseForSigning(lic);
  if (!integrity::VerifyManifestSignature(bytes_to_verify, lic.signature, pubkey)) {
    return LicenseStatus::kInvalidSignature;
  }

  // 5. Clock rollback check
  // If the system time is earlier than a known previously recorded timestamp (allowing 5m clock jitter)
  if (ctx.last_recorded_time > 0 && ctx.current_time > 0) {
    if (ctx.current_time + 300 < ctx.last_recorded_time) {
      return LicenseStatus::kClockRollbackDetected;
    }
  }

  // 6. Temporal validity
  if (ctx.current_time > 0) {
    // Issued in the future (allowing 5 minutes clock skew)
    if (lic.issued_at > 0 && ctx.current_time + 300 < lic.issued_at) {
      return LicenseStatus::kNotYetValid;
    }
    // Expiration check (including offline grace period)
    if (lic.expires_at > 0) {
      std::uint64_t max_valid_time = lic.expires_at + lic.grace_period_seconds;
      if (ctx.current_time > max_valid_time) {
        return LicenseStatus::kExpired;
      }
    }
  }

  // 7. Hardware binding check
  if (!lic.hardware_id.empty()) {
    if (ctx.current_hardware_id.empty()) {
      return LicenseStatus::kHardwareMismatch;
    }
    if (!VerifyHardwareMatch(lic.hardware_id, ctx.current_hardware_id, ctx.min_hw_match_score)) {
      return LicenseStatus::kHardwareMismatch;
    }
  }

  return LicenseStatus::kValid;
}

LicenseStatus VerifyLicenseBytes(const std::uint8_t* data,
                                 std::size_t len,
                                 const integrity::Ed25519PublicKey& pubkey,
                                 const LicenseVerificationContext& ctx,
                                 License* out_license) {
  if (len > kMaxLicenseSize) return LicenseStatus::kOversized;
  auto lic = DeserializeLicense(data, len);
  if (!lic.has_value()) return LicenseStatus::kMalformed;

  auto status = VerifyLicense(*lic, pubkey, ctx);
  if (status == LicenseStatus::kValid && out_license) {
    *out_license = std::move(*lic);
  }
  return status;
}

}  // namespace rtprotect::licensing
