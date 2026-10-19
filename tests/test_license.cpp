// tests/test_license.cpp

#include "licensing/license.h"
#include "licensing/license_signer.h"
#include "licensing/license_verifier.h"
#include "integrity/keys.h"
#include "tests/micro_test.h"

using namespace rtprotect::licensing;
using namespace rtprotect::integrity;

namespace {

License MakeTestLicense() {
  License lic;
  lic.license_id = "test-lic-001";
  lic.product_id = "com.vendor.sampleapp";
  lic.edition = "Enterprise";
  lic.customer_id = "alice@example.com";
  lic.capabilities = kCapCoreExecution | kCapAdvancedFeatures | kCapCommercialUse;
  lic.feature_flags = {"feature_telemetry", "feature_export"};
  lic.issued_at = 1700000000;
  lic.expires_at = 1800000000;
  lic.grace_period_seconds = 86400; // 1 day
  lic.hardware_id = "CPU1234:VOL5678:SYS9012:HOST3456-ABCDEF1234567890";
  lic.metadata = "seats=10";
  return lic;
}

}  // namespace

MT_TEST(License_Serialization_RoundTrip) {
  auto lic = MakeTestLicense();
  auto bytes = SerializeLicense(lic);
  auto deserialized = DeserializeLicense(bytes.data(), bytes.size());

  MT_CHECK(deserialized.has_value());
  MT_CHECK(deserialized->license_id == lic.license_id);
  MT_CHECK(deserialized->product_id == lic.product_id);
  MT_CHECK(deserialized->edition == lic.edition);
  MT_CHECK(deserialized->customer_id == lic.customer_id);
  MT_CHECK(deserialized->capabilities == lic.capabilities);
  MT_CHECK(deserialized->feature_flags.size() == 2);
  MT_CHECK(deserialized->issued_at == lic.issued_at);
  MT_CHECK(deserialized->expires_at == lic.expires_at);
  MT_CHECK(deserialized->hardware_id == lic.hardware_id);
}

MT_TEST(License_Text_RoundTrip) {
  auto lic = MakeTestLicense();
  std::string text = LicenseToText(lic);
  auto parsed = LicenseFromText(text);

  MT_CHECK(parsed.has_value());
  MT_CHECK(parsed->license_id == lic.license_id);
  MT_CHECK(parsed->product_id == lic.product_id);
  MT_CHECK(parsed->customer_id == lic.customer_id);
  MT_CHECK(parsed->capabilities == lic.capabilities);
}

MT_TEST(License_SignAndVerify_ValidSignature) {
  auto keypair = GenerateEd25519KeyPair();
  MT_CHECK(keypair.has_value());

  auto lic = MakeTestLicense();
  bool signed_ok = SignLicense(lic, keypair->private_key);
  MT_CHECK(signed_ok);

  LicenseVerificationContext ctx;
  ctx.current_time = 1750000000;  // Inside valid window
  ctx.expected_product_id = "com.vendor.sampleapp";
  ctx.expected_edition = "Enterprise";
  ctx.current_hardware_id = lic.hardware_id;

  LicenseStatus status = VerifyLicense(lic, keypair->public_key, ctx);
  MT_CHECK(status == LicenseStatus::kValid);
}

MT_TEST(License_SignAndVerify_TamperedField_FailsSignature) {
  auto keypair = GenerateEd25519KeyPair();
  MT_CHECK(keypair.has_value());

  auto lic = MakeTestLicense();
  MT_CHECK(SignLicense(lic, keypair->private_key));

  // Adversary tampers with capabilities to grant all features
  lic.capabilities = 0xFFFFFFFFFFFFFFFFULL;

  LicenseVerificationContext ctx;
  ctx.current_time = 1750000000;
  ctx.expected_product_id = "com.vendor.sampleapp";
  ctx.current_hardware_id = lic.hardware_id;

  LicenseStatus status = VerifyLicense(lic, keypair->public_key, ctx);
  MT_CHECK(status == LicenseStatus::kInvalidSignature);
}

MT_TEST(License_SignAndVerify_WrongKey_FailsSignature) {
  auto keypair1 = GenerateEd25519KeyPair();
  auto keypair2 = GenerateEd25519KeyPair();
  MT_CHECK(keypair1.has_value() && keypair2.has_value());

  auto lic = MakeTestLicense();
  MT_CHECK(SignLicense(lic, keypair1->private_key));

  LicenseVerificationContext ctx;
  ctx.current_time = 1750000000;
  ctx.expected_product_id = "com.vendor.sampleapp";
  ctx.current_hardware_id = lic.hardware_id;

  // Verify with keypair2
  LicenseStatus status = VerifyLicense(lic, keypair2->public_key, ctx);
  MT_CHECK(status == LicenseStatus::kInvalidSignature);
}

MT_TEST(License_Expiration_Enforced) {
  auto keypair = GenerateEd25519KeyPair();
  MT_CHECK(keypair.has_value());

  auto lic = MakeTestLicense();
  lic.expires_at = 1750000000;
  lic.grace_period_seconds = 3600; // 1 hour
  MT_CHECK(SignLicense(lic, keypair->private_key));

  LicenseVerificationContext ctx;
  ctx.expected_product_id = "com.vendor.sampleapp";
  ctx.current_hardware_id = lic.hardware_id;

  // 1. Current time within valid range
  ctx.current_time = 1740000000;
  MT_CHECK(VerifyLicense(lic, keypair->public_key, ctx) == LicenseStatus::kValid);

  // 2. Current time inside grace period
  ctx.current_time = 1750001000;
  MT_CHECK(VerifyLicense(lic, keypair->public_key, ctx) == LicenseStatus::kValid);

  // 3. Current time past grace period
  ctx.current_time = 1750005000;
  MT_CHECK(VerifyLicense(lic, keypair->public_key, ctx) == LicenseStatus::kExpired);
}

MT_TEST(License_ClockRollback_Detected) {
  auto keypair = GenerateEd25519KeyPair();
  MT_CHECK(keypair.has_value());

  auto lic = MakeTestLicense();
  MT_CHECK(SignLicense(lic, keypair->private_key));

  LicenseVerificationContext ctx;
  ctx.expected_product_id = "com.vendor.sampleapp";
  ctx.current_hardware_id = lic.hardware_id;

  // Last run was at t = 1760000000, but attacker rewound system clock to t = 1750000000
  ctx.last_recorded_time = 1760000000;
  ctx.current_time = 1750000000;

  LicenseStatus status = VerifyLicense(lic, keypair->public_key, ctx);
  MT_CHECK(status == LicenseStatus::kClockRollbackDetected);
}

MT_TEST(License_HardwareBinding_Enforced) {
  auto keypair = GenerateEd25519KeyPair();
  MT_CHECK(keypair.has_value());

  auto lic = MakeTestLicense();
  lic.hardware_id = "CPU-AAAA:VOL-BBBB:SYS-CCCC:HOST-DDDD-1111222233334444";
  MT_CHECK(SignLicense(lic, keypair->private_key));

  LicenseVerificationContext ctx;
  ctx.current_time = 1750000000;
  ctx.expected_product_id = "com.vendor.sampleapp";

  // Matching machine
  ctx.current_hardware_id = "CPU-AAAA:VOL-BBBB:SYS-CCCC:HOST-DDDD-1111222233334444";
  MT_CHECK(VerifyLicense(lic, keypair->public_key, ctx) == LicenseStatus::kValid);

  // Different machine entirely
  ctx.current_hardware_id = "CPU-XXXX:VOL-YYYY:SYS-ZZZZ:HOST-WWWW-9999888877776666";
  MT_CHECK(VerifyLicense(lic, keypair->public_key, ctx) == LicenseStatus::kHardwareMismatch);
}

MT_TEST(License_CapabilitiesAndFeatures) {
  auto lic = MakeTestLicense();
  MT_CHECK(HasCapability(lic, kCapCoreExecution));
  MT_CHECK(HasCapability(lic, kCapAdvancedFeatures));
  MT_CHECK(!HasCapability(lic, kCapTrialMode));

  MT_CHECK(HasFeature(lic, "feature_telemetry"));
  MT_CHECK(HasFeature(lic, "feature_export"));
  MT_CHECK(!HasFeature(lic, "feature_super_secret"));
}

MT_TEST(License_Deserialization_RejectsMalformed) {
  std::vector<std::uint8_t> garbage = {0x00, 0x01, 0x02, 0x03};
  MT_CHECK(!DeserializeLicense(garbage.data(), garbage.size()).has_value());

  // Truncated buffer
  auto lic = MakeTestLicense();
  auto bytes = SerializeLicense(lic);
  bytes.resize(bytes.size() - 20); // cut off part of signature
  MT_CHECK(!DeserializeLicense(bytes.data(), bytes.size()).has_value());
}

MT_MAIN()
