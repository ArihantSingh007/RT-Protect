// tests/test_update_manifest.cpp

#include "licensing/update_manifest.h"
#include "integrity/keys.h"
#include "tests/micro_test.h"

using namespace rtprotect::licensing;
using namespace rtprotect::integrity;

namespace {

UpdatePackage MakeTestUpdate() {
  UpdatePackage pkg;
  pkg.target_product = "com.vendor.sampleapp";
  pkg.target_version = "2.1.0";
  pkg.sequence_number = 15;
  pkg.timestamp = 1750000000;

  ResourceEntry r1;
  r1.name = "sampleapp.exe";
  r1.size = 1048576;
  r1.sha256.fill(0xAA);
  pkg.files.push_back(r1);

  ResourceEntry r2;
  r2.name = "assets.pak";
  r2.size = 2097152;
  r2.sha256.fill(0xBB);
  pkg.files.push_back(r2);

  return pkg;
}

}  // namespace

MT_TEST(UpdateManifest_RoundTrip_Serialization) {
  auto pkg = MakeTestUpdate();
  auto bytes = SerializeUpdatePackage(pkg);
  auto deserialized = DeserializeUpdatePackage(bytes.data(), bytes.size());

  MT_CHECK(deserialized.has_value());
  MT_CHECK(deserialized->target_product == pkg.target_product);
  MT_CHECK(deserialized->target_version == pkg.target_version);
  MT_CHECK(deserialized->sequence_number == pkg.sequence_number);
  MT_CHECK(deserialized->files.size() == 2);
  MT_CHECK(deserialized->files[0].name == "sampleapp.exe");
}

MT_TEST(UpdateManifest_SignAndVerify_Valid) {
  auto keypair = GenerateEd25519KeyPair();
  MT_CHECK(keypair.has_value());

  auto pkg = MakeTestUpdate();
  MT_CHECK(SignUpdatePackage(pkg, keypair->private_key));

  // Current installed sequence is 14; incoming is 15 -> valid!
  UpdateStatus status = VerifyUpdateMetadata(pkg, keypair->public_key, "com.vendor.sampleapp", 14);
  MT_CHECK(status == UpdateStatus::kValid);
}

MT_TEST(UpdateManifest_DowngradeAttack_Rejected) {
  auto keypair = GenerateEd25519KeyPair();
  MT_CHECK(keypair.has_value());

  auto pkg = MakeTestUpdate();
  pkg.sequence_number = 10;  // Older release
  MT_CHECK(SignUpdatePackage(pkg, keypair->private_key));

  // Current installed sequence is 14; incoming is 10 -> downgrade attack!
  UpdateStatus status = VerifyUpdateMetadata(pkg, keypair->public_key, "com.vendor.sampleapp", 14);
  MT_CHECK(status == UpdateStatus::kDowngradeDetected);

  // Equal sequence is also rejected (cannot reinstall same or older without explicit force)
  UpdateStatus status_eq = VerifyUpdateMetadata(pkg, keypair->public_key, "com.vendor.sampleapp", 10);
  MT_CHECK(status_eq == UpdateStatus::kDowngradeDetected);
}

MT_TEST(UpdateManifest_Tampered_FailsSignature) {
  auto keypair = GenerateEd25519KeyPair();
  MT_CHECK(keypair.has_value());

  auto pkg = MakeTestUpdate();
  MT_CHECK(SignUpdatePackage(pkg, keypair->private_key));

  // Tamper with file digest
  pkg.files[0].sha256.fill(0xEE);

  UpdateStatus status = VerifyUpdateMetadata(pkg, keypair->public_key, "com.vendor.sampleapp", 14);
  MT_CHECK(status == UpdateStatus::kInvalidSignature);
}

MT_MAIN()
