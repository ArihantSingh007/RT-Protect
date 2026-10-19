// tests/test_update_manifest.cpp

#include "licensing/update_manifest.h"
#include "integrity/keys.h"
#include <filesystem>
#include <fstream>
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

MT_TEST(UpdateManifest_PayloadVerification_ValidFiles) {
  auto temp_dir = std::filesystem::temp_directory_path() / "rtprotect_update_test_valid";
  std::filesystem::create_directories(temp_dir);

  std::string f1_content = "Hello, world! Update payload 1.";
  std::string f2_content = "Binary blob data payload 2.";

  std::ofstream(temp_dir / "app.exe", std::ios::binary) << f1_content;
  std::ofstream(temp_dir / "data.pak", std::ios::binary) << f2_content;

  UpdatePackage pkg;
  pkg.target_product = "com.test.app";
  pkg.target_version = "1.1.0";
  pkg.sequence_number = 2;

  ResourceEntry e1;
  e1.name = "app.exe";
  e1.size = f1_content.size();
  e1.sha256 = *Sha256(reinterpret_cast<const std::uint8_t*>(f1_content.data()), f1_content.size());
  pkg.files.push_back(e1);

  ResourceEntry e2;
  e2.name = "data.pak";
  e2.size = f2_content.size();
  e2.sha256 = *Sha256(reinterpret_cast<const std::uint8_t*>(f2_content.data()), f2_content.size());
  pkg.files.push_back(e2);

  auto status = VerifyUpdatePayload(pkg, temp_dir.string());
  MT_CHECK(status == UpdateStatus::kValid);

  std::filesystem::remove_all(temp_dir);
}

MT_TEST(UpdateManifest_PayloadVerification_MissingAndTamperedFiles) {
  auto temp_dir = std::filesystem::temp_directory_path() / "rtprotect_update_test_tamper";
  std::filesystem::create_directories(temp_dir);

  std::string content = "Genuine original content";
  std::ofstream(temp_dir / "file.bin", std::ios::binary) << content;

  UpdatePackage pkg;
  ResourceEntry e;
  e.name = "file.bin";
  e.size = content.size();
  e.sha256 = *Sha256(reinterpret_cast<const std::uint8_t*>(content.data()), content.size());
  pkg.files.push_back(e);

  // Missing file check
  ResourceEntry missing;
  missing.name = "absent.bin";
  missing.size = 10;
  missing.sha256.fill(0x11);
  pkg.files.push_back(missing);

  MT_CHECK(VerifyUpdatePayload(pkg, temp_dir.string()) == UpdateStatus::kFileNotFound);

  // Remove missing, but tamper file on disk
  pkg.files.pop_back();
  std::ofstream(temp_dir / "file.bin", std::ios::binary) << "Tampered modified content";
  MT_CHECK(VerifyUpdatePayload(pkg, temp_dir.string()) == UpdateStatus::kPayloadHashMismatch);

  std::filesystem::remove_all(temp_dir);
}

MT_TEST(UpdateManifest_PayloadVerification_RejectsPathTraversal) {
  UpdatePackage pkg;
  ResourceEntry e;
  e.name = "../escape.exe";
  e.size = 100;
  pkg.files.push_back(e);

  auto temp_dir = std::filesystem::temp_directory_path() / "rtprotect_update_test_traversal";
  std::filesystem::create_directories(temp_dir);

  MT_CHECK(VerifyUpdatePayload(pkg, temp_dir.string()) == UpdateStatus::kMalformedManifest);

  std::filesystem::remove_all(temp_dir);
}

MT_MAIN()
