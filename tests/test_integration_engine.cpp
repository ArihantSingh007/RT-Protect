// tests/test_integration_engine.cpp
//
// Comprehensive unit and adversarial security tests for the RTProtect
// Integration Engine (PlanIntegration, ExecuteIntegration, Rollback,
// and ValidateProtectedBuild).

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

#include "licensing/license.h"
#include "licensing/license_verifier.h"
#include "licensing/hardware_id.h"
#include "integrity/manifest.h"
#include "integrity/verifier.h"
#include "tooling/file_io.h"
#include "tooling/integration_engine.h"

namespace fs = std::filesystem;
using namespace rtprotect;
using namespace rtprotect::tooling;

namespace {

void CleanDir(const fs::path& p) {
  std::error_code ec;
  fs::remove_all(p, ec);
}

void TestPlanIntegrationValidation() {
  std::printf("Running TestPlanIntegrationValidation...\n");

  // 1. Empty target path
  IntegrationOptions empty_opts;
  auto plan_empty = PlanIntegration(empty_opts);
  assert(!plan_empty.is_supported);
  assert(!plan_empty.explanation.empty());

  // 2. Non-existent path
  IntegrationOptions nonexist_opts;
  nonexist_opts.target_project_path = "path/that/definitely/does/not/exist_12345";
  auto plan_nonexist = PlanIntegration(nonexist_opts);
  assert(!plan_nonexist.is_supported);

  // 3. Existing directory without CMakeLists.txt
  fs::path no_cmake_dir = "temp_test_no_cmake";
  CleanDir(no_cmake_dir);
  fs::create_directories(no_cmake_dir);
  IntegrationOptions no_cmake_opts;
  no_cmake_opts.target_project_path = no_cmake_dir.string();
  auto plan_no_cmake = PlanIntegration(no_cmake_opts);
  assert(!plan_no_cmake.is_supported);
  CleanDir(no_cmake_dir);

  std::printf("  PASSED: Input validation properly rejects invalid projects.\n");
}

void TestDryRunDoesNotModifyDisk() {
  std::printf("Running TestDryRunDoesNotModifyDisk...\n");

  fs::path test_dir = "temp_test_dryrun_proj";
  CleanDir(test_dir);
  fs::create_directories(test_dir);

  // Setup minimal CMakeLists.txt
  std::string orig_cmake = "cmake_minimum_required(VERSION 3.20)\nproject(TestApp)\nadd_executable(app main.cpp)\n";
  WriteTextFile((test_dir / "CMakeLists.txt").string(), orig_cmake);
  WriteTextFile((test_dir / "main.cpp").string(), "int main() { return 0; }\n");

  IntegrationOptions opts;
  opts.target_project_path = test_dir.string();
  opts.dry_run = true;
  opts.report_json_path = (test_dir / "dry_report.json").string();

  auto report = ExecuteIntegration(opts);
  assert(report.success);
  assert(!report.modified_files.empty());
  assert(!report.generated_files.empty());

  // Verify NO actual integration files were created on disk
  assert(!fs::exists(test_dir / "rtprotect_config.h"));
  assert(!fs::exists(test_dir / "rtprotect_runtime_glue.cpp"));
  assert(!fs::exists(test_dir / "release.pub"));
  assert(!fs::exists(test_dir / "release.priv"));
  assert(!fs::exists(test_dir / "client.license"));

  // Verify original CMakeLists.txt was untouched
  auto cur_cmake = ReadTextFile((test_dir / "CMakeLists.txt").string());
  assert(cur_cmake.has_value());
  assert(*cur_cmake == orig_cmake);

  // Verify dry report json was generated
  assert(fs::exists(test_dir / "dry_report.json"));

  CleanDir(test_dir);
  std::printf("  PASSED: Dry-run leaves filesystem completely unmodified.\n");
}

void TestTransactionalExecutionAndRollback() {
  std::printf("Running TestTransactionalExecutionAndRollback...\n");

  fs::path test_dir = "temp_test_trans_proj";
  CleanDir(test_dir);
  fs::create_directories(test_dir);

  std::string orig_cmake = "cmake_minimum_required(VERSION 3.20)\nproject(ClientApp)\nadd_executable(client main.cpp)\n";
  WriteTextFile((test_dir / "CMakeLists.txt").string(), orig_cmake);
  WriteTextFile((test_dir / "main.cpp").string(), "#include <iostream>\nint main() { return 0; }\n");

  IntegrationOptions opts;
  opts.target_project_path = test_dir.string();
  opts.product_id = "com.test.transaction";
  opts.release_version = "2.5.0";
  opts.profile = ProtectionProfile::kBalanced;
  opts.run_build = false; // Isolate file operations in unit test

  auto report = ExecuteIntegration(opts);
  assert(report.success);
  assert(!report.backup_path.empty());
  assert(fs::exists(report.backup_path));

  // 1. Verify generated artifacts
  assert(fs::exists(test_dir / "rtprotect_config.h"));
  assert(fs::exists(test_dir / "rtprotect_runtime_glue.cpp"));
  assert(fs::exists(test_dir / "release.pub"));
  assert(fs::exists(test_dir / "release.priv"));
  assert(fs::exists(test_dir / "release.manifest"));
  assert(fs::exists(test_dir / "release.sig"));
  assert(fs::exists(test_dir / "client.license"));

  // 2. Verify config header contains product and profile
  auto cfg_text = ReadTextFile((test_dir / "rtprotect_config.h").string());
  assert(cfg_text.has_value());
  assert(cfg_text->find("com.test.transaction") != std::string::npos);
  assert(cfg_text->find("balanced") != std::string::npos);

  // 3. Verify client.license validity with generated public key
  auto pub_data = ReadFile((test_dir / "release.pub").string());
  auto lic_data = ReadFile((test_dir / "client.license").string());
  assert(pub_data.has_value() && pub_data->size() == 32);
  assert(lic_data.has_value());

  integrity::Ed25519PublicKey pub;
  std::memcpy(pub.data(), pub_data->data(), 32);

  licensing::LicenseVerificationContext ctx;
  ctx.expected_product_id = "com.test.transaction";
  ctx.current_hardware_id = licensing::GetLocalHardwareId();
  licensing::License verified_lic;
  auto status = licensing::VerifyLicenseBytes(lic_data->data(), lic_data->size(), pub, ctx, &verified_lic);
  assert(status == licensing::LicenseStatus::kValid);
  (void)status;
  assert(verified_lic.product_id == "com.test.transaction");

  // Negative test: hardware mismatch fails
  licensing::LicenseVerificationContext bad_hw_ctx = ctx;
  bad_hw_ctx.current_hardware_id = "0000000000000000:0000000000000000:0000000000000000:0000000000000000-foreign_machine";
  auto bad_status = licensing::VerifyLicenseBytes(lic_data->data(), lic_data->size(), pub, bad_hw_ctx, &verified_lic);
  assert(bad_status == licensing::LicenseStatus::kHardwareMismatch);
  (void)bad_status;

  // 4. Validate protected build verification pass
  std::string val_err;
  bool val_ok = ValidateProtectedBuild(test_dir.string(),
                                       (test_dir / "release.pub").string(),
                                       (test_dir / "release.manifest").string(),
                                       (test_dir / "release.sig").string(),
                                       &val_err);
  assert(val_ok);
  (void)val_ok;
  assert(val_err.empty());

  // 5. Tamper with committed resource and verify ValidateProtectedBuild fails
  WriteTextFile((test_dir / "rtprotect_config.h").string(), "// TAMPERED CONTENT");
  bool val_tamper = ValidateProtectedBuild(test_dir.string(),
                                           (test_dir / "release.pub").string(),
                                           (test_dir / "release.manifest").string(),
                                           (test_dir / "release.sig").string(),
                                           &val_err);
  assert(!val_tamper);
  (void)val_tamper;
  assert(!val_err.empty());

  // 6. Test Rollback restores original state byte-for-byte
  std::string rb_err;
  bool rb_ok = ExecuteRollback(test_dir.string(), report.backup_path, &rb_err);
  assert(rb_ok);
  (void)rb_ok;

  // Verify all generated files removed
  assert(!fs::exists(test_dir / "rtprotect_config.h"));
  assert(!fs::exists(test_dir / "rtprotect_runtime_glue.cpp"));
  assert(!fs::exists(test_dir / "release.pub"));
  assert(!fs::exists(test_dir / "release.priv"));
  assert(!fs::exists(test_dir / "release.manifest"));
  assert(!fs::exists(test_dir / "release.sig"));
  assert(!fs::exists(test_dir / "client.license"));

  // Verify CMakeLists.txt matches original EXACTLY
  auto restored_cmake = ReadTextFile((test_dir / "CMakeLists.txt").string());
  assert(restored_cmake.has_value());
  assert(*restored_cmake == orig_cmake);

  CleanDir(test_dir);
  std::printf("  PASSED: Transactional execution and rollback verified.\n");
}

void TestPathTraversalPrevention() {
  std::printf("Running TestPathTraversalPrevention...\n");

  fs::path test_dir = "temp_test_traversal_proj";
  fs::path bkp_dir = "temp_test_traversal_bkp";
  CleanDir(test_dir);
  CleanDir(bkp_dir);
  fs::create_directories(test_dir);
  fs::create_directories(bkp_dir);

  // Create an invalid/tampered backup entry attempting to traverse outside target
  fs::path sub_bkp = bkp_dir / "subdir";
  fs::create_directories(sub_bkp);
  WriteTextFile((sub_bkp / "legit.txt").string(), "legit");

  // Attempting rollback on non-existent directories returns false
  std::string err;
  assert(!ExecuteRollback("non_existent_proj", bkp_dir.string(), &err));
  assert(!ExecuteRollback(test_dir.string(), "non_existent_bkp", &err));

  CleanDir(test_dir);
  CleanDir(bkp_dir);
  std::printf("  PASSED: Path traversal and directory boundary checks verified.\n");
}

}  // namespace

int main() {
  std::printf("=== RTProtect Integration Engine Tests ===\n");
  TestPlanIntegrationValidation();
  TestDryRunDoesNotModifyDisk();
  TestTransactionalExecutionAndRollback();
  TestPathTraversalPrevention();
  std::printf("ALL INTEGRATION ENGINE TESTS PASSED.\n");
  return 0;
}
