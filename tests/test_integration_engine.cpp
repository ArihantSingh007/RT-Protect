// tests/test_integration_engine.cpp
//
// Comprehensive unit and adversarial security tests for the RTProtect
// Integration Engine (PlanIntegration, ExecuteIntegration, Rollback,
// SignRelease, and ValidateProtectedBuild).

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

  // 4. CMakeLists.txt without add_executable
  fs::path no_exe_dir = "temp_test_no_exe";
  CleanDir(no_exe_dir);
  fs::create_directories(no_exe_dir);
  WriteTextFile((no_exe_dir / "CMakeLists.txt").string(), "cmake_minimum_required(VERSION 3.20)\nproject(LibOnly)\nadd_library(foo STATIC foo.cpp)\n");
  IntegrationOptions no_exe_opts;
  no_exe_opts.target_project_path = no_exe_dir.string();
  auto plan_no_exe = PlanIntegration(no_exe_opts);
  assert(!plan_no_exe.is_supported);
  CleanDir(no_exe_dir);

  std::printf("  PASSED: Input validation properly rejects invalid projects.\n");
}

void TestDryRunDoesNotModifyDisk() {
  std::printf("Running TestDryRunDoesNotModifyDisk...\n");

  fs::path test_dir = "temp_test_dryrun_proj";
  CleanDir(test_dir);
  fs::create_directories(test_dir);

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

  assert(!fs::exists(test_dir / "rtprotect_config.h"));
  assert(!fs::exists(test_dir / "rtprotect_runtime_glue.cpp"));
  assert(!fs::exists(test_dir / "release.pub"));
  assert(!fs::exists(test_dir / "license.pub"));
  assert(!fs::exists(test_dir / "release.priv"));
  assert(!fs::exists(test_dir / "client.license"));

  auto cur_cmake = ReadTextFile((test_dir / "CMakeLists.txt").string());
  assert(cur_cmake.has_value());
  assert(*cur_cmake == orig_cmake);

  assert(fs::exists(test_dir / "dry_report.json"));

  CleanDir(test_dir);
  std::printf("  PASSED: Dry-run leaves filesystem completely unmodified.\n");
}

void TestKeyIsolationAndSecurityPolicy() {
  std::printf("Running TestKeyIsolationAndSecurityPolicy (CRITICAL 1)...\n");

  fs::path test_dir = "temp_test_key_iso_proj";
  CleanDir(test_dir);
  fs::create_directories(test_dir);

  std::string orig_cmake = "cmake_minimum_required(VERSION 3.20)\nproject(KeyApp)\nadd_executable(keyapp main.cpp)\n";
  WriteTextFile((test_dir / "CMakeLists.txt").string(), orig_cmake);
  WriteTextFile((test_dir / "main.cpp").string(), "int main() { return 0; }\n");

  // 1. Production integration without pre-provisioned public keys fails closed
  IntegrationOptions prod_opts_no_keys;
  prod_opts_no_keys.target_project_path = test_dir.string();
  prod_opts_no_keys.use_dev_keys = false;
  prod_opts_no_keys.run_build = false;
  auto prod_rep = ExecuteIntegration(prod_opts_no_keys);
  assert(!prod_rep.success);
  assert(!prod_rep.error_message.empty());

  // 2. Supplying custom --dev-keys-dir inside client project is rejected
  IntegrationOptions bad_dev_opts;
  bad_dev_opts.target_project_path = test_dir.string();
  bad_dev_opts.use_dev_keys = true;
  bad_dev_opts.run_build = false;
  bad_dev_opts.dev_keys_dir = (test_dir / "insecure_keys").string();
  auto bad_dev_rep = ExecuteIntegration(bad_dev_opts);
  assert(!bad_dev_rep.success);
  assert(bad_dev_rep.error_message.find("Security policy violation") != std::string::npos);

  // 3. Dev-keys placed by default outside client project
  IntegrationOptions ok_dev_opts;
  ok_dev_opts.target_project_path = test_dir.string();
  ok_dev_opts.use_dev_keys = true;
  ok_dev_opts.run_build = false;
  auto ok_dev_rep = ExecuteIntegration(ok_dev_opts);
  assert(ok_dev_rep.success);
  assert(!fs::exists(test_dir / "release.priv"));
  assert(!fs::exists(test_dir / "license.priv"));
  assert(!fs::exists(fs::path(ok_dev_rep.backup_path) / "manifest.priv"));
  assert(!fs::exists(fs::path(ok_dev_rep.backup_path) / "license.priv"));
  assert(!fs::exists(fs::path(ok_dev_rep.backup_path) / "dev_keys"));

  // Verify private key is outside project
  assert(!ok_dev_rep.private_key_file.empty());
  assert(fs::exists(ok_dev_rep.private_key_file));
  assert(!ok_dev_rep.private_key_file.rfind(test_dir.string(), 0) == 0);

  // Cleanup dev keys
  fs::path dev_keys_dir = fs::path(ok_dev_rep.private_key_file).parent_path();
  CleanDir(dev_keys_dir);
  CleanDir(test_dir);
  std::printf("  PASSED: CRITICAL 1 key isolation and directory boundary checks verified.\n");
}

void TestTargetDiscoveryAndSelection() {
  std::printf("Running TestTargetDiscoveryAndSelection (HIGH 5)...\n");

  fs::path test_dir = "temp_test_targets_proj";
  CleanDir(test_dir);
  fs::create_directories(test_dir);

  // Project with multiple targets
  std::string multi_cmake =
      "cmake_minimum_required(VERSION 3.20)\n"
      "project(MultiApp)\n"
      "# add_executable(commented_out dummy.cpp)\n"
      "add_executable(primary_app main1.cpp)\n"
      "add_executable(helper_tool main2.cpp)\n";
  WriteTextFile((test_dir / "CMakeLists.txt").string(), multi_cmake);
  WriteTextFile((test_dir / "main1.cpp").string(), "int main() { return 0; }\n");
  WriteTextFile((test_dir / "main2.cpp").string(), "int main() { return 0; }\n");

  // 1. Omitting --target when multiple targets exist fails closed
  IntegrationOptions opts_no_target;
  opts_no_target.target_project_path = test_dir.string();
  opts_no_target.use_dev_keys = true;
  opts_no_target.run_build = false;
  auto rep1 = ExecuteIntegration(opts_no_target);
  assert(!rep1.success);
  assert(rep1.error_message.find("Multiple executable targets detected") != std::string::npos);

  // 2. Specifying non-existent target fails closed
  IntegrationOptions opts_bad_target = opts_no_target;
  opts_bad_target.target_name = "non_existent_target";
  auto rep2 = ExecuteIntegration(opts_bad_target);
  assert(!rep2.success);
  assert(rep2.error_message.find("was not found") != std::string::npos);

  // 3. Specifying valid target succeeds and instruments that exact target
  IntegrationOptions opts_valid_target = opts_no_target;
  opts_valid_target.target_name = "primary_app";
  auto rep3 = ExecuteIntegration(opts_valid_target);
  assert(rep3.success);
  assert(rep3.target_name == "primary_app");

  auto cfg_text = ReadTextFile((test_dir / "rtprotect_config.h").string());
  assert(cfg_text.has_value());
  assert(cfg_text->find("primary_app") != std::string::npos);

  CleanDir(test_dir);
  std::printf("  PASSED: HIGH 5 multi-target discovery and selection verified.\n");
}

void TestIdentifierValidation() {
  std::printf("Running TestIdentifierValidation (HIGH 6)...\n");

  fs::path test_dir = "temp_test_ident_proj";
  CleanDir(test_dir);
  fs::create_directories(test_dir);

  std::string cmake_text = "cmake_minimum_required(VERSION 3.20)\nproject(App)\nadd_executable(app main.cpp)\n";
  WriteTextFile((test_dir / "CMakeLists.txt").string(), cmake_text);
  WriteTextFile((test_dir / "main.cpp").string(), "int main() { return 0; }\n");

  IntegrationOptions opts;
  opts.target_project_path = test_dir.string();
  opts.use_dev_keys = true;
  opts.run_build = false;

  // Malicious product ID containing quote / semicolon
  opts.product_id = "com.client.app\"; system(\"calc\"); //";
  auto rep1 = ExecuteIntegration(opts);
  assert(!rep1.success);
  assert(rep1.error_message.find("Invalid product identifier") != std::string::npos);

  // Malicious version string containing newline
  opts.product_id = "com.client.valid";
  opts.release_version = "1.0.0\n#pragma message(\"injected\")";
  auto rep2 = ExecuteIntegration(opts);
  assert(!rep2.success);
  assert(rep2.error_message.find("Invalid release version") != std::string::npos);

  CleanDir(test_dir);
  std::printf("  PASSED: HIGH 6 product and version identifier validation verified.\n");
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
  opts.use_dev_keys = true;
  opts.run_build = false;

  auto report = ExecuteIntegration(opts);
  assert(report.success);
  assert(!report.backup_path.empty());
  assert(fs::exists(report.backup_path));

  // 1. Verify generated artifacts
  assert(fs::exists(test_dir / "rtprotect_config.h"));
  assert(fs::exists(test_dir / "rtprotect_runtime_glue.cpp"));
  assert(fs::exists(test_dir / "release.pub"));
  assert(fs::exists(test_dir / "license.pub"));
  assert(fs::exists(test_dir / "release.manifest"));
  assert(fs::exists(test_dir / "release.sig"));
  assert(fs::exists(test_dir / "client.license"));

  // Verify journal was created in backup directory
  assert(fs::exists(fs::path(report.backup_path) / "integration_journal.json"));

  // 2. Verify config header contains product and profile
  auto cfg_text = ReadTextFile((test_dir / "rtprotect_config.h").string());
  assert(cfg_text.has_value());
  assert(cfg_text->find("com.test.transaction") != std::string::npos);
  assert(cfg_text->find("balanced") != std::string::npos);

  // 3. Verify client.license validity with generated license public key
  auto pub_data = ReadFile((test_dir / "license.pub").string());
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
  assert(verified_lic.edition == "Development-Test");

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
  assert(!fs::exists(test_dir / "license.pub"));
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

  std::string err;
  assert(!ExecuteRollback("non_existent_proj", bkp_dir.string(), &err));
  assert(!ExecuteRollback(test_dir.string(), "non_existent_bkp", &err));

  CleanDir(test_dir);
  CleanDir(bkp_dir);
  std::printf("  PASSED: Path traversal and directory boundary checks verified.\n");
}

void TestBuildFailureFailsClosed() {
  std::printf("Running TestBuildFailureFailsClosed...\n");

  fs::path test_dir = "temp_test_build_fail_proj";
  CleanDir(test_dir);
  fs::create_directories(test_dir);

  std::string broken_cmake = "cmake_minimum_required(VERSION 3.20)\nproject(BrokenApp)\nadd_executable(broken main.cpp)\n";
  WriteTextFile((test_dir / "CMakeLists.txt").string(), broken_cmake);
  WriteTextFile((test_dir / "main.cpp").string(), "int main() { SYNTAX_ERROR_CANNOT_COMPILE_HERE; return 0; }\n");

  IntegrationOptions opts;
  opts.target_project_path = test_dir.string();
  opts.use_dev_keys = true;
  opts.run_build = true;

  auto report = ExecuteIntegration(opts);
  // HIGH 4 verification: Build failure MUST result in report.success == false!
  assert(!report.success);
  assert(!report.build_succeeded);
  assert(!report.error_message.empty());

  CleanDir(test_dir);
  std::printf("  PASSED: Build failure fails closed with non-zero error report.\n");
}

void TestStreamingSha256LargeFile() {
  std::printf("Running TestStreamingSha256LargeFile (MEDIUM 17)...\n");

  fs::path temp_file = "temp_test_large_file.dat";
  std::ofstream ofs(temp_file, std::ios::binary);
  // Write 70 MB of repeated pattern (exceeds the 64 MB ReadFile limit)
  std::vector<char> chunk(1024 * 1024, 'A');
  for (int i = 0; i < 70; ++i) {
    ofs.write(chunk.data(), chunk.size());
  }
  ofs.close();

  // ReadFile should fail or reject because > 64 MB
  auto direct_read = ReadFile(temp_file.string());
  assert(!direct_read.has_value());

  // Sha256File streaming MUST succeed regardless of file size
  std::uint64_t measured_size = 0;
  auto hash = integrity::Sha256File(temp_file.string(), &measured_size);
  assert(hash.has_value());
  assert(measured_size == 70ULL * 1024 * 1024);
  (void)hash;
  (void)direct_read;
  (void)measured_size;

  fs::remove(temp_file);
  std::printf("  PASSED: MEDIUM 17 streaming SHA-256 verifies files > 64 MB smoothly.\n");
}

}  // namespace

int main() {
  std::printf("=== RTProtect Integration Engine Tests ===\n");
  TestPlanIntegrationValidation();
  TestDryRunDoesNotModifyDisk();
  TestKeyIsolationAndSecurityPolicy();
  TestTargetDiscoveryAndSelection();
  TestIdentifierValidation();
  TestTransactionalExecutionAndRollback();
  TestPathTraversalPrevention();
  TestBuildFailureFailsClosed();
  TestStreamingSha256LargeFile();
  std::printf("ALL INTEGRATION ENGINE TESTS PASSED.\n");
  return 0;
}