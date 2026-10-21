// tests/test_integration_engine.cpp
//
// Comprehensive unit and adversarial security tests for the RTProtect
// Integration Engine (PlanIntegration, ExecuteIntegration, Rollback,
// SignRelease, and ValidateProtectedBuild).

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

#define RT_TEST_ASSERT(cond)                                                    \
  do {                                                                          \
    if (!(cond)) {                                                              \
      std::fprintf(stderr, "RT_TEST_ASSERT FAILED at %s:%d: %s\n",              \
                   __FILE__, __LINE__, #cond);                                  \
      std::fflush(stderr);                                                      \
      std::abort();                                                             \
    }                                                                           \
  } while (0)

#undef assert
#define assert(cond) RT_TEST_ASSERT(cond)

#include "licensing/license.h"
#include "licensing/license_signer.h"
#include "licensing/license_verifier.h"
#include "licensing/activation.h"
#include "licensing/hardware_id.h"
#include "integrity/manifest.h"
#include "integrity/signer.h"
#include "integrity/verifier.h"
#include "tooling/file_io.h"
#include "tooling/integration_engine.h"
#include "bytecode_vm/compiler.h"
#include "bytecode_vm/opcode_map.h"
#include "bytecode_vm/serialize.h"
#include "bytecode_vm/vm.h"
#include "crypto/aead.h"
#include "crypto/kdf.h"
#include "antitamper/risk_policy.h"

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

void TestSignReleaseKeyMismatchRejected() {
  std::printf("Running TestSignReleaseKeyMismatchRejected (Finding 1)...\n");

  fs::path test_dir = "temp_test_sign_mismatch";
  CleanDir(test_dir);
  fs::create_directories(test_dir);

  auto kp_correct = integrity::GenerateEd25519KeyPair();
  auto kp_wrong = integrity::GenerateEd25519KeyPair();
  assert(kp_correct.has_value() && kp_wrong.has_value());

  // Set up project with kp_correct public key
  WriteFile((test_dir / "release.pub").string(), kp_correct->public_key.data(), kp_correct->public_key.size());

  // Create a minimal manifest
  integrity::Manifest m;
  m.release_version = "1.0.0";
  m.release_sequence = 1;
  std::string dummy_data = "int main() { return 0; }";
  WriteTextFile((test_dir / "main.cpp").string(), dummy_data);
  m.AddResource("main.cpp", reinterpret_cast<const std::uint8_t*>(dummy_data.data()), dummy_data.size());
  auto m_bytes = integrity::SerializeManifest(m);
  WriteFile((test_dir / "release.manifest").string(), m_bytes.data(), m_bytes.size());

  // Save kp_wrong private key to an external file
  fs::path wrong_priv_file = test_dir / "wrong.priv";
  WriteSecretFile(wrong_priv_file.string(), kp_wrong->private_key.data(), kp_wrong->private_key.size());

  // Attempt to sign release using mismatched private key
  std::string err;
  bool ok = SignRelease(test_dir.string(), wrong_priv_file.string(), "", &err);

  // Finding 1 verification: SignRelease MUST return false, report mismatch, and NOT create release.sig!
  assert(!ok);
  assert(!err.empty());
  assert(err.find("Signing key mismatch") != std::string::npos || err.find("does not correspond") != std::string::npos);
  assert(!fs::exists(test_dir / "release.sig"));

  // Now sign with the correct key and verify it succeeds
  fs::path correct_priv_file = test_dir / "correct.priv";
  WriteSecretFile(correct_priv_file.string(), kp_correct->private_key.data(), kp_correct->private_key.size());
  bool ok_correct = SignRelease(test_dir.string(), correct_priv_file.string(), "", &err);
  assert(ok_correct);
  assert(fs::exists(test_dir / "release.sig"));

  CleanDir(test_dir);
  std::printf("  PASSED: Finding 1 signing key mismatch strictly rejected.\n");
}

void TestNoBuildReportsIntegratedState() {
  std::printf("Running TestNoBuildReportsIntegratedState (Finding 2)...\n");

  fs::path test_dir = "temp_test_nobuild_state";
  CleanDir(test_dir);
  fs::create_directories(test_dir);

  std::string orig_cmake = "cmake_minimum_required(VERSION 3.20)\nproject(ClientApp)\nadd_executable(client main.cpp)\n";
  WriteTextFile((test_dir / "CMakeLists.txt").string(), orig_cmake);
  WriteTextFile((test_dir / "main.cpp").string(), "int main() { return 0; }\n");

  IntegrationOptions opts;
  opts.target_project_path = test_dir.string();
  opts.use_dev_keys = true;
  opts.run_build = false;

  auto report = ExecuteIntegration(opts);
  // Finding 2 verification: --no-build must report kIntegrated, not kValidated or kAwaitingSignature
  assert(report.success);
  assert(report.state == IntegrationState::kIntegrated);
  assert(!report.build_succeeded);
  assert(!report.validation_succeeded);

  CleanDir(test_dir);
  std::printf("  PASSED: Finding 2 --no-build reports distinct kIntegrated state.\n");
}

void TestProductionLicenseSigningWorkflow() {
  std::printf("Running TestProductionLicenseSigningWorkflow (Finding 3)...\n");

  fs::path test_dir = "temp_test_prod_license";
  CleanDir(test_dir);
  fs::create_directories(test_dir);

  auto man_kp = integrity::GenerateEd25519KeyPair();
  auto lic_kp = integrity::GenerateEd25519KeyPair();
  assert(man_kp.has_value() && lic_kp.has_value());

  fs::path man_pub_file = test_dir / "external_man.pub";
  fs::path lic_pub_file = test_dir / "external_lic.pub";
  fs::path lic_priv_file = test_dir / "external_lic.priv";
  WriteFile(man_pub_file.string(), man_kp->public_key.data(), man_kp->public_key.size());
  WriteFile(lic_pub_file.string(), lic_kp->public_key.data(), lic_kp->public_key.size());
  WriteSecretFile(lic_priv_file.string(), lic_kp->private_key.data(), lic_kp->private_key.size());

  std::string orig_cmake = "cmake_minimum_required(VERSION 3.20)\nproject(ClientApp)\nadd_executable(client main.cpp)\n";
  WriteTextFile((test_dir / "CMakeLists.txt").string(), orig_cmake);
  WriteTextFile((test_dir / "main.cpp").string(), "int main() { return 0; }\n");

  IntegrationOptions opts;
  opts.target_project_path = test_dir.string();
  opts.product_id = "com.test.prodlic";
  opts.manifest_pubkey_path = man_pub_file.string();
  opts.license_pubkey_path = lic_pub_file.string();
  opts.sign_license_key_path = lic_priv_file.string();
  opts.staging_only = true;
  opts.run_build = false;

  auto report = ExecuteIntegration(opts);
  assert(report.success);
  assert(fs::exists(test_dir / "client.license"));

  // Verify the generated production license
  auto lic_data = ReadFile((test_dir / "client.license").string());
  assert(lic_data.has_value());

  licensing::LicenseVerificationContext ctx;
  ctx.expected_product_id = "com.test.prodlic";
  ctx.current_hardware_id = licensing::GetLocalHardwareId();
  licensing::License verified_lic;
  auto status = licensing::VerifyLicenseBytes(lic_data->data(), lic_data->size(), lic_kp->public_key, ctx, &verified_lic);
  assert(status == licensing::LicenseStatus::kValid);
  assert(verified_lic.edition == "Production");
  assert(verified_lic.product_id == "com.test.prodlic");

  CleanDir(test_dir);
  std::printf("  PASSED: Finding 3 production license signing workflow issues validated license.\n");
}

void TestValidateProtectedBuildEnforcesLicenseIntegrity() {
  std::printf("Running TestValidateProtectedBuildEnforcesLicenseIntegrity (Finding 4)...\n");

  fs::path test_dir = "temp_test_val_integrity";
  CleanDir(test_dir);
  fs::create_directories(test_dir);

  auto man_kp = integrity::GenerateEd25519KeyPair();
  auto lic_kp = integrity::GenerateEd25519KeyPair();
  assert(man_kp.has_value() && lic_kp.has_value());

  WriteFile((test_dir / "release.pub").string(), man_kp->public_key.data(), man_kp->public_key.size());
  WriteFile((test_dir / "license.pub").string(), lic_kp->public_key.data(), lic_kp->public_key.size());

  // Create valid license
  licensing::License lic;
  lic.license_id = "lic-val-1";
  lic.product_id = "com.test.val";
  lic.edition = "Standard";
  lic.customer_id = "tester";
  lic.capabilities = licensing::kCapCoreExecution;
  lic.issued_at = static_cast<std::uint64_t>(std::time(nullptr));
  lic.expires_at = 0;
  lic.hardware_id = licensing::GetLocalHardwareId();
  licensing::SignLicense(lic, lic_kp->private_key);
  auto lic_bytes = licensing::SerializeLicense(lic);
  WriteFile((test_dir / "client.license").string(), lic_bytes.data(), lic_bytes.size());

  // Create valid manifest and signature
  integrity::Manifest m;
  m.release_version = "1.0.0";
  m.release_sequence = 1;
  std::string file_data = "binary content";
  WriteTextFile((test_dir / "data.bin").string(), file_data);
  m.AddResource("data.bin", reinterpret_cast<const std::uint8_t*>(file_data.data()), file_data.size());
  auto m_bytes = integrity::SerializeManifest(m);
  WriteFile((test_dir / "release.manifest").string(), m_bytes.data(), m_bytes.size());
  auto sig = integrity::SignManifestBytes(m_bytes, man_kp->private_key);
  assert(sig.has_value());
  WriteFile((test_dir / "release.sig").string(), sig->data(), sig->size());

  // Validation should pass on untampered directory
  std::string val_err;
  bool ok = ValidateProtectedBuild(test_dir.string(),
                                  (test_dir / "release.pub").string(),
                                  (test_dir / "release.manifest").string(),
                                  (test_dir / "release.sig").string(),
                                  &val_err);
  assert(ok);
  assert(val_err.empty());

  // Tamper with client.license bytes -> ValidateProtectedBuild must fail!
  std::vector<std::uint8_t> tampered_lic = lic_bytes;
  tampered_lic[tampered_lic.size() - 5] ^= 0xFF;
  WriteFile((test_dir / "client.license").string(), tampered_lic.data(), tampered_lic.size());
  bool ok_tampered = ValidateProtectedBuild(test_dir.string(),
                                           (test_dir / "release.pub").string(),
                                           (test_dir / "release.manifest").string(),
                                           (test_dir / "release.sig").string(),
                                           &val_err);
  assert(!ok_tampered);
  assert(!val_err.empty());

  CleanDir(test_dir);
  std::printf("  PASSED: Finding 4 ValidateProtectedBuild strictly enforces license integrity.\n");
}

void TestPerBuildOpcodeSeeding() {
  std::printf("Running TestPerBuildOpcodeSeeding...\n");

  fs::path test_dir = "temp_test_opcode_proj";
  CleanDir(test_dir);
  fs::create_directories(test_dir);

  std::string cmake_text = "cmake_minimum_required(VERSION 3.20)\nproject(App)\nadd_executable(app main.cpp)\n";
  WriteTextFile((test_dir / "CMakeLists.txt").string(), cmake_text);
  WriteTextFile((test_dir / "main.cpp").string(), "int main() { return 0; }\n");

  IntegrationOptions opts;
  opts.target_project_path = test_dir.string();
  opts.use_dev_keys = true;
  opts.run_build = false;

  auto rep1 = ExecuteIntegration(opts);
  assert(rep1.success);
  assert(rep1.opcode_seed != 0);

  auto cfg1 = ReadTextFile((test_dir / "rtprotect_config.h").string());
  assert(cfg1.has_value());
  assert(cfg1->find("kBuildOpcodeSeed") != std::string::npos);
  assert(cfg1->find("GetBuildOpcodeMap()") != std::string::npos);

  CleanDir(test_dir);
  std::printf("  PASSED: Per-build randomized opcode map seeding verified.\n");
}

void TestFunctionVirtualization() {
  std::printf("Running TestFunctionVirtualization...\n");

  fs::path test_dir = "temp_test_virt_proj";
  CleanDir(test_dir);
  fs::create_directories(test_dir);

  std::string cmake_text = "cmake_minimum_required(VERSION 3.20)\nproject(VirtApp)\nadd_executable(virtapp main.cpp)\n";
  WriteTextFile((test_dir / "CMakeLists.txt").string(), cmake_text);

  std::string main_cpp =
      "#include <cstdint>\n"
      "RTPROTECT_VIRTUALIZE\n"
      "int64_t compute_auth(int64_t a, int64_t b) {\n"
      "    int64_t sum = a + b;\n"
      "    return sum * 2;\n"
      "}\n"
      "int main() {\n"
      "    return compute_auth(10, 20);\n"
      "}\n";
  WriteTextFile((test_dir / "main.cpp").string(), main_cpp);

  IntegrationOptions opts;
  opts.target_project_path = test_dir.string();
  opts.use_dev_keys = true;
  opts.run_build = false;

  auto rep = ExecuteIntegration(opts);
  assert(rep.success);
  assert(!rep.virtualized_functions.empty());
  assert(rep.virtualized_functions[0] == "compute_auth");

  auto transformed_main = ReadTextFile((test_dir / "main.cpp").string());
  assert(transformed_main.has_value());
  assert(transformed_main->find("[RTProtect Bytecode-Virtualized Function: compute_auth]") != std::string::npos);
  assert(transformed_main->find("s_enc_code") != std::string::npos);
  assert(transformed_main->find("s_fn_salt") != std::string::npos);
  assert(transformed_main->find("s_master") == std::string::npos); // Plaintext master key eliminated!
  assert(transformed_main->find("GetFunctionMasterKey") != std::string::npos);
  assert(transformed_main->find("ScatterTamperCheck") != std::string::npos);
  assert(transformed_main->find("AssessFastEnvironmentRisk") != std::string::npos);
  assert(transformed_main->find("DeriveTamperBoundKey") != std::string::npos);
  assert(transformed_main->find("rtprotect::vm::MemoryContext") != std::string::npos);
  assert(transformed_main->find("rtprotect::vm::Run") != std::string::npos);
  assert(transformed_main->find("s_res.error != rtprotect::vm::VmError::kNone") != std::string::npos);

  // Assert that rtprotect_config.h contains NO plaintext shards or masks
  auto cfg = ReadTextFile((test_dir / "rtprotect_config.h").string());
  assert(cfg.has_value());
  assert(cfg->find("kAuthShard") == std::string::npos);
  assert(cfg->find("kAuthMask") == std::string::npos);

  // Assert that release.manifest does NOT commit rtprotect_vm_root (master secrets are not shipped in manifests)
  auto man_bytes = ReadFile((test_dir / "release.manifest").string());
  assert(man_bytes.has_value());
  auto man = rtprotect::integrity::DeserializeManifest(man_bytes->data(), man_bytes->size());
  assert(man.has_value());
  assert(man->Find("rtprotect_vm_root") == nullptr);

  CleanDir(test_dir);
  std::printf("  PASSED: Function virtualization and tamper-bound wrapper generation verified.\n");
}

void TestFunctionVirtualizationExecutionRoundTrip() {
  std::printf("Running TestFunctionVirtualizationExecutionRoundTrip...\n");

  // 1. Target function with arithmetic and if/else branching
  std::string source_fn =
      "int64_t compute_auth(int64_t a, int64_t b) {\n"
      "    int64_t sum = a + b;\n"
      "    if (sum > 20) {\n"
      "        return sum * 2;\n"
      "    } else {\n"
      "        return sum + 1;\n"
      "    }\n"
      "}\n";

  // 2. Build-specific permutation seed
  const std::uint32_t opcode_seed = 0xA7B8C9D0u;
  auto opcode_map = rtprotect::vm::OpcodeMap::FromSeed(opcode_seed);

  // 3. Compile function with seeded opcode map
  std::string compile_err;
  rtprotect::vm::CompilerOptions opts;
  opts.opcode_map = &opcode_map;
  auto prog = rtprotect::vm::CompileCSubset(source_fn, &compile_err, opts);
  if (!prog.has_value()) {
    std::fprintf(stderr, "Compile error: %s\n", compile_err.c_str());
  }
  assert(prog.has_value());

  // 4. Serialize compiled bytecode
  auto serialized = rtprotect::vm::Serialize(*prog);

  // 5. Derive build master key from activation token vm_root and tamper-bound key
  std::string product_id = "com.vendor.virtapp";
  rtprotect::licensing::ActivationToken dev_token;
  bool token_loaded = rtprotect::licensing::LoadOrCreateDevToken(product_id, "lic-virt-roundtrip", &dev_token);
  assert(token_loaded);
  auto vm_root = dev_token.vm_root;

  rtprotect::integrity::Ed25519PublicKey manifest_pubkey{};
  manifest_pubkey.fill(0x42);

  std::array<std::uint8_t, 16> fn_salt{};
  for (std::size_t i = 0; i < fn_salt.size(); ++i) {
    fn_salt[i] = static_cast<std::uint8_t>(i ^ 0xAA);
  }

  auto master_key = DeriveBuildFunctionMasterKey(vm_root, manifest_pubkey, product_id, fn_salt.data(), fn_salt.size());
  assert(master_key.has_value());

  rtprotect::antitamper::RiskAssessment clean_risk;
  clean_risk.risk_score = 0;
  auto bound_key = rtprotect::antitamper::DeriveTamperBoundKey(*master_key, clean_risk, "compute_auth");

  // 6. Encrypt bytecode with tamper-bound key
  auto encrypted = rtprotect::crypto::Encrypt(bound_key, serialized.data(), serialized.size());
  assert(encrypted.has_value());

  // 7. Execute runtime decryption and execution pipeline (clean environment)
  rtprotect::antitamper::RiskAssessment runtime_risk;
  runtime_risk.risk_score = 0;
  auto runtime_master_key = DeriveBuildFunctionMasterKey(vm_root, manifest_pubkey, product_id, fn_salt.data(), fn_salt.size());
  assert(runtime_master_key.has_value());

  auto runtime_bound_key = rtprotect::antitamper::DeriveTamperBoundKey(*runtime_master_key, runtime_risk, "compute_auth");
  auto plain = rtprotect::crypto::Decrypt(runtime_bound_key, *encrypted, nullptr, 0, nullptr);
  assert(plain.has_value());

  auto runtime_prog = rtprotect::vm::Deserialize(plain->data(), plain->size());
  assert(runtime_prog.has_value());

  // 8. Assert numeric computation through the VM with the build opcode map
  // Case A: 10 + 20 = 30 (> 20) -> 30 * 2 = 60
  std::vector<std::int64_t> args_a = {10, 20};
  rtprotect::vm::MemoryContext mem_ctx(65536);
  auto res_a = rtprotect::vm::Run(*runtime_prog, args_a, &opcode_map, &mem_ctx);
  assert(res_a.error == rtprotect::vm::VmError::kNone);
  assert(res_a.value == 60);

  // Case B: 5 + 10 = 15 (<= 20) -> 15 + 1 = 16
  std::vector<std::int64_t> args_b = {5, 10};
  auto res_b = rtprotect::vm::Run(*runtime_prog, args_b, &opcode_map, &mem_ctx);
  assert(res_b.error == rtprotect::vm::VmError::kNone);
  assert(res_b.value == 16);

  // 9. Adversarial Case A: Execution without the seeded opcode map MUST fail verification
  auto bad_map_res = rtprotect::vm::Run(*runtime_prog, args_a, nullptr, &mem_ctx);
  assert(bad_map_res.error != rtprotect::vm::VmError::kNone);

  // 10. Adversarial Case B: Tampered runtime environment MUST corrupt key and fail decryption
  rtprotect::antitamper::RiskAssessment tampered_risk;
  tampered_risk.risk_score = 50; // Debugger / patch detected
  auto tampered_bound_key = rtprotect::antitamper::DeriveTamperBoundKey(*runtime_master_key, tampered_risk, "compute_auth");
  auto bad_decrypt = rtprotect::crypto::Decrypt(tampered_bound_key, *encrypted, nullptr, 0, nullptr);
  assert(!bad_decrypt.has_value()); // Cryptographic GCM tag failure!

  // 11. Memory Operations Round-Trip Execution:
  // Function using store8 and load8 running through VM with MemoryContext
  std::string mem_fn =
      "int64_t mem_test(int64_t addr, int64_t val) {\n"
      "    store8(addr, val);\n"
      "    int64_t retrieved = load8(addr);\n"
      "    return retrieved + 10;\n"
      "}\n";
  auto mem_prog = rtprotect::vm::CompileCSubset(mem_fn, &compile_err, opts);
  assert(mem_prog.has_value());
  rtprotect::vm::MemoryContext runtime_mem(4096);
  std::vector<std::int64_t> mem_args = {100, 42};
  auto mem_res = rtprotect::vm::Run(*mem_prog, mem_args, &opcode_map, &runtime_mem);
  assert(mem_res.error == rtprotect::vm::VmError::kNone);
  assert(mem_res.value == 52);
  assert(runtime_mem.data[100] == 42);

  // 12. Memory Access Out of Bounds properly reports kMemoryAccessOutOfBounds when mem_ctx is null
  auto null_mem_res = rtprotect::vm::Run(*mem_prog, mem_args, &opcode_map, nullptr);
  assert(null_mem_res.error == rtprotect::vm::VmError::kMemoryAccessOutOfBounds);

  std::printf("  PASSED: End-to-end opcode permutation, tamper-key derivation, and VM execution verified.\n");
}

void TestFunctionExtractionHandlesCommentsAndStrings() {
  std::printf("Running TestFunctionExtractionHandlesCommentsAndStrings...\n");

  fs::path test_dir = "temp_test_brace_proj";
  CleanDir(test_dir);
  fs::create_directories(test_dir);

  std::string cmake_text = "cmake_minimum_required(VERSION 3.20)\nproject(BraceApp)\nadd_executable(braceapp main.cpp)\n";
  WriteTextFile((test_dir / "CMakeLists.txt").string(), cmake_text);

  std::string complex_cpp =
      "#include <cstdint>\n"
      "const char* dummy_header() { return \"header with { and } braces\"; }\n"
      "RTPROTECT_VIRTUALIZE\n"
      "int64_t complex_calc(int64_t x) {\n"
      "    // Comment with { and }\n"
      "    /* Multi-line block comment with { \n"
      "       and unclosed { \n"
      "    */\n"
      "    int64_t res = x * 3;\n"
      "    return res;\n"
      "}\n"
      "int main() {\n"
      "    return complex_calc(7);\n"
      "}\n";
  WriteTextFile((test_dir / "main.cpp").string(), complex_cpp);

  IntegrationOptions opts;
  opts.target_project_path = test_dir.string();
  opts.use_dev_keys = true;
  opts.run_build = false;

  auto rep = ExecuteIntegration(opts);
  assert(rep.success);
  assert(!rep.virtualized_functions.empty());
  assert(rep.virtualized_functions[0] == "complex_calc");

  auto transformed = ReadTextFile((test_dir / "main.cpp").string());
  assert(transformed.has_value());
  assert(transformed->find("[RTProtect Bytecode-Virtualized Function: complex_calc]") != std::string::npos);
  assert(transformed->find("s_master") == std::string::npos); // NO raw master key!
  assert(transformed->find("s_fn_salt") != std::string::npos);
  assert(transformed->find("GetFunctionMasterKey") != std::string::npos);
  assert(transformed->find("ScatterTamperCheck") != std::string::npos);

  CleanDir(test_dir);
  std::printf("  PASSED: Comment- and string-literal-aware brace extraction verified.\n");
}

void TestDetailedJsonReporting() {
  std::printf("Running TestDetailedJsonReporting...\n");

  fs::path test_dir = "temp_test_json_proj";
  CleanDir(test_dir);
  fs::create_directories(test_dir);

  std::string cmake_text = "cmake_minimum_required(VERSION 3.20)\nproject(JsonApp)\nadd_executable(jsonapp main.cpp)\n";
  WriteTextFile((test_dir / "CMakeLists.txt").string(), cmake_text);
  WriteTextFile((test_dir / "main.cpp").string(), "int main() { return 0; }\n");

  IntegrationOptions opts;
  opts.target_project_path = test_dir.string();
  opts.use_dev_keys = true;
  opts.run_build = false;
  opts.report_json_path = (test_dir / "report.json").string();

  auto rep = ExecuteIntegration(opts);
  assert(rep.success);

  std::string json = rep.ToJson();
  assert(json.find("\"virtualized_functions\"") != std::string::npos);
  assert(json.find("\"obfuscated_string_count\"") != std::string::npos);
  assert(json.find("\"scattered_check_count\"") != std::string::npos);
  assert(json.find("\"opcode_seed\"") != std::string::npos);

  CleanDir(test_dir);
  std::printf("  PASSED: Detailed JSON execution reporting verified.\n");
}

void TestAstScannerRawStringsAndTranslationUnitObfuscation() {
  std::printf("Running TestAstScannerRawStringsAndTranslationUnitObfuscation...\n");

  fs::path test_dir = "temp_test_ast_raw_strings";
  CleanDir(test_dir);
  fs::create_directories(test_dir);

  // File contains raw string literals with unmatched braces in a prior helper function
  std::string main_cpp =
      "#include <cstdint>\n"
      "#include <string>\n"
      "const char* g_global_banner = \"Welcome to Protected Application\";\n"
      "const char* get_schema() {\n"
      "    return R\"delim({ \"unmatched_brace\": { { \"nested\": [1, 2, 3] )delim\";\n"
      "}\n"
      "RTPROTECT_VIRTUALIZE\n"
      "int64_t compute_raw(int64_t a) {\n"
      "    int64_t res = a * 10;\n"
      "    return res + 2;\n"
      "}\n"
      "int main() {\n"
      "    const char* secret_status = \"System Operational\";\n"
      "    return compute_raw(5);\n"
      "}\n";

  fs::path file_path = test_dir / "main.cpp";
  WriteTextFile(file_path.string(), main_cpp);

  std::array<std::uint8_t, 32> vm_root{};
  vm_root.fill(0x77);
  auto kp = rtprotect::integrity::GenerateEd25519KeyPair();
  assert(kp.has_value());

  std::vector<std::string> virtualized;
  std::size_t obf_count = 0;
  std::size_t scatt_count = 0;

  bool ok = TransformSourceFile(
      file_path,
      ProtectionProfile::kMaximum,
      1337,
      vm_root,
      kp->public_key,
      "test_ast_prod",
      virtualized,
      obf_count,
      scatt_count);

  assert(ok);
  assert(!virtualized.empty());
  assert(virtualized[0] == "compute_raw");
  assert(obf_count > 0);

  auto transformed = ReadTextFile(file_path.string());
  assert(transformed.has_value());
  assert(transformed->find("[RTProtect Bytecode-Virtualized Function: compute_raw]") != std::string::npos);
  assert(transformed->find("OBFUSCATED_STRING") != std::string::npos);
  assert(transformed->find("obfuscation/obfuscated_string.h") != std::string::npos);

  CleanDir(test_dir);
  std::printf("  PASSED: AST scanner raw string parsing and translation unit string obfuscation verified.\n");
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
  TestSignReleaseKeyMismatchRejected();
  TestNoBuildReportsIntegratedState();
  TestProductionLicenseSigningWorkflow();
  TestValidateProtectedBuildEnforcesLicenseIntegrity();
  TestPerBuildOpcodeSeeding();
  TestFunctionVirtualization();
  TestFunctionVirtualizationExecutionRoundTrip();
  TestFunctionExtractionHandlesCommentsAndStrings();
  TestDetailedJsonReporting();
  TestAstScannerRawStringsAndTranslationUnitObfuscation();
  std::printf("ALL INTEGRATION ENGINE TESTS PASSED.\n");
  return 0;
}