// tooling/integration_engine.cpp

#include "tooling/integration_engine.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "antitamper/risk_policy.h"
#include "integrity/keys.h"
#include "integrity/manifest.h"
#include "integrity/signer.h"
#include "integrity/verifier.h"
#include "licensing/hardware_id.h"
#include "licensing/license.h"
#include "licensing/license_signer.h"
#include "licensing/license_verifier.h"
#include "tooling/file_io.h"

namespace fs = std::filesystem;

namespace rtprotect::tooling {

const char* ToString(ProtectionProfile p) {
  switch (p) {
    case ProtectionProfile::kDevelopment: return "development";
    case ProtectionProfile::kBalanced: return "balanced";
    case ProtectionProfile::kMaximum: return "maximum";
  }
  return "unknown";
}

ProtectionProfile ParseProfile(const std::string& str) {
  if (str == "dev" || str == "development") return ProtectionProfile::kDevelopment;
  if (str == "max" || str == "maximum") return ProtectionProfile::kMaximum;
  return ProtectionProfile::kBalanced;
}

std::string ChangePlan::FormatSummary() const {
  std::ostringstream ss;
  ss << "RTProtect Integration Change Plan\n";
  ss << "=================================\n";
  ss << "Detected Language:     " << detected_language << "\n";
  ss << "Detected Build System: " << detected_build_system << "\n";
  ss << "Detected Sources:      " << detected_sources.size() << " file(s)\n";
  for (const auto& s : detected_sources) {
    ss << "  - " << s << "\n";
  }
  ss << "\nFiles to Create:\n";
  for (const auto& f : files_to_create) {
    ss << "  + " << f << "\n";
  }
  ss << "\nFiles to Modify:\n";
  for (const auto& f : files_to_modify) {
    ss << "  * " << f << "\n";
  }
  if (!warnings.empty()) {
    ss << "\nWarnings:\n";
    for (const auto& w : warnings) {
      ss << "  ! " << w << "\n";
    }
  }
  ss << "Supported: " << (is_supported ? "YES" : "NO") << "\n";
  return ss.str();
}

std::string IntegrationReport::ToJson() const {
  std::ostringstream ss;
  ss << "{\n";
  ss << "  \"success\": " << (success ? "true" : "false") << ",\n";
  ss << "  \"error_message\": \"" << error_message << "\",\n";
  ss << "  \"backup_path\": \"" << backup_path << "\",\n";
  ss << "  \"build_succeeded\": " << (build_succeeded ? "true" : "false") << ",\n";
  ss << "  \"validation_succeeded\": " << (validation_succeeded ? "true" : "false") << ",\n";

  auto write_array = [&](const char* name, const std::vector<std::string>& list, bool trailing_comma) {
    ss << "  \"" << name << "\": [";
    for (std::size_t i = 0; i < list.size(); ++i) {
      ss << "\"" << list[i] << "\"";
      if (i + 1 < list.size()) ss << ", ";
    }
    ss << "]" << (trailing_comma ? "," : "") << "\n";
  };

  write_array("modified_files", modified_files, true);
  write_array("generated_files", generated_files, true);
  write_array("warnings", warnings, true);

  ss << "  \"public_key_file\": \"" << public_key_file << "\",\n";
  ss << "  \"manifest_file\": \"" << manifest_file << "\",\n";
  ss << "  \"license_file\": \"" << license_file << "\"\n";
  ss << "}\n";
  return ss.str();
}

namespace {

bool IsPathWithin(const fs::path& child, const fs::path& base) {
  auto abs_child = fs::weakly_canonical(child);
  auto abs_base = fs::weakly_canonical(base);
  auto child_str = abs_child.string();
  auto base_str = abs_base.string();
  return child_str.rfind(base_str, 0) == 0;
}

}  // namespace

ChangePlan PlanIntegration(const IntegrationOptions& options) {
  ChangePlan plan;
  if (options.target_project_path.empty()) {
    plan.explanation = "Target project path is empty";
    return plan;
  }

  std::error_code ec;
  fs::path proj_path = fs::canonical(options.target_project_path, ec);
  if (ec || !fs::is_directory(proj_path)) {
    plan.explanation = "Target project path does not exist or is not a directory";
    return plan;
  }

  // Detect build system
  fs::path cmake_file = proj_path / "CMakeLists.txt";
  if (fs::exists(cmake_file)) {
    plan.detected_build_system = "CMake";
    plan.detected_language = "C++";
    plan.is_supported = true;
    plan.files_to_modify.push_back((proj_path / "CMakeLists.txt").string());
  } else {
    plan.explanation = "No supported build system found (CMakeLists.txt required)";
    return plan;
  }

  // Scan sources
  for (const auto& entry : fs::recursive_directory_iterator(proj_path, ec)) {
    if (entry.is_regular_file()) {
      auto ext = entry.path().extension().string();
      if (ext == ".cpp" || ext == ".cc" || ext == ".cxx" || ext == ".c") {
        plan.detected_sources.push_back(entry.path().string());
      }
    }
  }

  if (plan.detected_sources.empty()) {
    plan.warnings.push_back("No C/C++ source files found in target directory");
  }

  plan.files_to_create.push_back((proj_path / "rtprotect_config.h").string());
  plan.files_to_create.push_back((proj_path / "rtprotect_runtime_glue.cpp").string());
  plan.files_to_create.push_back((proj_path / "release.pub").string());
  plan.files_to_create.push_back((proj_path / "release.priv").string());
  plan.files_to_create.push_back((proj_path / "release.manifest").string());
  plan.files_to_create.push_back((proj_path / "release.sig").string());
  plan.files_to_create.push_back((proj_path / "client.license").string());

  return plan;
}

IntegrationReport ExecuteIntegration(const IntegrationOptions& options) {
  IntegrationReport report;
  auto plan = PlanIntegration(options);
  if (!plan.is_supported) {
    report.success = false;
    report.error_message = plan.explanation;
    return report;
  }

  fs::path proj_path = fs::canonical(options.target_project_path);

  // If dry-run requested, report planned changes and exit
  if (options.dry_run) {
    report.success = true;
    report.modified_files = plan.files_to_modify;
    report.generated_files = plan.files_to_create;
    report.warnings = plan.warnings;
    if (!options.report_json_path.empty()) {
      WriteTextFile(options.report_json_path, report.ToJson());
    }
    return report;
  }

  // 1. Transactional Backup
  auto now = std::chrono::system_clock::now().time_since_epoch();
  auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(now).count();
  fs::path backup_dir = options.backup_dir.empty()
      ? (proj_path / (".rtprotect_backup_" + std::to_string(timestamp)))
      : fs::path(options.backup_dir);

  std::error_code ec;
  fs::create_directories(backup_dir, ec);
  if (ec) {
    report.success = false;
    report.error_message = "Failed to create backup directory: " + backup_dir.string();
    return report;
  }

  report.backup_path = backup_dir.string();

  // Backup CMakeLists.txt and any modified files
  for (const auto& file_str : plan.files_to_modify) {
    fs::path src(file_str);
    if (fs::exists(src)) {
      auto rel = fs::relative(src, proj_path);
      auto dest = backup_dir / rel;
      fs::create_directories(dest.parent_path(), ec);
      fs::copy_file(src, dest, fs::copy_options::overwrite_existing, ec);
    }
  }

  // 2. Key Generation
  auto keypair = integrity::GenerateEd25519KeyPair();
  if (!keypair.has_value()) {
    report.success = false;
    report.error_message = "Failed to generate Ed25519 signing keypair";
    return report;
  }

  fs::path pub_path = proj_path / "release.pub";
  fs::path priv_path = proj_path / "release.priv";
  WriteFile(pub_path.string(), keypair->public_key.data(), keypair->public_key.size());
  WriteSecretFile(priv_path.string(), keypair->private_key.data(), keypair->private_key.size());

  report.public_key_file = pub_path.string();
  report.private_key_file = priv_path.string();
  report.generated_files.push_back(pub_path.string());
  report.generated_files.push_back(priv_path.string());

  // 3. Generate rtprotect_config.h
  fs::path config_header_path = proj_path / "rtprotect_config.h";
  {
    std::ostringstream ss;
    ss << "// Generated by RTProtect Integration Engine\n";
    ss << "#pragma once\n\n";
    ss << "#include <cstdint>\n";
    ss << "#include <array>\n\n";
    ss << "namespace rtprotect_client {\n\n";
    ss << "inline constexpr const char* kProductId = \"" << options.product_id << "\";\n";
    ss << "inline constexpr const char* kReleaseVersion = \"" << options.release_version << "\";\n";
    ss << "inline constexpr const char* kProtectionProfile = \"" << ToString(options.profile) << "\";\n\n";

    ss << "// Embedded Ed25519 Public Verification Key\n";
    ss << "inline constexpr std::array<std::uint8_t, 32> kPublicKey = {\n  ";
    for (std::size_t i = 0; i < keypair->public_key.size(); ++i) {
      char h[8];
      std::snprintf(h, sizeof(h), "0x%02X", keypair->public_key[i]);
      ss << h;
      if (i + 1 < keypair->public_key.size()) ss << ", ";
      if ((i + 1) % 8 == 0 && i + 1 < keypair->public_key.size()) ss << "\n  ";
    }
    ss << "\n};\n\n";
    ss << "bool VerifyClientIntegrityAndLicense();\n\n";
    ss << "}  // namespace rtprotect_client\n";

    WriteTextFile(config_header_path.string(), ss.str());
    report.generated_files.push_back(config_header_path.string());
  }

  // 4. Generate rtprotect_runtime_glue.cpp
  fs::path glue_path = proj_path / "rtprotect_runtime_glue.cpp";
  {
    std::ostringstream ss;
    ss << "// Generated by RTProtect Integration Engine\n";
    ss << "#include \"rtprotect_config.h\"\n";
    ss << "#include \"licensing/license.h\"\n";
    ss << "#include \"licensing/license_verifier.h\"\n";
    ss << "#include \"licensing/hardware_id.h\"\n";
    ss << "#include \"integrity/manifest.h\"\n";
    ss << "#include \"integrity/verifier.h\"\n";
    ss << "#include \"antitamper/risk_policy.h\"\n";
    ss << "#include \"tooling/file_io.h\"\n";
    ss << "#include <ctime>\n\n";

    ss << "namespace rtprotect_client {\n\n";
    ss << "bool VerifyClientIntegrityAndLicense() {\n";
    ss << "  // 1. Runtime risk assessment\n";
    ss << "  auto risk = rtprotect::antitamper::AssessEnvironmentRisk();\n";
    if (options.profile == ProtectionProfile::kMaximum) {
      ss << "  if (!rtprotect::antitamper::EnforceRiskPolicy(rtprotect::antitamper::RiskAction::kTerminate, risk)) return false;\n";
    } else if (options.profile == ProtectionProfile::kBalanced) {
      ss << "  if (!rtprotect::antitamper::EnforceRiskPolicy(rtprotect::antitamper::RiskAction::kRestrict, risk)) return false;\n";
    } else {
      ss << "  rtprotect::antitamper::EnforceRiskPolicy(rtprotect::antitamper::RiskAction::kReportOnly, risk);\n";
    }
    ss << "\n  // 2. Client license verification\n";
    ss << "  auto lic_data = rtprotect::tooling::ReadFile(\"client.license\");\n";
    ss << "  if (!lic_data.has_value()) return false;\n";
    ss << "  rtprotect::licensing::LicenseVerificationContext ctx;\n";
    ss << "  ctx.current_time = static_cast<std::uint64_t>(std::time(nullptr));\n";
    ss << "  ctx.expected_product_id = kProductId;\n";
    ss << "  ctx.current_hardware_id = rtprotect::licensing::GetLocalHardwareId();\n";
    ss << "  rtprotect::licensing::License lic;\n";
    ss << "  auto lic_status = rtprotect::licensing::VerifyLicenseBytes(lic_data->data(), lic_data->size(), kPublicKey, ctx, &lic);\n";
    ss << "  if (lic_status != rtprotect::licensing::LicenseStatus::kValid) return false;\n";
    ss << "\n  // 3. Manifest signature check\n";
    ss << "  auto man_bytes = rtprotect::tooling::ReadFile(\"release.manifest\");\n";
    ss << "  auto sig_bytes = rtprotect::tooling::ReadFile(\"release.sig\");\n";
    ss << "  if (!man_bytes.has_value() || !sig_bytes.has_value() || sig_bytes->size() != 64) return false;\n";
    ss << "  rtprotect::integrity::Ed25519Signature sig;\n";
    ss << "  std::memcpy(sig.data(), sig_bytes->data(), 64);\n";
    ss << "  if (!rtprotect::integrity::VerifyManifestSignature(*man_bytes, sig, kPublicKey)) return false;\n";
    ss << "  return true;\n";
    ss << "}\n\n";
    ss << "}  // namespace rtprotect_client\n";

    WriteTextFile(glue_path.string(), ss.str());
    report.generated_files.push_back(glue_path.string());
  }

  // 5. Update CMakeLists.txt
  fs::path cmake_path = proj_path / "CMakeLists.txt";
  auto cmake_content = ReadTextFile(cmake_path.string());
  if (cmake_content.has_value()) {
    std::string root = options.rtprotect_root.empty() ? "." : options.rtprotect_root;
    std::replace(root.begin(), root.end(), '\\', '/');

    std::string target_name;
    auto pos = cmake_content->find("add_executable(");
    if (pos != std::string::npos) {
      pos += 15;
      while (pos < cmake_content->size() && std::isspace(static_cast<unsigned char>((*cmake_content)[pos]))) pos++;
      auto end_pos = pos;
      while (end_pos < cmake_content->size() && !std::isspace(static_cast<unsigned char>((*cmake_content)[end_pos])) && (*cmake_content)[end_pos] != ')') {
        end_pos++;
      }
      if (end_pos > pos) {
        target_name = cmake_content->substr(pos, end_pos - pos);
      }
    }

    std::ostringstream ss;
    ss << "\n# --- Added by RTProtect Integration Tool ---\n";
    ss << "include_directories(\"" << root << "\")\n";
    ss << "include_directories(\"" << root << "/third_party/openssl/include\")\n";
    if (!target_name.empty()) {
      ss << "target_link_directories(" << target_name << " PRIVATE\n";
      ss << "    \"" << root << "/build/integrity\"\n";
      ss << "    \"" << root << "/build/licensing\"\n";
      ss << "    \"" << root << "/build/antitamper\"\n";
      ss << "    \"" << root << "/build/crypto\"\n";
      ss << "    \"" << root << "/third_party/openssl/lib\"\n";
      ss << ")\n";
      ss << "target_sources(" << target_name << " PRIVATE rtprotect_runtime_glue.cpp)\n";
      ss << "target_link_libraries(" << target_name << " PRIVATE\n";
      ss << "    rtprotect_licensing\n";
      ss << "    rtprotect_integrity\n";
      ss << "    rtprotect_antitamper\n";
      ss << "    rtprotect_crypto\n";
      ss << "    \"" << root << "/third_party/openssl/lib/libcrypto.lib\"\n";
      ss << "    iphlpapi\n";
      ss << "    ws2_32\n";
      ss << ")\n";
    }
    ss << "\n# Compiler Hardening Profile: " << ToString(options.profile) << "\n";
    if (options.profile == ProtectionProfile::kMaximum) {
      ss << "if(MSVC)\n  add_compile_options(/guard:cf /DYNAMICBASE /NXCOMPAT)\n";
      ss << "else()\n  add_compile_options(-fstack-protector-strong -fPIE)\n  add_link_options(-pie)\nendif()\n";
    } else if (options.profile == ProtectionProfile::kBalanced) {
      ss << "if(NOT MSVC)\n  add_compile_options(-fstack-protector)\nendif()\n";
    }

    std::string updated_cmake = *cmake_content + ss.str();
    WriteTextFile(cmake_path.string(), updated_cmake);
    report.modified_files.push_back(cmake_path.string());
  }

  // 6. Generate Initial Release Manifest and Sign it
  fs::path manifest_path = proj_path / "release.manifest";
  fs::path sig_path = proj_path / "release.sig";
  {
    integrity::Manifest manifest;
    manifest.release_version = options.release_version;
    manifest.release_sequence = 1;

    // Commit config and glue
    auto cfg_data = ReadFile(config_header_path.string());
    if (cfg_data.has_value()) {
      manifest.AddResource("rtprotect_config.h", cfg_data->data(), cfg_data->size());
    }

    auto man_bytes = integrity::SerializeManifest(manifest);
    WriteFile(manifest_path.string(), man_bytes.data(), man_bytes.size());

    auto sig = integrity::SignManifestBytes(man_bytes, keypair->private_key);
    if (sig.has_value()) {
      WriteFile(sig_path.string(), sig->data(), sig->size());
    }

    report.manifest_file = manifest_path.string();
    report.signature_file = sig_path.string();
    report.generated_files.push_back(manifest_path.string());
    report.generated_files.push_back(sig_path.string());
  }

  // 7. Generate Default Client License
  fs::path lic_path = proj_path / "client.license";
  {
    licensing::License lic;
    lic.license_id = "lic-auto-" + std::to_string(timestamp);
    lic.product_id = options.product_id;
    lic.edition = "Standard";
    lic.customer_id = "client@domain.local";
    lic.capabilities = licensing::kCapCoreExecution | licensing::kCapCommercialUse;
    lic.issued_at = static_cast<std::uint64_t>(std::time(nullptr));
    lic.expires_at = 0; // Perpetual
    lic.hardware_id = licensing::GetLocalHardwareId();
    licensing::SignLicense(lic, keypair->private_key);

    auto lic_bytes = licensing::SerializeLicense(lic);
    WriteFile(lic_path.string(), lic_bytes.data(), lic_bytes.size());

    report.license_file = lic_path.string();
    report.generated_files.push_back(lic_path.string());
  }

  report.success = true;

  if (options.run_build) {
    fs::path build_dir = proj_path / "build_protected";
    std::string config_cmd = "cmake -B \"" + build_dir.string() + "\" -S \"" + proj_path.string() + "\"";
    std::string build_cmd = "cmake --build \"" + build_dir.string() + "\"";

    int cr = std::system(config_cmd.c_str());
    int br = (cr == 0) ? std::system(build_cmd.c_str()) : 1;
    report.build_succeeded = (br == 0);

    // Validate
    std::string val_err;
    report.validation_succeeded = ValidateProtectedBuild(
        proj_path.string(), pub_path.string(), manifest_path.string(), sig_path.string(), &val_err);
    if (!val_err.empty()) {
      report.warnings.push_back(val_err);
    }
  }

  if (!options.report_json_path.empty()) {
    WriteTextFile(options.report_json_path, report.ToJson());
  }

  return report;
}

bool ExecuteRollback(const std::string& target_project_path,
                     const std::string& backup_dir,
                     std::string* error_out) {
  std::error_code ec;
  fs::path proj_path = fs::canonical(target_project_path, ec);
  if (ec || !fs::is_directory(proj_path)) {
    if (error_out) *error_out = "Target project directory does not exist";
    return false;
  }

  fs::path bkp_path = fs::canonical(backup_dir, ec);
  if (ec || !fs::is_directory(bkp_path)) {
    if (error_out) *error_out = "Backup directory does not exist: " + backup_dir;
    return false;
  }

  // Restore backed-up files
  for (const auto& entry : fs::recursive_directory_iterator(bkp_path, ec)) {
    if (entry.is_regular_file()) {
      auto rel = fs::relative(entry.path(), bkp_path);
      auto dest = proj_path / rel;
      if (!IsPathWithin(dest, proj_path)) {
        if (error_out) *error_out = "Path traversal detected in backup target: " + dest.string();
        return false;
      }
      fs::create_directories(dest.parent_path(), ec);
      fs::copy_file(entry.path(), dest, fs::copy_options::overwrite_existing, ec);
      if (ec) {
        if (error_out) *error_out = "Failed restoring: " + dest.string();
        return false;
      }
    }
  }

  // Remove generated files
  std::vector<std::string> to_remove = {
    "rtprotect_config.h",
    "rtprotect_runtime_glue.cpp",
    "release.pub",
    "release.priv",
    "release.manifest",
    "release.sig",
    "client.license"
  };
  for (const auto& f : to_remove) {
    fs::path target_file = proj_path / f;
    if (fs::exists(target_file)) {
      fs::remove(target_file, ec);
    }
  }

  return true;
}

bool ValidateProtectedBuild(const std::string& project_dir,
                            const std::string& public_key_path,
                            const std::string& manifest_path,
                            const std::string& signature_path,
                            std::string* error_out) {
  auto pub_bytes = ReadFile(public_key_path);
  if (!pub_bytes.has_value() || pub_bytes->size() != 32) {
    if (error_out) *error_out = "Invalid or missing public key file";
    return false;
  }

  auto man_bytes = ReadFile(manifest_path);
  if (!man_bytes.has_value()) {
    if (error_out) *error_out = "Missing manifest file";
    return false;
  }

  auto sig_bytes = ReadFile(signature_path);
  if (!sig_bytes.has_value() || sig_bytes->size() != 64) {
    if (error_out) *error_out = "Invalid or missing signature file";
    return false;
  }

  integrity::Ed25519PublicKey pub;
  std::memcpy(pub.data(), pub_bytes->data(), 32);

  integrity::Ed25519Signature sig;
  std::memcpy(sig.data(), sig_bytes->data(), 64);

  if (!integrity::VerifyManifestSignature(*man_bytes, sig, pub)) {
    if (error_out) *error_out = "Manifest digital signature verification failed";
    return false;
  }

  auto manifest = integrity::DeserializeManifest(man_bytes->data(), man_bytes->size());
  if (!manifest.has_value()) {
    if (error_out) *error_out = "Failed deserializing signed manifest";
    return false;
  }

  fs::path root(project_dir);
  for (const auto& res : manifest->resources) {
    fs::path res_path = root / res.name;
    auto data = ReadFile(res_path.string());
    if (!data.has_value()) {
      if (error_out) *error_out = "Committed resource missing on disk: " + res.name;
      return false;
    }
    auto err = integrity::CheckResource(*manifest, res.name, data->data(), data->size());
    if (err != integrity::IntegrityError::kNone) {
      if (error_out) *error_out = std::string("Committed resource verification failed: ") + res.name;
      return false;
    }
  }

  return true;
}

}  // namespace rtprotect::tooling
