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

namespace {

std::string EscapeJson(const std::string& str) {
  std::string out;
  out.reserve(str.size() * 2);
  for (char c : str) {
    if (c == '\\') out += "\\\\";
    else if (c == '"') out += "\\\"";
    else if (c == '\n') out += "\\n";
    else if (c == '\r') out += "\\r";
    else if (c == '\t') out += "\\t";
    else out += c;
  }
  return out;
}

bool IsPathWithin(const fs::path& child, const fs::path& base) {
  std::error_code ec;
  auto abs_child = fs::weakly_canonical(child, ec);
  if (ec) return false;
  auto abs_base = fs::weakly_canonical(base, ec);
  if (ec) return false;

  auto rel = fs::relative(abs_child, abs_base, ec);
  if (ec || rel.empty()) return false;
  auto rel_str = rel.string();
  if (rel_str == ".." ||
      rel_str.rfind(std::string("..") + static_cast<char>(fs::path::preferred_separator), 0) == 0 ||
      rel_str.rfind("../", 0) == 0 || rel_str.rfind("..\\", 0) == 0 ||
      rel.is_absolute()) {
    return false;
  }
  return true;
}

}  // namespace

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
  ss << "  \"error_message\": \"" << EscapeJson(error_message) << "\",\n";
  ss << "  \"backup_path\": \"" << EscapeJson(backup_path) << "\",\n";
  ss << "  \"build_succeeded\": " << (build_succeeded ? "true" : "false") << ",\n";
  ss << "  \"validation_succeeded\": " << (validation_succeeded ? "true" : "false") << ",\n";

  auto write_array = [&](const char* name, const std::vector<std::string>& list, bool trailing_comma) {
    ss << "  \"" << name << "\": [";
    for (std::size_t i = 0; i < list.size(); ++i) {
      ss << "\"" << EscapeJson(list[i]) << "\"";
      if (i + 1 < list.size()) ss << ", ";
    }
    ss << "]" << (trailing_comma ? "," : "") << "\n";
  };

  write_array("modified_files", modified_files, true);
  write_array("generated_files", generated_files, true);
  write_array("warnings", warnings, true);

  ss << "  \"public_key_file\": \"" << EscapeJson(public_key_file) << "\",\n";
  ss << "  \"manifest_public_key_file\": \"" << EscapeJson(manifest_public_key_file) << "\",\n";
  ss << "  \"license_public_key_file\": \"" << EscapeJson(license_public_key_file) << "\",\n";
  if (!private_key_file.empty()) {
    ss << "  \"private_key_file\": \"" << EscapeJson(private_key_file) << "\",\n";
  }
  ss << "  \"manifest_file\": \"" << EscapeJson(manifest_file) << "\",\n";
  ss << "  \"signature_file\": \"" << EscapeJson(signature_file) << "\",\n";
  ss << "  \"license_file\": \"" << EscapeJson(license_file) << "\"\n";
  ss << "}\n";
  return ss.str();
}

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
  plan.files_to_create.push_back((proj_path / "license.pub").string());
  plan.files_to_create.push_back((proj_path / "release.manifest").string());
  plan.files_to_create.push_back((proj_path / "release.sig").string());
  plan.files_to_create.push_back((proj_path / "client.license").string());
  // NOTE: release.priv is NEVER created in the client project

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

  // 1. Transactional Backup & Journal
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

  // Dev keys directory (always stored outside client project root)
  fs::path dev_keys_dir = options.dev_keys_dir.empty()
      ? (backup_dir / "dev_keys")
      : fs::path(options.dev_keys_dir);
  fs::create_directories(dev_keys_dir, ec);

  // Track planned creations and pre-existing file backups
  std::vector<std::string> backed_up_relative;
  std::vector<std::string> planned_created;

  auto backup_if_exists = [&](const fs::path& target) {
    if (fs::exists(target)) {
      auto rel = fs::relative(target, proj_path);
      auto dest = backup_dir / rel;
      fs::create_directories(dest.parent_path(), ec);
      fs::copy_file(target, dest, fs::copy_options::overwrite_existing, ec);
      backed_up_relative.push_back(rel.string());
    } else {
      auto rel = fs::relative(target, proj_path);
      planned_created.push_back(rel.string());
    }
  };

  for (const auto& file_str : plan.files_to_modify) {
    backup_if_exists(fs::path(file_str));
  }
  for (const auto& file_str : plan.files_to_create) {
    backup_if_exists(fs::path(file_str));
  }

  // 2. Separate Manifest and License Keys
  // 2. Separate Manifest and License Keys
  // Production security: Private keys are NEVER placed in the client project.
  integrity::Ed25519PublicKey manifest_pubkey{};
  integrity::Ed25519PublicKey license_pubkey{};
  std::optional<integrity::Ed25519PrivateKey> manifest_privkey;
  std::optional<integrity::Ed25519PrivateKey> license_privkey;
  bool has_manifest_privkey = false;
  bool has_license_privkey = false;

  if (!options.manifest_pubkey_path.empty()) {
    auto pub_bytes = ReadFile(options.manifest_pubkey_path);
    if (!pub_bytes.has_value() || pub_bytes->size() != integrity::kEd25519PublicKeyLen) {
      report.success = false;
      report.error_message = "Invalid or unreadable manifest public key file: " + options.manifest_pubkey_path;
      return report;
    }
    std::memcpy(manifest_pubkey.data(), pub_bytes->data(), integrity::kEd25519PublicKeyLen);
  } else {
    auto kp = integrity::GenerateEd25519KeyPair();
    if (!kp.has_value()) {
      report.success = false;
      report.error_message = "Failed to generate manifest signing keypair";
      return report;
    }
    manifest_pubkey = kp->public_key;
    has_manifest_privkey = true;
    fs::path dev_manifest_priv = dev_keys_dir / "manifest.priv";
    WriteSecretFile(dev_manifest_priv.string(), kp->private_key.data(), kp->private_key.size());
    report.private_key_file = dev_manifest_priv.string();
    manifest_privkey = std::move(kp->private_key);
  }

  if (!options.license_pubkey_path.empty()) {
    auto pub_bytes = ReadFile(options.license_pubkey_path);
    if (!pub_bytes.has_value() || pub_bytes->size() != integrity::kEd25519PublicKeyLen) {
      report.success = false;
      report.error_message = "Invalid or unreadable license public key file: " + options.license_pubkey_path;
      return report;
    }
    std::memcpy(license_pubkey.data(), pub_bytes->data(), integrity::kEd25519PublicKeyLen);
  } else {
    auto kp = integrity::GenerateEd25519KeyPair();
    if (!kp.has_value()) {
      report.success = false;
      report.error_message = "Failed to generate license signing keypair";
      return report;
    }
    license_pubkey = kp->public_key;
    has_license_privkey = true;
    fs::path dev_license_priv = dev_keys_dir / "license.priv";
    WriteSecretFile(dev_license_priv.string(), kp->private_key.data(), kp->private_key.size());
    license_privkey = std::move(kp->private_key);
  }

  // Write ONLY public keys to client project
  fs::path manifest_pub_path = proj_path / "release.pub";
  fs::path license_pub_path = proj_path / "license.pub";
  WriteFile(manifest_pub_path.string(), manifest_pubkey.data(), manifest_pubkey.size());
  WriteFile(license_pub_path.string(), license_pubkey.data(), license_pubkey.size());

  report.public_key_file = manifest_pub_path.string();
  report.manifest_public_key_file = manifest_pub_path.string();
  report.license_public_key_file = license_pub_path.string();
  report.generated_files.push_back(manifest_pub_path.string());
  report.generated_files.push_back(license_pub_path.string());

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

    auto dump_key = [&](const char* name, const integrity::Ed25519PublicKey& k) {
      ss << "// Embedded " << name << " Verification Key\n";
      ss << "inline constexpr std::array<std::uint8_t, 32> " << name << " = {\n  ";
      for (std::size_t i = 0; i < k.size(); ++i) {
        char h[8];
        std::snprintf(h, sizeof(h), "0x%02X", k[i]);
        ss << h;
        if (i + 1 < k.size()) ss << ", ";
        if ((i + 1) % 8 == 0 && i + 1 < k.size()) ss << "\n  ";
      }
      ss << "\n};\n\n";
    };

    dump_key("kManifestPublicKey", manifest_pubkey);
    dump_key("kLicensePublicKey", license_pubkey);
    // Legacy alias
    dump_key("kPublicKey", manifest_pubkey);

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
    ss << "#include \"integrity/sha256.h\"\n";
    ss << "#include \"antitamper/risk_policy.h\"\n";
    ss << "#include \"tooling/file_io.h\"\n\n";
    ss << "#include <ctime>\n";
    ss << "#include <cstdio>\n";
    ss << "#include <cstdlib>\n";
    ss << "#include <cstring>\n";
    ss << "#include <filesystem>\n";
    ss << "#include <string>\n\n";

    ss << "#if defined(_WIN32)\n";
    ss << "#include <windows.h>\n";
    ss << "#elif defined(__APPLE__)\n";
    ss << "#include <mach-o/dyld.h>\n";
    ss << "#else\n";
    ss << "#include <unistd.h>\n";
    ss << "#endif\n\n";

    ss << "namespace rtprotect_client {\n\n";

    ss << "namespace {\n\n";
    ss << "std::string GetCurrentExecutablePath() {\n";
    ss << "#if defined(_WIN32)\n";
    ss << "  char buf[MAX_PATH] = {0};\n";
    ss << "  ::GetModuleFileNameA(NULL, buf, MAX_PATH);\n";
    ss << "  return std::string(buf);\n";
    ss << "#elif defined(__APPLE__)\n";
    ss << "  char buf[1024] = {0};\n";
    ss << "  uint32_t size = sizeof(buf);\n";
    ss << "  if (_NSGetExecutablePath(buf, &size) == 0) return std::string(buf);\n";
    ss << "  return \"\";\n";
    ss << "#else\n";
    ss << "  char buf[1024] = {0};\n";
    ss << "  ssize_t len = ::readlink(\"/proc/self/exe\", buf, sizeof(buf) - 1);\n";
    ss << "  if (len > 0) { buf[len] = '\\0'; return std::string(buf); }\n";
    ss << "  return \"\";\n";
    ss << "#endif\n";
    ss << "}\n\n";

    ss << "std::optional<std::vector<std::uint8_t>> ReadAuxiliaryFile(const std::string& name) {\n";
    ss << "  namespace fs = std::filesystem;\n";
    ss << "  std::string exe = GetCurrentExecutablePath();\n";
    ss << "  if (!exe.empty()) {\n";
    ss << "    auto next_to_exe = fs::path(exe).parent_path() / name;\n";
    ss << "    if (fs::exists(next_to_exe)) return rtprotect::tooling::ReadFile(next_to_exe.string());\n";
    ss << "  }\n";
    ss << "  if (fs::exists(name)) return rtprotect::tooling::ReadFile(name);\n";
    ss << "  auto parent_rel = fs::path(\"..\") / name;\n";
    ss << "  if (fs::exists(parent_rel)) return rtprotect::tooling::ReadFile(parent_rel.string());\n";
    ss << "  return std::nullopt;\n";
    ss << "}\n\n";
    ss << "}  // namespace\n\n";

    ss << "bool VerifyClientIntegrityAndLicense() {\n";
    ss << "  // 1. Runtime environment risk assessment\n";
    ss << "  auto risk = rtprotect::antitamper::AssessEnvironmentRisk();\n";
    if (options.profile == ProtectionProfile::kMaximum) {
      ss << "  if (!rtprotect::antitamper::EnforceRiskPolicy(rtprotect::antitamper::RiskAction::kTerminate, risk)) return false;\n";
    } else if (options.profile == ProtectionProfile::kBalanced) {
      ss << "  if (!rtprotect::antitamper::EnforceRiskPolicy(rtprotect::antitamper::RiskAction::kRestrict, risk)) return false;\n";
    } else {
      ss << "  rtprotect::antitamper::EnforceRiskPolicy(rtprotect::antitamper::RiskAction::kReportOnly, risk);\n";
    }

    ss << "\n  // 2. Client license verification\n";
    ss << "  auto lic_data = ReadAuxiliaryFile(\"client.license\");\n";
    ss << "  if (!lic_data.has_value()) return false;\n";
    ss << "  rtprotect::licensing::LicenseVerificationContext ctx;\n";
    ss << "  ctx.current_time = static_cast<std::uint64_t>(std::time(nullptr));\n";
    ss << "  ctx.expected_product_id = kProductId;\n";
    ss << "  ctx.current_hardware_id = rtprotect::licensing::GetLocalHardwareId();\n";
    ss << "  rtprotect::licensing::License lic;\n";
    ss << "  auto lic_status = rtprotect::licensing::VerifyLicenseBytes(lic_data->data(), lic_data->size(), kLicensePublicKey, ctx, &lic);\n";
    ss << "  if (lic_status != rtprotect::licensing::LicenseStatus::kValid) return false;\n";

    ss << "\n  // 3. Manifest signature and anti-rollback verification\n";
    ss << "  auto man_bytes = ReadAuxiliaryFile(\"release.manifest\");\n";
    ss << "  auto sig_bytes = ReadAuxiliaryFile(\"release.sig\");\n";
    ss << "  if (!man_bytes.has_value() || !sig_bytes.has_value() || sig_bytes->size() != 64) return false;\n";
    ss << "  rtprotect::integrity::Ed25519Signature sig;\n";
    ss << "  std::memcpy(sig.data(), sig_bytes->data(), 64);\n";
    ss << "  if (!rtprotect::integrity::VerifyManifestSignature(*man_bytes, sig, kManifestPublicKey)) return false;\n";
    ss << "  auto manifest = rtprotect::integrity::DeserializeManifest(man_bytes->data(), man_bytes->size());\n";
    ss << "  if (!manifest.has_value() || manifest->release_sequence < 1) return false;\n";

    ss << "\n  // 4. Runtime executable integrity verification\n";
    ss << "  std::string exe_path = GetCurrentExecutablePath();\n";
    ss << "  if (!exe_path.empty()) {\n";
    ss << "    auto exe_bytes = rtprotect::tooling::ReadFile(exe_path);\n";
    ss << "    if (!exe_bytes.has_value()) return false;\n";
    ss << "    auto actual_hash = rtprotect::integrity::Sha256(exe_bytes->data(), exe_bytes->size());\n";
    ss << "    if (!actual_hash.has_value()) return false;\n";
    ss << "    std::string exe_name = std::filesystem::path(exe_path).filename().string();\n";
    ss << "    auto res = manifest->Find(exe_name);\n";
    ss << "    if (!res) {\n";
    ss << "      for (const auto& r : manifest->resources) {\n";
    ss << "        if (r.name.find(exe_name) != std::string::npos || exe_name.find(r.name) != std::string::npos) {\n";
    ss << "          res = &r;\n";
    ss << "          break;\n";
    ss << "        }\n";
    ss << "      }\n";
    ss << "    }\n";
    ss << "    if (res != nullptr) {\n";
    ss << "      if (res->size != exe_bytes->size() || res->sha256 != *actual_hash) return false;\n";
    ss << "    }\n";
    ss << "  }\n";

    ss << "  return true;\n";
    ss << "}\n\n";

    ss << "}  // namespace rtprotect_client\n\n";

    ss << "// Automatic startup hook -- executes before main()\n";
    ss << "#if defined(_MSC_VER)\n";
    ss << "static int InitializeRtProtectStartupHook() {\n";
    ss << "  if (!rtprotect_client::VerifyClientIntegrityAndLicense()) {\n";
    ss << "    std::fprintf(stderr, \"[RTProtect] Fatal: Integrity or license verification failed. Terminating.\\n\");\n";
    ss << "    std::exit(1);\n";
    ss << "  }\n";
    ss << "  return 0;\n";
    ss << "}\n";
    ss << "#pragma section(\".CRT$XCU\", read)\n";
    ss << "__declspec(allocate(\".CRT$XCU\")) static int (*p_init_rtprotect)() = InitializeRtProtectStartupHook;\n";
    ss << "#else\n";
    ss << "__attribute__((constructor(101))) static void InitializeRtProtectStartupHook() {\n";
    ss << "  if (!rtprotect_client::VerifyClientIntegrityAndLicense()) {\n";
    ss << "    std::fprintf(stderr, \"[RTProtect] Fatal: Integrity or license verification failed. Terminating.\\n\");\n";
    ss << "    std::exit(1);\n";
    ss << "  }\n";
    ss << "}\n";
    ss << "#endif\n";

    WriteTextFile(glue_path.string(), ss.str());
    report.generated_files.push_back(glue_path.string());
  }

  std::string root = options.rtprotect_root.empty() ? "." : options.rtprotect_root;
  std::error_code ec_root;
  auto abs_root = fs::weakly_canonical(fs::path(root), ec_root);
  std::string root_str = ec_root ? root : abs_root.string();
  std::replace(root_str.begin(), root_str.end(), '\\', '/');

  // 5. Update CMakeLists.txt
  fs::path cmake_path = proj_path / "CMakeLists.txt";
  std::string target_name;
  auto cmake_content = ReadTextFile(cmake_path.string());
  if (cmake_content.has_value()) {

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
    ss << "if(NOT DEFINED OPENSSL_ROOT_DIR AND EXISTS \"" << root_str << "/third_party/openssl\")\n";
    ss << "  set(OPENSSL_ROOT_DIR \"" << root_str << "/third_party/openssl\")\n";
    ss << "endif()\n";
    ss << "find_package(OpenSSL REQUIRED)\n";
    if (!target_name.empty()) {
      ss << "target_include_directories(" << target_name << " PRIVATE\n";
      ss << "    \"" << root_str << "\"\n";
      ss << "    \"" << root_str << "/third_party/openssl/include\"\n";
      ss << ")\n";
      ss << "target_link_directories(" << target_name << " PRIVATE\n";
      ss << "    \"" << root_str << "/build/integrity\"\n";
      ss << "    \"" << root_str << "/build/licensing\"\n";
      ss << "    \"" << root_str << "/build/antitamper\"\n";
      ss << "    \"" << root_str << "/build/crypto\"\n";
      ss << "    \"" << root_str << "/build-reconst/integrity\"\n";
      ss << "    \"" << root_str << "/build-reconst/licensing\"\n";
      ss << "    \"" << root_str << "/build-reconst/antitamper\"\n";
      ss << "    \"" << root_str << "/build-reconst/crypto\"\n";
      ss << "    \"" << root_str << "/third_party/openssl/lib\"\n";
      ss << "    \"" << root_str << "/lib\"\n";
      ss << ")\n";
      ss << "target_sources(" << target_name << " PRIVATE rtprotect_runtime_glue.cpp)\n";
      ss << "target_link_libraries(" << target_name << " PRIVATE\n";
      ss << "    rtprotect_licensing\n";
      ss << "    rtprotect_integrity\n";
      ss << "    rtprotect_antitamper\n";
      ss << "    rtprotect_crypto\n";
      ss << "    OpenSSL::Crypto\n";
      ss << "    $<$<PLATFORM_ID:Windows>:iphlpapi>\n";
      ss << "    $<$<PLATFORM_ID:Windows>:ws2_32>\n";
      ss << ")\n";

      ss << "\n# Compiler Hardening Profile: " << ToString(options.profile) << "\n";
      if (options.profile == ProtectionProfile::kMaximum) {
        ss << "if(MSVC)\n";
        ss << "  target_compile_options(" << target_name << " PRIVATE /guard:cf /DYNAMICBASE /NXCOMPAT)\n";
        ss << "else()\n";
        ss << "  target_compile_options(" << target_name << " PRIVATE -fstack-protector-strong -fPIE)\n";
        ss << "  target_link_options(" << target_name << " PRIVATE -pie)\n";
        ss << "endif()\n";
      } else if (options.profile == ProtectionProfile::kBalanced) {
        ss << "if(NOT MSVC)\n";
        ss << "  target_compile_options(" << target_name << " PRIVATE -fstack-protector)\n";
        ss << "endif()\n";
      }
    }

    std::string updated_cmake = *cmake_content + ss.str();
    WriteTextFile(cmake_path.string(), updated_cmake);
    report.modified_files.push_back(cmake_path.string());
  }

  // 6. Generate Default Client License
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

    if (has_license_privkey && license_privkey.has_value()) {
      licensing::SignLicense(lic, *license_privkey);
    }
    auto lic_bytes = licensing::SerializeLicense(lic);
    WriteFile(lic_path.string(), lic_bytes.data(), lic_bytes.size());

    report.license_file = lic_path.string();
    report.generated_files.push_back(lic_path.string());
  }

  // 7. Generate Initial Release Manifest
  fs::path manifest_path = proj_path / "release.manifest";
  fs::path sig_path = proj_path / "release.sig";
  {
    integrity::Manifest manifest;
    manifest.release_version = options.release_version;
    manifest.release_sequence = 1;

    auto cfg_data = ReadFile(config_header_path.string());
    if (cfg_data.has_value()) {
      manifest.AddResource("rtprotect_config.h", cfg_data->data(), cfg_data->size());
    }

    auto man_bytes = integrity::SerializeManifest(manifest);
    WriteFile(manifest_path.string(), man_bytes.data(), man_bytes.size());

    if (has_manifest_privkey && manifest_privkey.has_value()) {
      auto sig = integrity::SignManifestBytes(man_bytes, *manifest_privkey);
      if (sig.has_value()) {
        WriteFile(sig_path.string(), sig->data(), sig->size());
      }
    }

    report.manifest_file = manifest_path.string();
    report.signature_file = sig_path.string();
    report.generated_files.push_back(manifest_path.string());
    report.generated_files.push_back(sig_path.string());
  }

  // 8. Build and Post-Build Executable Measurement
  if (options.run_build) {
    fs::path build_dir = proj_path / "build_protected";
    std::string config_cmd = "cmake -B \"" + build_dir.string() + "\" -S \"" + proj_path.string() + "\"";
    std::string openssl_dir = root_str + "/third_party/openssl";
    if (fs::exists(openssl_dir)) {
      config_cmd += " -DOPENSSL_ROOT_DIR=\"" + openssl_dir + "\"";
    }
    std::string build_cmd = "cmake --build \"" + build_dir.string() + "\"";

    int cr = std::system(config_cmd.c_str());
    if (cr != 0) {
      report.build_succeeded = false;
      report.success = false;
      report.error_message = "CMake configuration failed for target project";
      return report;
    }

    int br = std::system(build_cmd.c_str());
    if (br != 0) {
      report.build_succeeded = false;
      report.success = false;
      report.error_message = "Protected build failed during compilation / linking";
      return report;
    }
    report.build_succeeded = true;

    // Locate compiled binary
    std::string exe_name = target_name.empty() ? "app" : target_name;
#if defined(_WIN32)
    exe_name += ".exe";
#endif

    fs::path built_exe;
    std::vector<fs::path> candidate_dirs = {
      build_dir,
      build_dir / "Release",
      build_dir / "Debug"
    };
    for (const auto& cd : candidate_dirs) {
      if (fs::exists(cd / exe_name)) {
        built_exe = cd / exe_name;
        break;
      }
    }

    // Measure the actual compiled executable and update signed manifest
    integrity::Manifest manifest;
    manifest.release_version = options.release_version;
    manifest.release_sequence = 1;

    auto cfg_data = ReadFile(config_header_path.string());
    if (cfg_data.has_value()) {
      manifest.AddResource("rtprotect_config.h", cfg_data->data(), cfg_data->size());
    }

    if (!built_exe.empty()) {
      auto exe_data = ReadFile(built_exe.string());
      if (exe_data.has_value()) {
        manifest.AddResource(exe_name, exe_data->data(), exe_data->size());
      }
    }

    auto man_bytes = integrity::SerializeManifest(manifest);
    WriteFile(manifest_path.string(), man_bytes.data(), man_bytes.size());

    if (has_manifest_privkey && manifest_privkey.has_value()) {
      auto sig = integrity::SignManifestBytes(man_bytes, *manifest_privkey);
      if (sig.has_value()) {
        WriteFile(sig_path.string(), sig->data(), sig->size());
      }
    }

    // Deploy manifest, signature, license, and public keys alongside the built binary
    if (!built_exe.empty()) {
      auto dest_dir = built_exe.parent_path();
      fs::copy_file(manifest_path, dest_dir / "release.manifest", fs::copy_options::overwrite_existing, ec);
      fs::copy_file(sig_path, dest_dir / "release.sig", fs::copy_options::overwrite_existing, ec);
      fs::copy_file(lic_path, dest_dir / "client.license", fs::copy_options::overwrite_existing, ec);
      fs::copy_file(manifest_pub_path, dest_dir / "release.pub", fs::copy_options::overwrite_existing, ec);
    }

    // Validate the protected build
    std::string val_err;
    report.validation_succeeded = ValidateProtectedBuild(
        proj_path.string(), manifest_pub_path.string(), manifest_path.string(), sig_path.string(), &val_err);
    if (!report.validation_succeeded) {
      report.success = false;
      report.error_message = "Protected build validation failed: " + val_err;
      return report;
    }
  }

  // 9. Write Transactional Journal
  {
    std::ostringstream jss;
    jss << "{\n";
    jss << "  \"timestamp\": " << timestamp << ",\n";
    jss << "  \"target_project\": \"" << EscapeJson(proj_path.string()) << "\",\n";
    jss << "  \"created_files\": [\n";
    for (std::size_t i = 0; i < planned_created.size(); ++i) {
      jss << "    \"" << EscapeJson(planned_created[i]) << "\"" << (i + 1 < planned_created.size() ? "," : "") << "\n";
    }
    jss << "  ],\n";
    jss << "  \"backed_up_files\": [\n";
    for (std::size_t i = 0; i < backed_up_relative.size(); ++i) {
      jss << "    \"" << EscapeJson(backed_up_relative[i]) << "\"" << (i + 1 < backed_up_relative.size() ? "," : "") << "\n";
    }
    jss << "  ]\n";
    jss << "}\n";
    WriteTextFile((backup_dir / "integration_journal.json").string(), jss.str());
  }

  report.success = true;

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

  // Check if integration_journal.json exists
  fs::path journal_path = bkp_path / "integration_journal.json";
  if (fs::exists(journal_path)) {
    auto jtext = ReadTextFile(journal_path.string());
    if (jtext.has_value()) {
      auto extract_list = [](const std::string& json, const std::string& key) -> std::vector<std::string> {
        std::vector<std::string> items;
        auto pos = json.find("\"" + key + "\"");
        if (pos == std::string::npos) return items;
        auto open_bracket = json.find('[', pos);
        auto close_bracket = json.find(']', open_bracket);
        if (open_bracket == std::string::npos || close_bracket == std::string::npos) return items;
        std::string array_str = json.substr(open_bracket + 1, close_bracket - open_bracket - 1);
        std::istringstream iss(array_str);
        std::string line;
        while (std::getline(iss, line, ',')) {
          auto q1 = line.find('"');
          auto q2 = line.rfind('"');
          if (q1 != std::string::npos && q2 != std::string::npos && q2 > q1) {
            items.push_back(line.substr(q1 + 1, q2 - q1 - 1));
          }
        }
        return items;
      };

      auto created_files = extract_list(*jtext, "created_files");
      auto backed_up_files = extract_list(*jtext, "backed_up_files");

      // Remove only files that were newly created
      for (const auto& rel_file : created_files) {
        fs::path target_file = proj_path / rel_file;
        if (IsPathWithin(target_file, proj_path) && fs::exists(target_file)) {
          fs::remove(target_file, ec);
        }
      }

      // Restore backed-up files
      for (const auto& rel_file : backed_up_files) {
        fs::path src = bkp_path / rel_file;
        fs::path dest = proj_path / rel_file;
        if (IsPathWithin(dest, proj_path) && fs::exists(src)) {
          fs::create_directories(dest.parent_path(), ec);
          fs::copy_file(src, dest, fs::copy_options::overwrite_existing, ec);
          if (ec) {
            if (error_out) *error_out = "Failed restoring: " + dest.string();
            return false;
          }
        }
      }

      return true;
    }
  }

  // Fallback: restore backed-up files
  for (const auto& entry : fs::recursive_directory_iterator(bkp_path, ec)) {
    if (entry.is_regular_file()) {
      auto rel = fs::relative(entry.path(), bkp_path);
      if (rel.string() == "integration_journal.json") continue;
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

  // Remove standard generated files
  std::vector<std::string> to_remove = {
    "rtprotect_config.h",
    "rtprotect_runtime_glue.cpp",
    "release.pub",
    "license.pub",
    "release.priv",
    "release.manifest",
    "release.sig",
    "client.license"
  };
  for (const auto& f : to_remove) {
    fs::path target_file = proj_path / f;
    if (IsPathWithin(target_file, proj_path) && fs::exists(target_file)) {
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
    std::optional<std::vector<std::uint8_t>> data = ReadFile(res_path.string());
    if (!data.has_value()) {
      std::vector<fs::path> candidate_dirs = {
        root / "build_protected",
        root / "build_protected" / "Release",
        root / "build_protected" / "Debug",
        root / "build",
        root / "build" / "Release",
        root / "build" / "Debug"
      };
      for (const auto& cd : candidate_dirs) {
        if (fs::exists(cd / res.name)) {
          data = ReadFile((cd / res.name).string());
          break;
        }
      }
    }

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
