// tooling/integration_engine.h
//
// RTProtect Integration Engine.
//
// Inspects target client C/C++ projects, generates protection wrappers,
// build rules, and signed manifests, and applies transactional changes
// with complete backup, dry-run preview, and rollback support.

#pragma once

#include <string>
#include <vector>
#include <optional>

namespace rtprotect::tooling {

enum class ProtectionProfile {
  kDevelopment = 0,
  kBalanced,
  kMaximum
};

const char* ToString(ProtectionProfile p);
ProtectionProfile ParseProfile(const std::string& str);

struct IntegrationOptions {
  std::string target_project_path;
  ProtectionProfile profile = ProtectionProfile::kBalanced;
  std::string output_dir;
  std::string report_json_path;
  std::string backup_dir;            // Empty = auto-generate timestamped folder
  bool dry_run = false;
  bool non_interactive = false;
  bool use_dev_keys = false;
  bool run_build = true;
  std::string product_id = "com.client.protected";
  std::string release_version = "1.0.0";
  std::string rtprotect_root;       // Path to RTProtect repository
};

struct ChangePlan {
  std::string detected_language = "Unknown";
  std::string detected_build_system = "Unknown";
  std::vector<std::string> detected_sources;
  std::vector<std::string> files_to_create;
  std::vector<std::string> files_to_modify;
  std::vector<std::string> warnings;
  bool is_supported = false;
  std::string explanation;

  std::string FormatSummary() const;
};

struct IntegrationReport {
  bool success = false;
  std::string error_message;
  std::string backup_path;
  std::vector<std::string> modified_files;
  std::vector<std::string> generated_files;
  std::vector<std::string> warnings;
  std::string public_key_file;
  std::string private_key_file;
  std::string manifest_file;
  std::string signature_file;
  std::string license_file;
  bool build_succeeded = false;
  bool validation_succeeded = false;

  std::string ToJson() const;
};

// Inspects the target project and prepares a preview change plan without altering files.
ChangePlan PlanIntegration(const IntegrationOptions& options);

// Executes the complete transactional integration workflow.
IntegrationReport ExecuteIntegration(const IntegrationOptions& options);

// Restores target project from a designated backup directory.
bool ExecuteRollback(const std::string& target_project_path,
                     const std::string& backup_dir,
                     std::string* error_out = nullptr);

// Validates an already-protected build artifacts against signed manifests.
bool ValidateProtectedBuild(const std::string& project_dir,
                            const std::string& public_key_path,
                            const std::string& manifest_path,
                            const std::string& signature_path,
                            std::string* error_out = nullptr);

}  // namespace rtprotect::tooling
