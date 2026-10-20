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

enum class IntegrationState {
  kPlanned = 0,
  kIntegrated,
  kBuilt,
  kAwaitingSignature,
  kValidated,
  kFailed
};

const char* ToString(IntegrationState s);

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
  bool staging_only = false;         // If true, instrument project for vendor signing without requiring local signatures
  std::string product_id = "com.client.protected";
  std::string release_version = "1.0.0";
  std::string target_name;           // Selected CMake executable target (required if multiple targets exist)
  std::string rtprotect_root;        // Path to RTProtect repository / SDK
  std::string manifest_pubkey_path;  // External manifest public key
  std::string license_pubkey_path;   // External license public key
  std::string sign_manifest_key_path;// Optional vendor release signing private key
  std::string sign_license_key_path; // Optional vendor license signing private key
  std::string license_file_path;     // Optional pre-issued client.license to deploy
  std::string dev_keys_dir;          // Output directory for dev keys (must be outside client project)
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
  IntegrationState state = IntegrationState::kFailed;
  bool is_staged_only = false;
  std::string target_name;
  std::string error_message;
  std::string backup_path;
  std::vector<std::string> modified_files;
  std::vector<std::string> generated_files;
  std::vector<std::string> warnings;
  std::string public_key_file;          // Primary / manifest public key file
  std::string manifest_public_key_file; // Manifest verification public key
  std::string license_public_key_file;  // License verification public key
  std::string private_key_file;         // Populated only in --dev-keys mode (in external dev_keys_dir)
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

// Signs release artifacts on a vendor signing machine using private signing keys.
bool SignRelease(const std::string& project_dir,
                 const std::string& manifest_privkey_path,
                 const std::string& license_file_path = "",
                 std::string* error_out = nullptr);

// Validates an already-protected build artifacts against signed manifests.
bool ValidateProtectedBuild(const std::string& project_dir,
                            const std::string& public_key_path,
                            const std::string& manifest_path,
                            const std::string& signature_path,
                            std::string* error_out = nullptr);

}  // namespace rtprotect::tooling
