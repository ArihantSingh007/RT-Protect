// tooling/integration_engine.h
//
// RTProtect Integration Engine.
//
// Inspects target client C/C++ projects, generates protection wrappers,
// build rules, and signed manifests, and applies transactional changes
// with complete backup, dry-run preview, and rollback support.

#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "crypto/aead.h"
#include "integrity/keys.h"

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
  std::string activation_pubkey_path;// External activation token public key (separated from manifest/license)
  std::string sign_manifest_key_path;// Optional vendor release signing private key
  std::string sign_license_key_path; // Optional vendor license signing private key
  std::string sign_activation_key_path; // Optional activation token signing private key
  std::string license_file_path;     // Optional pre-issued client.license to deploy
  std::string dev_keys_dir;          // Output directory for dev keys (must be outside client project)
  std::string activation_server_url; // Online Activation Authority URL (e.g. "https://license.vendor.com")
  std::string activation_credential; // Secret activation secret for device activation (separated from public license ID)
  std::uint64_t minimum_release_sequence = 1; // Monotonically increasing anti-rollback sequence requirement
  std::string customer_id = "authorized-client";
  std::string license_edition = "Production";
  std::uint64_t license_expires_at = 0;
  std::string content_key_path;      // Dedicated content encryption master key (separated from signing key)
  std::string vm_root_file;          // Optional explicit binary file for release VM root
  std::string vm_root_hex;           // Optional explicit 64-char hex string for release VM root
  bool auto_virtualize = false;       // Whole-program automated candidate selection without manual annotations
  double virtualization_budget = 25.0;// Virtualization overhead budget: percentage of eligible functions to protect
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
  std::string activation_public_key_file; // Activation token verification public key
  std::string private_key_file;         // Populated only in --dev-keys mode (in external dev_keys_dir)
  std::string manifest_file;
  std::string signature_file;
  std::string license_file;
  bool build_succeeded = false;
  bool validation_succeeded = false;
  std::vector<std::string> virtualized_functions;
  std::size_t obfuscated_string_count = 0;
  std::size_t scattered_check_count = 0;
  std::uint32_t opcode_seed = 0;

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
                            std::string* error_out = nullptr,
                            bool require_license = true,
                            std::uint64_t minimum_release_sequence = 1,
                            const std::string& expected_product_id = "");

// Derives function master key dynamically using HKDF from activation token VM root,
// manifest public key, product ID, and function-specific salt.
std::optional<crypto::Aes256Key> DeriveBuildFunctionMasterKey(
    const std::array<std::uint8_t, 32>& vm_root,
    const integrity::Ed25519PublicKey& manifest_pubkey,
    const std::string& product_id,
    const std::uint8_t* salt,
    std::size_t salt_len);

// Transforms target source file: virtualizes RTPROTECT_VIRTUALIZE functions,
// obfuscates string literals, and injects scattered tamper checkpoints.
bool TransformSourceFile(const std::filesystem::path& file_path,
                         const ProtectionProfile profile,
                         const std::uint32_t opcode_seed,
                         const std::array<std::uint8_t, 32>& vm_root,
                         const integrity::Ed25519PublicKey& manifest_pubkey,
                         const std::string& product_id,
                         std::vector<std::string>& out_virtualized,
                         std::size_t& out_obfuscated_count,
                         std::size_t& out_scattered_count,
                         std::string* out_error_message = nullptr);

}  // namespace rtprotect::tooling
