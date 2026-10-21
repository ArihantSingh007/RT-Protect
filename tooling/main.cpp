// tooling/main.cpp
//
// rtprotect-tool: Unified CLI for software protection, asymmetric licensing,
// build integrity verification, hardware fingerprinting, and project integration.

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include <openssl/crypto.h>

#include "crypto/aead.h"
#include "integrity/keys.h"
#include "integrity/manifest.h"
#include "integrity/sha256.h"
#include "integrity/signer.h"
#include "integrity/verifier.h"
#include "licensing/hardware_id.h"
#include "licensing/license.h"
#include "licensing/license_signer.h"
#include "licensing/license_verifier.h"
#include "licensing/activation.h"
#include "licensing/activation_server.h"
#include "tooling/file_io.h"
#include "tooling/integration_engine.h"

using namespace rtprotect;
using namespace rtprotect::tooling;

namespace {

std::string FormatCapabilities(std::uint64_t caps) {
  std::vector<std::string> names;
  if (caps & licensing::kCapCoreExecution) names.push_back("CoreExecution");
  if (caps & licensing::kCapAdvancedFeatures) names.push_back("AdvancedFeatures");
  if (caps & licensing::kCapExportData) names.push_back("ExportData");
  if (caps & licensing::kCapCommercialUse) names.push_back("CommercialUse");
  if (caps & licensing::kCapTrialMode) names.push_back("TrialMode");
  if (caps & licensing::kCapOfflineAllowed) names.push_back("OfflineAllowed");
  if (names.empty()) return "None";
  std::string res;
  for (std::size_t i = 0; i < names.size(); ++i) {
    if (i > 0) res += ", ";
    res += names[i];
  }
  return res;
}

bool ParseCapabilitiesExact(const std::string& str, std::uint64_t* out_caps, std::string* error_msg) {
  if (!out_caps) return false;
  *out_caps = 0;
  if (str.empty()) {
    *out_caps = licensing::kCapCoreExecution;
    return true;
  }

  char* end = nullptr;
  unsigned long long val = std::strtoull(str.c_str(), &end, 0);
  if (end != str.c_str() && *end == '\0') {
    *out_caps = static_cast<std::uint64_t>(val);
    return true;
  }

  std::vector<std::string> tokens;
  std::string current;
  for (char c : str) {
    if (c == ',' || c == '|' || c == ' ' || c == '\t' || c == ';') {
      if (!current.empty()) {
        tokens.push_back(current);
        current.clear();
      }
    } else {
      current += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
  }
  if (!current.empty()) {
    tokens.push_back(current);
  }

  std::uint64_t caps = 0;
  std::vector<std::string> seen;

  for (const auto& tok : tokens) {
    if (std::find(seen.begin(), seen.end(), tok) != seen.end()) {
      if (error_msg) *error_msg = "Duplicate capability flag: '" + tok + "'";
      return false;
    }
    seen.push_back(tok);

    if (tok == "core" || tok == "coreexecution" || tok == "kcapcoreexecution") {
      caps |= licensing::kCapCoreExecution;
    } else if (tok == "adv" || tok == "advanced" || tok == "advancedfeatures" || tok == "kcapadvancedfeatures") {
      caps |= licensing::kCapAdvancedFeatures;
    } else if (tok == "export" || tok == "exportdata" || tok == "kcapexportdata") {
      caps |= licensing::kCapExportData;
    } else if (tok == "commercial" || tok == "commercialuse" || tok == "kcapcommercialuse") {
      caps |= licensing::kCapCommercialUse;
    } else if (tok == "trial" || tok == "trialmode" || tok == "kcaptrialmode") {
      caps |= licensing::kCapTrialMode;
    } else if (tok == "offline" || tok == "offlineallowed" || tok == "kcapofflineallowed") {
      caps |= licensing::kCapOfflineAllowed;
    } else {
      if (error_msg) *error_msg = "Unrecognized capability flag: '" + tok + "'. Valid options: core, adv, export, commercial, trial, offline";
      return false;
    }
  }

  if (caps == 0) {
    caps = licensing::kCapCoreExecution;
  }
  *out_caps = caps;
  return true;
}

[[maybe_unused]] std::uint64_t ParseCapabilities(const std::string& str) {
  std::uint64_t caps = 0;
  std::string err;
  if (!ParseCapabilitiesExact(str, &caps, &err)) {
    std::fprintf(stderr, "warning: %s. Defaulting to CoreExecution.\n", err.c_str());
    return licensing::kCapCoreExecution;
  }
  return caps;
}

void PrintUsage() {
  std::fprintf(stderr,
      "rtprotect-tool v2.0.0 -- RTProtect Software Protection & Integration CLI\n\n"
      "Usage:\n"
      "  Project Integration & Build Operations:\n"
      "    rtprotect-tool integrate <project-path> [options]\n"
      "    rtprotect-tool unreal-integrate <uproject-path> [options]\n"
      "      --profile <dev|balanced|maximum>   Protection hardening profile (default: balanced)\n"
      "      --target <name>                   Specify CMake executable target to protect\n"
      "      --dry-run                         Preview plan without modifying files\n"
      "      --dev-keys                        Use development test keys (outside client project)\n"
      "      --manifest-pubkey <file>          External Ed25519 public key for manifest verification\n"
      "      --license-pubkey <file>           External Ed25519 public key for license verification\n"
      "      --sign-manifest-key <file>        Vendor private key for manifest signing\n"
      "      --sign-license-key <file>         Vendor private key for license signing\n"
      "      --license-file <file>             Deploy authorized vendor client.license\n"
      "      --staging                         Stage project instrumentation without signing\n"
      "      --backup-dir <dir>                Custom location for project backup\n"
      "      --report <json-file>              Output JSON execution report to path\n"
      "      --product <id>                    Product identifier (default: com.client.protected)\n"
      "      --version <ver>                   Release version string (default: 1.0.0)\n"
      "      --rtprotect-root <dir>            Root path to RTProtect distribution / SDK\n"
      "      --no-build                        Skip automatic build and verification\n"
      "      --non-interactive                 Do not prompt for confirmation\n"
      "\n"
      "    rtprotect-tool sign-release <project-path> --manifest-key <file> [--license <file>]\n"
      "      Signs and packages release manifest using vendor private key on signing machine.\n"
      "\n"
      "    rtprotect-tool rollback <project-path> <backup-dir>\n"
      "      Restores project to pre-integration state from designated backup.\n"
      "\n"
      "    rtprotect-tool validate-build <project-dir> <pub-key-file> <manifest-file> <sig-file>\n"
      "      Validates integrity of protected build outputs against signed manifest.\n"
      "\n"
      "  License Management & Hardware ID:\n"
      "    rtprotect-tool license-generate [options]\n"
      "      --priv-key <file>                 Ed25519 private key (required)\n"
      "      --out <file>                      Output license file path (required)\n"
      "      --product <id>                    Product ID (default: com.client.protected)\n"
      "      --edition <name>                  Edition string (default: Standard)\n"
      "      --customer <id>                   Customer identifier (default: user@domain.local)\n"
      "      --capabilities <flags>            Capability names or bitmask (default: core,commercial)\n"
      "      --expires-in-days <n>             Days until expiration (0 = perpetual, default: 0)\n"
      "      --hwid <id>                       Hardware binding ID (default: local machine ID)\n"
      "      --format <binary|text>            Output format (default: binary)\n"
      "\n"
      "    rtprotect-tool license-verify [options]\n"
      "      --pub-key <file>                  Ed25519 public key (required)\n"
      "      --license <file>                  License file to verify (required)\n"
      "      --product <id>                    Expected product ID (optional)\n"
      "      --edition <name>                  Expected edition (optional)\n"
      "      --hwid <id>                       Hardware ID to match against (optional)\n"
      "\n"
      "    rtprotect-tool license-inspect <license-file>\n"
      "      Parses and displays contents, capabilities, and expiration of a license file.\n"
      "\n"
      "    rtprotect-tool fingerprint [--canonical]\n"
      "      Computes and displays multi-metric hardware fingerprint of local machine.\n"
      "\n"
      "  Online Activation & Revocation:\n"
      "    rtprotect-tool activate-issue [options]\n"
      "      --priv-key <file>                 Vendor Ed25519 private key (required)\n"
      "      --license-id <id>                 Authorized license ID (required)\n"
      "      --out <file>                      Output ticket file path (required)\n"
      "      --hwid <id>                       Device hardware ID (default: local machine ID)\n"
      "      --validity-hours <n>              Ticket validity duration in hours (default: 24)\n"
      "      --format <binary|text>            Output format (default: binary)\n"
      "      --revocation-db <file>            Optional revocation database to verify against\n"
      "\n"
      "    rtprotect-tool activate-verify [options]\n"
      "      --pub-key <file>                  Vendor Ed25519 public key (required)\n"
      "      --ticket <file>                   Activation ticket file to verify (required)\n"
      "      --license-id <id>                 Expected license ID (optional)\n"
      "      --hwid <id>                       Expected hardware ID (default: local machine ID)\n"
      "      --revocation-db <file>            Optional revocation database to check\n"
      "\n"
      "    rtprotect-tool activate-revoke --db <file> [options]\n"
      "      --revoke-license <id>             Add license ID to revocation list\n"
      "      --revoke-ticket <id>              Add ticket ID to revocation list\n"
      "      --unrevoke-license <id>           Remove license ID from revocation list\n"
      "      --unrevoke-ticket <id>            Remove ticket ID from revocation list\n"
      "      --reason <string>                 Reason for revocation\n"
      "      --list                            Display current revocation database entries\n"
      "\n"
      "  Cryptographic & Integrity Primitives:\n"
      "    rtprotect-tool genkey-ed25519 <priv-out> <pub-out>\n"
      "    rtprotect-tool genkey-aes <key-out>\n"
      "    rtprotect-tool hash <file>\n"
      "    rtprotect-tool encrypt <key-file> <input-file> <output-file>\n"
      "    rtprotect-tool decrypt <key-file> <input-file> <output-file>\n"
      "    rtprotect-tool manifest-build <manifest-out> <version> <name>=<file> [...]\n"
      "    rtprotect-tool manifest-sign <manifest-file> <priv-key-file> <sig-out>\n"
      "    rtprotect-tool manifest-verify <manifest-file> <sig-file> <pub-key-file> <name> <file>\n"
      "\n"
      "  General:\n"
      "    rtprotect-tool --version | version\n"
      "    rtprotect-tool --help | help\n");
}

int CmdGenkeyEd25519(int argc, char** argv) {
  if (argc != 4) { PrintUsage(); return 2; }
  auto kp = integrity::GenerateEd25519KeyPair();
  if (!kp.has_value()) {
    std::fprintf(stderr, "error: key generation failed\n");
    return 1;
  }
  if (!WriteSecretFile(argv[2], kp->private_key.data(), kp->private_key.size()) ||
      !WriteFile(argv[3], kp->public_key.data(), kp->public_key.size())) {
    std::fprintf(stderr, "error: failed to write key file(s)\n");
    return 1;
  }
  std::fprintf(stderr,
      "Wrote Ed25519 keypair.\n"
      "  Private key: %s  -- KEEP OFFLINE. Never embed in, or ship as part of,\n"
      "                     a distributed application (see docs/THREAT_MODEL.md Sec.7).\n"
      "  Public key:  %s  -- safe to embed in a client application.\n",
      argv[2], argv[3]);
  return 0;
}

int CmdGenkeyAes(int argc, char** argv) {
  if (argc != 3) { PrintUsage(); return 2; }
  auto key = crypto::Aes256Key::Generate();
  if (!WriteSecretFile(argv[2], key.bytes().data(), key.bytes().size())) {
    std::fprintf(stderr, "error: failed to write key file\n");
    return 1;
  }
  std::fprintf(stderr, "Wrote AES-256 key: %s -- keep this secret.\n", argv[2]);
  return 0;
}

int CmdHash(int argc, char** argv) {
  if (argc != 3) { PrintUsage(); return 2; }
  auto data = ReadFile(argv[2]);
  if (!data.has_value()) {
    std::fprintf(stderr, "error: could not read %s\n", argv[2]);
    return 1;
  }
  auto digest = integrity::Sha256(data->data(), data->size());
  if (!digest.has_value()) {
    std::fprintf(stderr, "error: hashing failed\n");
    return 1;
  }
  std::printf("%s  %s\n", ToHex(digest->data(), digest->size()).c_str(), argv[2]);
  return 0;
}

int CmdEncrypt(int argc, char** argv) {
  if (argc != 5) { PrintUsage(); return 2; }
  auto key_bytes = ReadFile(argv[2]);
  auto plaintext = ReadFile(argv[3]);
  if (!key_bytes.has_value() || !plaintext.has_value()) {
    std::fprintf(stderr, "error: could not read key or input file\n");
    return 1;
  }
  auto key = crypto::Aes256Key::FromBytes(key_bytes->data(), key_bytes->size());
  if (!key_bytes->empty()) OPENSSL_cleanse(key_bytes->data(), key_bytes->size());
  if (!key.has_value()) {
    std::fprintf(stderr, "error: key file is not exactly %zu bytes\n", crypto::kAes256KeyLen);
    return 1;
  }
  auto enc = crypto::Encrypt(*key, plaintext->data(), plaintext->size());
  if (!enc.has_value()) {
    std::fprintf(stderr, "error: encryption failed\n");
    return 1;
  }
  auto wire = enc->Serialize();
  if (!WriteFile(argv[4], wire)) {
    std::fprintf(stderr, "error: could not write output file\n");
    return 1;
  }
  std::fprintf(stderr, "Encrypted %s -> %s (%zu bytes plaintext, %zu bytes ciphertext blob)\n",
               argv[3], argv[4], plaintext->size(), wire.size());
  return 0;
}

int CmdDecrypt(int argc, char** argv) {
  if (argc != 5) { PrintUsage(); return 2; }
  auto key_bytes = ReadFile(argv[2]);
  auto blob = ReadFile(argv[3]);
  if (!key_bytes.has_value() || !blob.has_value()) {
    std::fprintf(stderr, "error: could not read key or input file\n");
    return 1;
  }
  auto key = crypto::Aes256Key::FromBytes(key_bytes->data(), key_bytes->size());
  if (!key_bytes->empty()) OPENSSL_cleanse(key_bytes->data(), key_bytes->size());
  if (!key.has_value()) {
    std::fprintf(stderr, "error: key file is not exactly %zu bytes\n", crypto::kAes256KeyLen);
    return 1;
  }
  auto msg = crypto::EncryptedMessage::Deserialize(blob->data(), blob->size());
  if (!msg.has_value()) {
    std::fprintf(stderr, "error: input file is not a valid encrypted blob\n");
    return 1;
  }
  crypto::AeadError aead_err = crypto::AeadError::kNone;
  auto plaintext = crypto::Decrypt(*key, *msg, nullptr, 0, &aead_err);
  if (!plaintext.has_value()) {
    std::fprintf(stderr, "error: decryption failed: %s\n", crypto::ToString(aead_err));
    return 1;
  }
  if (!WriteFile(argv[4], *plaintext)) {
    std::fprintf(stderr, "error: could not write output file\n");
    return 1;
  }
  std::fprintf(stderr, "Decrypted %s -> %s (%zu bytes)\n", argv[3], argv[4], plaintext->size());
  return 0;
}

int CmdManifestBuild(int argc, char** argv) {
  if (argc < 5) { PrintUsage(); return 2; }
  integrity::Manifest manifest;
  manifest.release_version = argv[3];

  for (int i = 4; i < argc; ++i) {
    std::string arg = argv[i];
    auto eq = arg.find('=');
    if (eq == std::string::npos) {
      std::fprintf(stderr, "error: expected <resource-name>=<resource-file>, got '%s'\n",
                   arg.c_str());
      return 2;
    }
    std::string name = arg.substr(0, eq);
    std::string path = arg.substr(eq + 1);
    auto data = ReadFile(path);
    if (!data.has_value()) {
      std::fprintf(stderr, "error: could not read resource file %s\n", path.c_str());
      return 1;
    }
    if (!manifest.AddResource(name, data->data(), data->size())) {
      std::fprintf(stderr, "error: could not add resource %s to manifest\n", name.c_str());
      return 1;
    }
    std::fprintf(stderr, "  added %-20s %8zu bytes  sha256=%s\n", name.c_str(), data->size(),
                 ToHex(manifest.Find(name)->sha256.data(), manifest.Find(name)->sha256.size())
                     .c_str());
  }

  auto wire = integrity::SerializeManifest(manifest);
  if (!WriteFile(argv[2], wire)) {
    std::fprintf(stderr, "error: could not write manifest file\n");
    return 1;
  }
  std::fprintf(stderr, "Wrote manifest %s (version %s, %zu resource(s), %zu bytes)\n", argv[2],
               manifest.release_version.c_str(), manifest.resources.size(), wire.size());
  return 0;
}

int CmdManifestSign(int argc, char** argv) {
  if (argc != 5) { PrintUsage(); return 2; }
  auto manifest_bytes = ReadFile(argv[2]);
  auto priv_bytes = ReadFile(argv[3]);
  if (!manifest_bytes.has_value() || !priv_bytes.has_value()) {
    std::fprintf(stderr, "error: could not read manifest or private key file\n");
    return 1;
  }
  auto priv = integrity::Ed25519PrivateKey::FromBytes(priv_bytes->data(), priv_bytes->size());
  if (!priv_bytes->empty()) OPENSSL_cleanse(priv_bytes->data(), priv_bytes->size());
  if (!priv.has_value()) {
    std::fprintf(stderr, "error: private key file is not exactly %zu bytes\n",
                 integrity::kEd25519PrivateKeyLen);
    return 1;
  }

  auto sig = integrity::SignManifestBytes(*manifest_bytes, *priv);
  if (!sig.has_value()) {
    std::fprintf(stderr, "error: signing failed\n");
    return 1;
  }
  if (!WriteFile(argv[4], sig->data(), sig->size())) {
    std::fprintf(stderr, "error: could not write signature file\n");
    return 1;
  }
  std::fprintf(stderr, "Signed %s -> %s\n", argv[2], argv[4]);
  return 0;
}

int CmdManifestVerify(int argc, char** argv) {
  if (argc != 7) { PrintUsage(); return 2; }
  auto manifest_bytes = ReadFile(argv[2]);
  auto sig_bytes = ReadFile(argv[3]);
  auto pub_bytes = ReadFile(argv[4]);
  std::string resource_name = argv[5];
  auto resource_bytes = ReadFile(argv[6]);

  if (!manifest_bytes.has_value() || !sig_bytes.has_value() || !pub_bytes.has_value() ||
      !resource_bytes.has_value()) {
    std::fprintf(stderr, "error: could not read one or more input files\n");
    return 1;
  }
  if (sig_bytes->size() != integrity::kEd25519SignatureLen) {
    std::fprintf(stderr, "error: signature file is not exactly %zu bytes\n",
                 integrity::kEd25519SignatureLen);
    return 1;
  }
  if (pub_bytes->size() != integrity::kEd25519PublicKeyLen) {
    std::fprintf(stderr, "error: public key file is not exactly %zu bytes\n",
                 integrity::kEd25519PublicKeyLen);
    return 1;
  }

  std::array<std::uint8_t, integrity::kEd25519SignatureLen> sig;
  std::copy(sig_bytes->begin(), sig_bytes->end(), sig.begin());
  integrity::Ed25519PublicKey pub;
  std::copy(pub_bytes->begin(), pub_bytes->end(), pub.begin());

  auto err = integrity::VerifyAndCheckResource(*manifest_bytes, sig, pub, resource_name,
                                                resource_bytes->data(), resource_bytes->size());
  if (err != integrity::IntegrityError::kNone) {
    std::fprintf(stderr, "FAILED: %s\n", integrity::ToString(err));
    return 1;
  }
  std::fprintf(stderr, "OK: %s matches the signed manifest.\n", resource_name.c_str());
  return 0;
}

int CmdIntegrate(int argc, char** argv) {
  if (argc < 3) {
    PrintUsage();
    return 2;
  }
  IntegrationOptions options;
  options.target_project_path = argv[2];

  for (int i = 3; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--dry-run") {
      options.dry_run = true;
    } else if (arg == "--dev-keys") {
      options.use_dev_keys = true;
    } else if (arg == "--non-interactive") {
      options.non_interactive = true;
    } else if (arg == "--no-build") {
      options.run_build = false;
    } else if (arg == "--staging" || arg == "--prepare-only") {
      options.staging_only = true;
    } else if (arg == "--target" && i + 1 < argc) {
      options.target_name = argv[++i];
    } else if (arg == "--profile" && i + 1 < argc) {
      options.profile = ParseProfile(argv[++i]);
    } else if (arg == "--backup-dir" && i + 1 < argc) {
      options.backup_dir = argv[++i];
    } else if (arg == "--report" && i + 1 < argc) {
      options.report_json_path = argv[++i];
    } else if (arg == "--product" && i + 1 < argc) {
      options.product_id = argv[++i];
    } else if (arg == "--version" && i + 1 < argc) {
      options.release_version = argv[++i];
    } else if (arg == "--rtprotect-root" && i + 1 < argc) {
      options.rtprotect_root = argv[++i];
    } else if (arg == "--manifest-pubkey" && i + 1 < argc) {
      options.manifest_pubkey_path = argv[++i];
    } else if (arg == "--license-pubkey" && i + 1 < argc) {
      options.license_pubkey_path = argv[++i];
    } else if (arg == "--sign-manifest-key" && i + 1 < argc) {
      options.sign_manifest_key_path = argv[++i];
    } else if (arg == "--sign-license-key" && i + 1 < argc) {
      options.sign_license_key_path = argv[++i];
    } else if (arg == "--license-file" && i + 1 < argc) {
      options.license_file_path = argv[++i];
    } else if (arg == "--dev-keys-dir" && i + 1 < argc) {
      options.dev_keys_dir = argv[++i];
    } else {
      std::fprintf(stderr, "Unknown option: %s\n", arg.c_str());
      return 2;
    }
  }

  auto plan = PlanIntegration(options);
  if (!plan.is_supported) {
    std::fprintf(stderr, "error: project cannot be protected: %s\n", plan.explanation.c_str());
    return 1;
  }

  std::printf("%s\n", plan.FormatSummary().c_str());

  if (options.dry_run) {
    std::printf("Dry-run preview completed. No changes made.\n");
    if (!options.report_json_path.empty()) {
      IntegrationReport dry_report;
      dry_report.success = true;
      dry_report.modified_files = plan.files_to_modify;
      dry_report.generated_files = plan.files_to_create;
      dry_report.warnings = plan.warnings;
      WriteTextFile(options.report_json_path, dry_report.ToJson());
    }
    return 0;
  }

  auto report = ExecuteIntegration(options);
  if (!report.success) {
    std::fprintf(stderr, "Integration failed: %s\n", report.error_message.c_str());
    return 1;
  }

  switch (report.state) {
    case IntegrationState::kValidated:
      std::printf("Integration and validation succeeded! [STATE: VALIDATED (READY FOR RELEASE)]\n");
      break;
    case IntegrationState::kAwaitingSignature:
      std::printf("Project staged successfully! [STATE: AWAITING SIGNATURE (STAGED, UNSIGNED)]\n");
      std::printf("  NOTE: Release artifacts are unsigned. Run 'rtprotect-tool sign-release' on your vendor signing machine.\n");
      break;
    case IntegrationState::kIntegrated:
      std::printf("Project instrumented successfully! [STATE: INTEGRATED (UNBUILT, UNSIGNED)]\n");
      std::printf("  NOTE: Target project has not been built or validated.\n");
      break;
    case IntegrationState::kPlanned:
      std::printf("Integration plan completed! [STATE: PLANNED]\n");
      break;
    default:
      std::printf("Integration state: %s\n", ToString(report.state));
      break;
  }

  std::printf("  Backup created at: %s\n", report.backup_path.c_str());
  std::printf("  Generated files:\n");
  for (const auto& gf : report.generated_files) {
    std::printf("    + %s\n", gf.c_str());
  }
  std::printf("  Modified files:\n");
  for (const auto& mf : report.modified_files) {
    std::printf("    * %s\n", mf.c_str());
  }
  if (!report.warnings.empty()) {
    std::printf("  Warnings:\n");
    for (const auto& w : report.warnings) {
      std::printf("    ! %s\n", w.c_str());
    }
  }
  if (options.run_build) {
    std::printf("  Build status: %s\n", report.build_succeeded ? "SUCCESS" : "FAILED");
    std::printf("  Validation status: %s\n", report.validation_succeeded ? "SUCCESS" : "FAILED");
  }
  if (!options.report_json_path.empty()) {
    std::printf("  Report saved to: %s\n", options.report_json_path.c_str());
  }
  return 0;
}

int CmdRollback(int argc, char** argv) {
  if (argc != 4) {
    std::fprintf(stderr, "Usage: rtprotect-tool rollback <project-path> <backup-dir>\n");
    return 2;
  }
  std::string err;
  if (!ExecuteRollback(argv[2], argv[3], &err)) {
    std::fprintf(stderr, "Rollback failed: %s\n", err.c_str());
    return 1;
  }
  std::printf("Rollback succeeded. Restored %s from %s\n", argv[2], argv[3]);
  return 0;
}

int CmdSignRelease(int argc, char** argv) {
  if (argc < 4) {
    std::fprintf(stderr, "Usage: rtprotect-tool sign-release <project-path> --manifest-key <file> [--license <file>]\n");
    return 2;
  }
  std::string proj_path = argv[2];
  std::string manifest_privkey;
  std::string license_file;

  for (int i = 3; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--manifest-key" && i + 1 < argc) {
      manifest_privkey = argv[++i];
    } else if (arg == "--license" && i + 1 < argc) {
      license_file = argv[++i];
    } else {
      std::fprintf(stderr, "Unknown option: %s\n", arg.c_str());
      return 2;
    }
  }

  if (manifest_privkey.empty()) {
    std::fprintf(stderr, "Error: --manifest-key is required.\n");
    return 2;
  }

  std::string err;
  if (!SignRelease(proj_path, manifest_privkey, license_file, &err)) {
    std::fprintf(stderr, "Release signing failed: %s\n", err.c_str());
    return 1;
  }

  std::printf("Release signed and validated successfully for: %s\n", proj_path.c_str());
  return 0;
}

int CmdValidateBuild(int argc, char** argv) {
  if (argc != 6) {
    std::fprintf(stderr, "Usage: rtprotect-tool validate-build <project-dir> <pub-key-file> <manifest-file> <sig-file>\n");
    return 2;
  }
  std::string err;
  if (!ValidateProtectedBuild(argv[2], argv[3], argv[4], argv[5], &err)) {
    std::fprintf(stderr, "Build validation failed: %s\n", err.c_str());
    return 1;
  }
  std::printf("Build validation succeeded: all committed resources match signed manifest.\n");
  return 0;
}

int CmdLicenseGenerate(int argc, char** argv) {
  std::string priv_key_file;
  std::string out_file;
  std::string product_id = "com.client.protected";
  std::string edition = "Standard";
  std::string customer_id = "customer@domain.local";
  std::string capabilities_str = "core,commercial";
  std::uint32_t expires_in_days = 0;
  std::string hwid;
  std::string format = "binary";

  for (int i = 2; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--priv-key" && i + 1 < argc) priv_key_file = argv[++i];
    else if (arg == "--out" && i + 1 < argc) out_file = argv[++i];
    else if (arg == "--product" && i + 1 < argc) product_id = argv[++i];
    else if (arg == "--edition" && i + 1 < argc) edition = argv[++i];
    else if (arg == "--customer" && i + 1 < argc) customer_id = argv[++i];
    else if (arg == "--capabilities" && i + 1 < argc) capabilities_str = argv[++i];
    else if (arg == "--expires-in-days" && i + 1 < argc) expires_in_days = std::stoul(argv[++i]);
    else if (arg == "--hwid" && i + 1 < argc) hwid = argv[++i];
    else if (arg == "--format" && i + 1 < argc) format = argv[++i];
    else {
      std::fprintf(stderr, "error: unknown argument '%s'\n", arg.c_str());
      return 2;
    }
  }

  if (priv_key_file.empty() || out_file.empty()) {
    std::fprintf(stderr, "error: --priv-key and --out are required for license-generate\n");
    return 2;
  }

  auto priv_bytes = ReadFile(priv_key_file);
  if (!priv_bytes.has_value() || priv_bytes->size() != integrity::kEd25519PrivateKeyLen) {
    std::fprintf(stderr, "error: invalid private key file: %s\n", priv_key_file.c_str());
    return 1;
  }
  auto priv_key = integrity::Ed25519PrivateKey::FromBytes(priv_bytes->data(), priv_bytes->size());
  if (!priv_bytes->empty()) OPENSSL_cleanse(priv_bytes->data(), priv_bytes->size());
  if (!priv_key.has_value()) {
    std::fprintf(stderr, "error: failed to load private key\n");
    return 1;
  }

  licensing::License lic;
  auto now = static_cast<std::uint64_t>(std::time(nullptr));
  lic.license_id = "lic-" + std::to_string(now);
  lic.product_id = product_id;
  lic.edition = edition;
  lic.customer_id = customer_id;
  std::uint64_t caps = 0;
  std::string cap_err;
  if (!ParseCapabilitiesExact(capabilities_str, &caps, &cap_err)) {
    std::fprintf(stderr, "error: %s\n", cap_err.c_str());
    return 2;
  }
  lic.capabilities = caps;
  lic.issued_at = now;
  if (expires_in_days > 0) {
    lic.expires_at = now + static_cast<std::uint64_t>(expires_in_days) * 86400ULL;
  } else {
    lic.expires_at = 0;
  }
  lic.hardware_id = hwid.empty() ? licensing::GetLocalHardwareId() : hwid;

  if (!licensing::SignLicense(lic, *priv_key)) {
    std::fprintf(stderr, "error: failed to sign license\n");
    return 1;
  }

  if (format == "text") {
    std::string text = licensing::LicenseToText(lic);
    if (!WriteTextFile(out_file, text)) {
      std::fprintf(stderr, "error: failed to write license file\n");
      return 1;
    }
  } else {
    auto bin = licensing::SerializeLicense(lic);
    if (!WriteFile(out_file, bin.data(), bin.size())) {
      std::fprintf(stderr, "error: failed to write license file\n");
      return 1;
    }
  }

  std::printf("Successfully generated license: %s\n", out_file.c_str());
  std::printf("  License ID:    %s\n", lic.license_id.c_str());
  std::printf("  Product ID:    %s\n", lic.product_id.c_str());
  std::printf("  Edition:       %s\n", lic.edition.c_str());
  std::printf("  Customer:      %s\n", lic.customer_id.c_str());
  std::printf("  Capabilities:  %s\n", FormatCapabilities(lic.capabilities).c_str());
  std::printf("  Expires:       %s\n", lic.expires_at == 0 ? "Never (Perpetual)" : std::to_string(lic.expires_at).c_str());
  std::printf("  Hardware ID:   %s\n", lic.hardware_id.c_str());
  return 0;
}

int CmdLicenseVerify(int argc, char** argv) {
  std::string pub_key_file;
  std::string lic_file;
  std::string expected_product;
  std::string expected_edition;
  std::string expected_hwid;

  for (int i = 2; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--pub-key" && i + 1 < argc) pub_key_file = argv[++i];
    else if (arg == "--license" && i + 1 < argc) lic_file = argv[++i];
    else if (arg == "--product" && i + 1 < argc) expected_product = argv[++i];
    else if (arg == "--edition" && i + 1 < argc) expected_edition = argv[++i];
    else if (arg == "--hwid" && i + 1 < argc) expected_hwid = argv[++i];
    else {
      std::fprintf(stderr, "error: unknown argument '%s'\n", arg.c_str());
      return 2;
    }
  }

  if (pub_key_file.empty() || lic_file.empty()) {
    std::fprintf(stderr, "error: --pub-key and --license are required for license-verify\n");
    return 2;
  }

  auto pub_bytes = ReadFile(pub_key_file);
  if (!pub_bytes.has_value() || pub_bytes->size() != integrity::kEd25519PublicKeyLen) {
    std::fprintf(stderr, "error: invalid public key file: %s\n", pub_key_file.c_str());
    return 1;
  }
  integrity::Ed25519PublicKey pub_key;
  std::memcpy(pub_key.data(), pub_bytes->data(), 32);

  auto lic_data = ReadFile(lic_file);
  if (!lic_data.has_value()) {
    std::fprintf(stderr, "error: could not read license file: %s\n", lic_file.c_str());
    return 1;
  }

  licensing::LicenseVerificationContext ctx;
  ctx.current_time = static_cast<std::uint64_t>(std::time(nullptr));
  ctx.expected_product_id = expected_product;
  ctx.expected_edition = expected_edition;
  ctx.current_hardware_id = expected_hwid.empty() ? licensing::GetLocalHardwareId() : expected_hwid;

  licensing::License lic;
  licensing::LicenseStatus status = licensing::LicenseStatus::kMalformed;

  status = licensing::VerifyLicenseBytes(lic_data->data(), lic_data->size(), pub_key, ctx, &lic);
  if (status == licensing::LicenseStatus::kMalformed) {
    std::string text_str(reinterpret_cast<const char*>(lic_data->data()), lic_data->size());
    auto maybe_lic = licensing::LicenseFromText(text_str);
    if (maybe_lic.has_value()) {
      lic = *maybe_lic;
      status = licensing::VerifyLicense(lic, pub_key, ctx);
    }
  }

  if (status == licensing::LicenseStatus::kValid) {
    std::printf("VALID: License verified successfully!\n");
    std::printf("  License ID:   %s\n", lic.license_id.c_str());
    std::printf("  Product:      %s\n", lic.product_id.c_str());
    std::printf("  Edition:      %s\n", lic.edition.c_str());
    std::printf("  Customer:     %s\n", lic.customer_id.c_str());
    std::printf("  Capabilities: %s\n", FormatCapabilities(lic.capabilities).c_str());
    return 0;
  } else {
    std::fprintf(stderr, "INVALID: License verification failed: %s\n", licensing::ToString(status));
    return 1;
  }
}

int CmdLicenseInspect(int argc, char** argv) {
  if (argc != 3) {
    std::fprintf(stderr, "Usage: rtprotect-tool license-inspect <license-file>\n");
    return 2;
  }
  auto data = ReadFile(argv[2]);
  if (!data.has_value()) {
    std::fprintf(stderr, "error: could not read %s\n", argv[2]);
    return 1;
  }
  auto lic = licensing::DeserializeLicense(data->data(), data->size());
  if (!lic.has_value()) {
    std::string text(reinterpret_cast<const char*>(data->data()), data->size());
    lic = licensing::LicenseFromText(text);
  }
  if (!lic.has_value()) {
    std::fprintf(stderr, "error: file is not a valid RTProtect binary or text license\n");
    return 1;
  }
  std::printf("RTProtect License Details:\n");
  std::printf("  Schema Version: %u\n", lic->schema_version);
  std::printf("  License ID:     %s\n", lic->license_id.c_str());
  std::printf("  Product ID:     %s\n", lic->product_id.c_str());
  std::printf("  Edition:        %s\n", lic->edition.c_str());
  std::printf("  Customer ID:    %s\n", lic->customer_id.c_str());
  std::printf("  Capabilities:   %s (0x%016llX)\n", FormatCapabilities(lic->capabilities).c_str(), static_cast<unsigned long long>(lic->capabilities));
  std::printf("  Issued At:      %llu\n", static_cast<unsigned long long>(lic->issued_at));
  if (lic->expires_at == 0) {
    std::printf("  Expires At:     0 (Never - Perpetual)\n");
  } else {
    std::printf("  Expires At:     %llu\n", static_cast<unsigned long long>(lic->expires_at));
  }
  std::printf("  Grace Period:   %u days\n", static_cast<unsigned>(lic->grace_period_seconds / 86400));
  std::printf("  Hardware ID:    %s\n", lic->hardware_id.c_str());
  std::printf("  Signature:      %s...\n", ToHex(lic->signature.data(), 16).c_str());
  return 0;
}

int CmdFingerprint(int argc, char** argv) {
  bool canonical = false;
  if (argc >= 3 && std::string(argv[2]) == "--canonical") {
    canonical = true;
  }
  auto fp = licensing::GetLocalHardwareFingerprint();
  if (canonical) {
    std::printf("%s\n", fp.composite_id.c_str());
    return 0;
  }
  std::printf("RTProtect Hardware Fingerprint:\n");
  std::printf("  CPU Component:     %s\n", fp.cpu_component.c_str());
  std::printf("  Storage Component: %s\n", fp.storage_component.c_str());
  std::printf("  System Component:  %s\n", fp.system_component.c_str());
  std::printf("  Host Component:    %s\n", fp.host_component.c_str());
  std::printf("  ----------------------------------------------------------------\n");
  std::printf("  Composite HWID:    %s\n", fp.composite_id.c_str());
  return 0;
}

int CmdActivateIssue(int argc, char** argv) {
  std::string priv_key_file;
  std::string license_id;
  std::string out_file;
  std::string hwid;
  std::string format = "binary";
  std::string revocation_db_file;
  int validity_hours = 24;

  for (int i = 2; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--priv-key" && i + 1 < argc) priv_key_file = argv[++i];
    else if (arg == "--license-id" && i + 1 < argc) license_id = argv[++i];
    else if (arg == "--out" && i + 1 < argc) out_file = argv[++i];
    else if (arg == "--hwid" && i + 1 < argc) hwid = argv[++i];
    else if (arg == "--validity-hours" && i + 1 < argc) validity_hours = std::atoi(argv[++i]);
    else if (arg == "--format" && i + 1 < argc) format = argv[++i];
    else if (arg == "--revocation-db" && i + 1 < argc) revocation_db_file = argv[++i];
    else {
      std::fprintf(stderr, "error: unknown argument '%s'\n", arg.c_str());
      return 2;
    }
  }

  if (priv_key_file.empty() || license_id.empty() || out_file.empty()) {
    std::fprintf(stderr, "error: --priv-key, --license-id, and --out are required for activate-issue\n");
    return 2;
  }

  auto priv_bytes = ReadFile(priv_key_file);
  if (!priv_bytes.has_value() || priv_bytes->size() != integrity::kEd25519PrivateKeyLen) {
    std::fprintf(stderr, "error: invalid private key file: %s\n", priv_key_file.c_str());
    return 1;
  }
  auto priv_key = integrity::Ed25519PrivateKey::FromBytes(priv_bytes->data(), priv_bytes->size());
  if (!priv_key.has_value()) {
    std::fprintf(stderr, "error: could not load private key\n");
    return 1;
  }

  licensing::ActivationManager mgr;
  if (!revocation_db_file.empty()) {
    auto db_text = ReadTextFile(revocation_db_file);
    if (db_text.has_value()) {
      mgr.ImportRevocationListJson(*db_text);
    }
  }

  std::string target_hwid = (hwid.empty() || hwid == "local") ? licensing::GetLocalHardwareId() : hwid;
  auto now = static_cast<std::uint64_t>(std::time(nullptr));
  auto req = licensing::CreateActivationRequest(license_id, target_hwid, "1.0.0", now);

  std::uint64_t validity_seconds = static_cast<std::uint64_t>(std::max(1, validity_hours)) * 3600ULL;
  auto result = mgr.IssueTicket(req, *priv_key, validity_seconds, now);
  if (result.status != licensing::ActivationStatus::kValid || !result.ticket.has_value()) {
    std::fprintf(stderr, "error: failed to issue activation ticket: %s\n",
                 result.error_message.empty() ? licensing::ToString(result.status) : result.error_message.c_str());
    return 1;
  }

  if (format == "text") {
    std::string text = licensing::ActivationTicketToText(*result.ticket);
    if (!WriteTextFile(out_file, text)) {
      std::fprintf(stderr, "error: failed to write ticket file: %s\n", out_file.c_str());
      return 1;
    }
  } else {
    auto bin = licensing::SerializeActivationTicket(*result.ticket);
    if (!WriteFile(out_file, bin.data(), bin.size())) {
      std::fprintf(stderr, "error: failed to write ticket file: %s\n", out_file.c_str());
      return 1;
    }
  }

  std::printf("Successfully issued activation ticket: %s\n", out_file.c_str());
  std::printf("  Ticket ID:     %s\n", result.ticket->ticket_id.c_str());
  std::printf("  License ID:    %s\n", result.ticket->license_id.c_str());
  std::printf("  Hardware ID:   %s\n", result.ticket->hardware_id.c_str());
  std::printf("  Issued At:     %llu\n", static_cast<unsigned long long>(result.ticket->issued_at));
  std::printf("  Expires At:    %llu (%d hours)\n", static_cast<unsigned long long>(result.ticket->expires_at), validity_hours);
  return 0;
}

int CmdActivateVerify(int argc, char** argv) {
  std::string pub_key_file;
  std::string ticket_file;
  std::string expected_license;
  std::string expected_hwid;
  std::string revocation_db_file;

  for (int i = 2; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--pub-key" && i + 1 < argc) pub_key_file = argv[++i];
    else if (arg == "--ticket" && i + 1 < argc) ticket_file = argv[++i];
    else if (arg == "--license-id" && i + 1 < argc) expected_license = argv[++i];
    else if (arg == "--hwid" && i + 1 < argc) expected_hwid = argv[++i];
    else if (arg == "--revocation-db" && i + 1 < argc) revocation_db_file = argv[++i];
    else {
      std::fprintf(stderr, "error: unknown argument '%s'\n", arg.c_str());
      return 2;
    }
  }

  if (pub_key_file.empty() || ticket_file.empty()) {
    std::fprintf(stderr, "error: --pub-key and --ticket are required for activate-verify\n");
    return 2;
  }

  auto pub_bytes = ReadFile(pub_key_file);
  if (!pub_bytes.has_value() || pub_bytes->size() != integrity::kEd25519PublicKeyLen) {
    std::fprintf(stderr, "error: invalid public key file: %s\n", pub_key_file.c_str());
    return 1;
  }
  integrity::Ed25519PublicKey pub_key;
  std::memcpy(pub_key.data(), pub_bytes->data(), 32);

  auto tkt_data = ReadFile(ticket_file);
  if (!tkt_data.has_value()) {
    std::fprintf(stderr, "error: could not read ticket file: %s\n", ticket_file.c_str());
    return 1;
  }

  std::optional<licensing::ActivationTicket> ticket =
      licensing::DeserializeActivationTicket(tkt_data->data(), tkt_data->size());
  if (!ticket.has_value()) {
    std::string text(reinterpret_cast<const char*>(tkt_data->data()), tkt_data->size());
    ticket = licensing::ActivationTicketFromText(text);
  }

  if (!ticket.has_value()) {
    std::fprintf(stderr, "error: failed to parse activation ticket (corrupted or unrecognized format)\n");
    return 1;
  }

  if (!revocation_db_file.empty()) {
    auto db_text = ReadTextFile(revocation_db_file);
    if (db_text.has_value()) {
      licensing::ActivationManager mgr;
      mgr.ImportRevocationListJson(*db_text);
      if (mgr.IsLicenseRevoked(ticket->license_id)) {
        std::fprintf(stderr, "VERIFICATION FAILED: License '%s' has been revoked\n", ticket->license_id.c_str());
        return 1;
      }
      if (mgr.IsTicketRevoked(ticket->ticket_id)) {
        std::fprintf(stderr, "VERIFICATION FAILED: Ticket '%s' has been revoked\n", ticket->ticket_id.c_str());
        return 1;
      }
    }
  }

  licensing::ActivationRequest req;
  req.license_id = expected_license.empty() ? ticket->license_id : expected_license;
  req.hardware_id = (expected_hwid.empty() || expected_hwid == "local") ? licensing::GetLocalHardwareId() : expected_hwid;
  req.nonce = ticket->nonce; // Mirrored nonce check

  auto now = static_cast<std::uint64_t>(std::time(nullptr));
  auto status = licensing::VerifyActivationTicket(*ticket, pub_key, req, now);

  if (status != licensing::ActivationStatus::kValid) {
    std::fprintf(stderr, "VERIFICATION FAILED: %s\n", licensing::ToString(status));
    return 1;
  }

  std::printf("Ticket Verification Succeeded:\n");
  std::printf("  Ticket ID:    %s\n", ticket->ticket_id.c_str());
  std::printf("  License ID:   %s\n", ticket->license_id.c_str());
  std::printf("  Hardware ID:  %s\n", ticket->hardware_id.c_str());
  std::printf("  Issued At:    %llu\n", static_cast<unsigned long long>(ticket->issued_at));
  std::printf("  Expires At:   %llu\n", static_cast<unsigned long long>(ticket->expires_at));
  std::printf("  Status:       Valid\n");
  return 0;
}

int CmdActivateRevoke(int argc, char** argv) {
  std::string db_file;
  std::string revoke_license_id;
  std::string revoke_ticket_id;
  std::string unrevoke_license_id;
  std::string unrevoke_ticket_id;
  std::string reason = "Revoked by vendor";
  bool list_entries = false;

  for (int i = 2; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--db" && i + 1 < argc) db_file = argv[++i];
    else if (arg == "--revoke-license" && i + 1 < argc) revoke_license_id = argv[++i];
    else if (arg == "--revoke-ticket" && i + 1 < argc) revoke_ticket_id = argv[++i];
    else if (arg == "--unrevoke-license" && i + 1 < argc) unrevoke_license_id = argv[++i];
    else if (arg == "--unrevoke-ticket" && i + 1 < argc) unrevoke_ticket_id = argv[++i];
    else if (arg == "--reason" && i + 1 < argc) reason = argv[++i];
    else if (arg == "--list") list_entries = true;
    else {
      std::fprintf(stderr, "error: unknown argument '%s'\n", arg.c_str());
      return 2;
    }
  }

  if (db_file.empty()) {
    std::fprintf(stderr, "error: --db <file> is required for activate-revoke\n");
    return 2;
  }

  licensing::ActivationManager mgr;
  auto existing = ReadTextFile(db_file);
  if (existing.has_value()) {
    mgr.ImportRevocationListJson(*existing);
  }

  bool modified = false;
  if (!revoke_license_id.empty()) {
    mgr.RevokeLicense(revoke_license_id, reason);
    std::printf("Revoked license: %s (reason: %s)\n", revoke_license_id.c_str(), reason.c_str());
    modified = true;
  }
  if (!revoke_ticket_id.empty()) {
    mgr.RevokeTicket(revoke_ticket_id, reason);
    std::printf("Revoked ticket: %s (reason: %s)\n", revoke_ticket_id.c_str(), reason.c_str());
    modified = true;
  }
  if (!unrevoke_license_id.empty()) {
    mgr.UnrevokeLicense(unrevoke_license_id);
    std::printf("Unrevoked license: %s\n", unrevoke_license_id.c_str());
    modified = true;
  }
  if (!unrevoke_ticket_id.empty()) {
    mgr.UnrevokeTicket(unrevoke_ticket_id);
    std::printf("Unrevoked ticket: %s\n", unrevoke_ticket_id.c_str());
    modified = true;
  }

  if (modified) {
    std::string exported = mgr.ExportRevocationListJson();
    if (!WriteTextFile(db_file, exported)) {
      std::fprintf(stderr, "error: failed to write updated revocation db: %s\n", db_file.c_str());
      return 1;
    }
    std::printf("Saved updated revocation database to %s\n", db_file.c_str());
  }

  if (list_entries || !modified) {
    std::printf("Current Revocation Database (%s):\n", db_file.c_str());
    std::string json = mgr.ExportRevocationListJson();
    std::printf("%s\n", json.c_str());
  }
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    PrintUsage();
    return 2;
  }
  std::string cmd = argv[1];

  if (cmd == "--help" || cmd == "-h" || cmd == "help") {
    PrintUsage();
    return 0;
  }
  if (cmd == "--version" || cmd == "-v" || cmd == "version") {
    std::printf("RTProtect CLI v2.0.0-hardened\n"
                "  Ed25519 Asymmetric Integrity & Licensing\n"
                "  Hardware Fingerprinting & Anti-Tamper Engine\n"
                "  OpenSSL 3.4.0 EVP Backend\n");
    return 0;
  }

  // Integration & Lifecycle commands
  if (cmd == "integrate") return CmdIntegrate(argc, argv);
  if (cmd == "unreal-integrate") return CmdIntegrate(argc, argv);
  if (cmd == "sign-release") return CmdSignRelease(argc, argv);
  if (cmd == "rollback") return CmdRollback(argc, argv);
  if (cmd == "validate-build") return CmdValidateBuild(argc, argv);

  // Licensing & HWID commands
  if (cmd == "license-generate") return CmdLicenseGenerate(argc, argv);
  if (cmd == "license-verify") return CmdLicenseVerify(argc, argv);
  if (cmd == "license-inspect") return CmdLicenseInspect(argc, argv);
  if (cmd == "fingerprint") return CmdFingerprint(argc, argv);

  // Online Activation & Revocation
  if (cmd == "activate-issue") return CmdActivateIssue(argc, argv);
  if (cmd == "activate-verify") return CmdActivateVerify(argc, argv);
  if (cmd == "activate-revoke") return CmdActivateRevoke(argc, argv);

  // Cryptographic Primitives
  if (cmd == "genkey-ed25519") return CmdGenkeyEd25519(argc, argv);
  if (cmd == "genkey-aes") return CmdGenkeyAes(argc, argv);
  if (cmd == "hash") return CmdHash(argc, argv);
  if (cmd == "encrypt") return CmdEncrypt(argc, argv);
  if (cmd == "decrypt") return CmdDecrypt(argc, argv);
  if (cmd == "manifest-build") return CmdManifestBuild(argc, argv);
  if (cmd == "manifest-sign") return CmdManifestSign(argc, argv);
  if (cmd == "manifest-verify") return CmdManifestVerify(argc, argv);

  std::fprintf(stderr, "error: unknown command '%s'\n\n", cmd.c_str());
  PrintUsage();
  return 2;
}
