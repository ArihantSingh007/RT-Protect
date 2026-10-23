// tooling/activation_server_main.cpp
//
// Standalone network server for RTProtect Activation Authority.
// Serves /activate, /renew, and /deactivate REST endpoints backed by
// persistent database storage and Ed25519 cryptographic token signing.

#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>

#include <openssl/rand.h>

#include "integrity/keys.h"
#include "integrity/signer.h"
#include "integrity/verifier.h"
#include "licensing/activation_database.h"
#include "licensing/activation_server_http.h"
#include "licensing/activation_service.h"
#include "licensing/secrets_manager.h"
#include "tooling/file_io.h"

using namespace rtprotect;
using namespace rtprotect::licensing;

namespace {

std::atomic<bool> g_stop_requested{false};

void SignalHandler(int) {
  g_stop_requested.store(true);
}

void PrintUsage() {
  std::cout << "RTProtect Activation Server v2.0.0\n\n"
            << "Usage:\n"
            << "  rtprotect-activation-server [options]\n\n"
            << "Options:\n"
            << "  --port <p>                     Listen port (default: 8080)\n"
            << "  --host <h>                     Listen address (default: 127.0.0.1)\n"
            << "  --db <path>                    Database file path (default: activations.db)\n"
            << "  --key <path>                   Ed25519 signing private key file (required or auto-generated)\n"
            << "  --key-vault <type>             Vault type: 'dpapi' (default), 'env', or 'file'\n"
            << "  --vault-id <id>                Retrieve signing key from secret store by ID\n"
            << "  --vault-dir <path>             Custom directory path for secret vault store\n"
            << "  --provision-vault <id> <pub>   Generate key directly into vault, export public key to <pub>, and exit\n"
            << "  --tls-cert <path>              TLS server certificate PEM file\n"
            << "  --tls-key <path>               TLS server private key PEM file\n"
            << "  --insecure-dev-only            Allow non-loopback binding without TLS and print secrets\n"
            << "  --admin-token <token>          Shared secret token for administrative /events and /analytics endpoints\n"
            << "  --admin-token-file <path>      File containing administrative shared secret token\n"
            << "  --register-license <id> <prod> <seats> [vm_root_hex]\n"
            << "                                 Register a license and exit\n"
            << "  --credential <secret>          Secret activation credential for registered license\n"
            << "  --generate-credential          Cryptographically generate a random activation credential secret\n"
            << "  --revoke-license <id>          Revoke a license and exit\n"
            << "  --help                         Show this help message\n"
            << "  --version                      Display version information\n";
}

std::string BytesToHex(const std::uint8_t* data, std::size_t len) {
  std::ostringstream ss;
  for (std::size_t i = 0; i < len; ++i) {
    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
  }
  return ss.str();
}

bool HexToBytes(const std::string& hex, std::uint8_t* out, std::size_t expected_len) {
  if (hex.size() != expected_len * 2) return false;
  for (std::size_t i = 0; i < expected_len; ++i) {
    char h[3] = { hex[i * 2], hex[i * 2 + 1], '\0' };
    char* end = nullptr;
    long v = std::strtol(h, &end, 16);
    if (end != h + 2 || v < 0 || v > 255) return false;
    out[i] = static_cast<std::uint8_t>(v);
  }
  return true;
}

}  // namespace

int main(int argc, char* argv[]) {
  std::uint16_t port = 8080;
  std::string host = "127.0.0.1";
  std::string db_path = "activations.db";
  std::string key_path;
  std::string vault_type_str;
  std::string vault_id;
  std::string vault_dir;
  std::string provision_vault_id;
  std::string provision_pubkey_path;
  std::string tls_cert_path;
  std::string tls_key_path;
  std::string admin_token;
  std::string admin_token_file;
  bool insecure_dev_only = false;

  std::string reg_lic_id;
  std::string reg_prod_id;
  std::uint32_t reg_seats = 1;
  std::string reg_vm_root_hex;
  std::string reg_credential;
  bool reg_generate_cred = false;

  std::string revoke_lic_id;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--help" || arg == "-h") {
      PrintUsage();
      return 0;
    } else if (arg == "--version" || arg == "-v") {
      std::cout << "rtprotect-activation-server v2.0.0\n";
      return 0;
    } else if (arg == "--port" && i + 1 < argc) {
      port = static_cast<std::uint16_t>(std::strtoul(argv[++i], nullptr, 10));
    } else if (arg == "--host" && i + 1 < argc) {
      host = argv[++i];
    } else if (arg == "--db" && i + 1 < argc) {
      db_path = argv[++i];
    } else if (arg == "--key" && i + 1 < argc) {
      key_path = argv[++i];
    } else if (arg == "--key-vault" && i + 1 < argc) {
      vault_type_str = argv[++i];
    } else if (arg == "--vault-id" && i + 1 < argc) {
      vault_id = argv[++i];
    } else if (arg == "--vault-dir" && i + 1 < argc) {
      vault_dir = argv[++i];
    } else if (arg == "--provision-vault" && i + 2 < argc) {
      provision_vault_id = argv[++i];
      provision_pubkey_path = argv[++i];
    } else if (arg == "--tls-cert" && i + 1 < argc) {
      tls_cert_path = argv[++i];
    } else if (arg == "--tls-key" && i + 1 < argc) {
      tls_key_path = argv[++i];
    } else if (arg == "--insecure-dev-only") {
      insecure_dev_only = true;
    } else if (arg == "--admin-token" && i + 1 < argc) {
      admin_token = argv[++i];
    } else if (arg == "--admin-token-file" && i + 1 < argc) {
      admin_token_file = argv[++i];
    } else if (arg == "--credential" && i + 1 < argc) {
      reg_credential = argv[++i];
    } else if (arg == "--generate-credential") {
      reg_generate_cred = true;
    } else if (arg == "--register-license" && i + 3 < argc) {
      reg_lic_id = argv[++i];
      reg_prod_id = argv[++i];
      reg_seats = static_cast<std::uint32_t>(std::strtoul(argv[++i], nullptr, 10));
      if (i + 1 < argc && argv[i + 1][0] != '-') {
        reg_vm_root_hex = argv[++i];
      }
    } else if (arg == "--revoke-license" && i + 1 < argc) {
      revoke_lic_id = argv[++i];
    }
  }

  ActivationDatabase db(db_path);

  if (!reg_lic_id.empty()) {
    if (reg_credential.empty() && !reg_generate_cred && !insecure_dev_only) {
      std::cerr << "Error: --register-license requires --credential <secret> or --generate-credential in production mode.\n"
                << "       (Pass --insecure-dev-only to register credential-free licenses for local testing).\n";
      return 1;
    }

    if (reg_generate_cred) {
      std::array<std::uint8_t, 32> cred_bytes{};
      if (RAND_bytes(cred_bytes.data(), static_cast<int>(cred_bytes.size())) != 1) {
        std::cerr << "Error: Cryptographic RNG failure generating activation credential\n";
        return 1;
      }
      reg_credential = BytesToHex(cred_bytes.data(), cred_bytes.size());
    }

    LicenseRecord rec;
    rec.license_id = reg_lic_id;
    rec.product_id = reg_prod_id;
    rec.max_seats = reg_seats;
    rec.status = LicenseRecordStatus::kActive;
    auto now = std::chrono::system_clock::now().time_since_epoch();
    rec.created_at = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(now).count());

    if (!reg_credential.empty()) {
      auto cred_hash = integrity::Sha256(
          reinterpret_cast<const std::uint8_t*>(reg_credential.data()),
          reg_credential.size());
      if (!cred_hash.has_value()) {
        std::cerr << "Error: Failed to compute SHA-256 verifier for activation credential\n";
        return 1;
      }
      rec.activation_credential_hash = BytesToHex(cred_hash->data(), cred_hash->size());
    }

    if (!reg_vm_root_hex.empty()) {
      if (!HexToBytes(reg_vm_root_hex, rec.vm_root.data(), rec.vm_root.size())) {
        std::cerr << "Error: Invalid vm_root_hex (expected 64 hex characters)\n";
        return 1;
      }
    } else {
      if (RAND_bytes(rec.vm_root.data(), static_cast<int>(rec.vm_root.size())) != 1) {
        std::cerr << "Error: RNG failure generating vm_root\n";
        return 1;
      }
    }

    if (!db.RegisterLicense(rec) || !db.Save()) {
      std::cerr << "Error: Failed to register license in database\n";
      return 1;
    }

    std::cout << "Registered license " << rec.license_id
              << " for product " << rec.product_id
              << " with " << rec.max_seats << " seats.\n"
              << "Canonical vm_root: [PROVISIONED: " << BytesToHex(rec.vm_root.data(), 4) << "...redacted]\n";
    if (!reg_credential.empty()) {
      std::cout << "Activation Credential: " << reg_credential << "\n"
                << "Credential Hash (SHA-256): " << rec.activation_credential_hash << "\n"
                << "[IMPORTANT] Deliver the Activation Credential to licensee; only the hash verifier is stored on server.\n";
    }
    return 0;
  }

  if (!revoke_lic_id.empty()) {
    if (!db.UpdateLicenseStatus(revoke_lic_id, LicenseRecordStatus::kRevoked) || !db.Save()) {
      std::cerr << "Error: Failed to revoke license " << revoke_lic_id << "\n";
      return 1;
    }
    std::cout << "Successfully revoked license " << revoke_lic_id << "\n";
    return 0;
  }

  // Handle direct vault provisioning command
  if (!provision_vault_id.empty()) {
    SecretProviderType ptype = SecretProviderType::kWindowsDpapiVault;
    if (!vault_type_str.empty()) {
      auto parsed = ParseSecretProviderType(vault_type_str);
      if (!parsed) {
        std::cerr << "Error: Unknown secret vault type: " << vault_type_str
                  << " (supported: 'dpapi', 'env', 'file')\n";
        return 1;
      }
      ptype = *parsed;
    }
    auto provider = CreateSecretProvider(ptype, vault_dir);
    if (!provider) {
      std::cerr << "Error: Failed to initialize secret provider " << ToString(ptype) << "\n";
      return 1;
    }
    integrity::Ed25519PublicKey pub{};
    std::string err;
    if (!ProvisionSigningKeyInVault(*provider, provision_vault_id, provision_pubkey_path, &pub, &err)) {
      std::cerr << "Error: Failed to provision key in vault: " << err << "\n";
      return 1;
    }
    std::cout << "Successfully generated and provisioned Ed25519 signing key into "
              << provider->Name() << " under ID '" << provision_vault_id << "'.\n"
              << "Exported public verification key to: " << provision_pubkey_path << "\n"
              << "Public Key (hex): " << BytesToHex(pub.data(), pub.size()) << "\n";
    return 0;
  }

  // Load or generate Ed25519 signing key
  std::optional<integrity::Ed25519KeyPair> key_pair;
  if (!vault_id.empty()) {
    SecretProviderType ptype = SecretProviderType::kWindowsDpapiVault;
    if (!vault_type_str.empty()) {
      auto parsed = ParseSecretProviderType(vault_type_str);
      if (!parsed) {
        std::cerr << "Error: Unknown secret vault type: " << vault_type_str << "\n";
        return 1;
      }
      ptype = *parsed;
    }
    auto provider = CreateSecretProvider(ptype, vault_dir);
    if (!provider) {
      std::cerr << "Error: Failed to initialize secret provider " << ToString(ptype) << "\n";
      return 1;
    }
    std::string err;
    key_pair = provider->RetrieveSigningKeyPair(vault_id, &err);
    if (!key_pair.has_value()) {
      std::cerr << "Error: Failed to retrieve signing key '" << vault_id << "' from vault ("
                << provider->Name() << "): " << err << "\n";
      return 1;
    }
    std::cout << "Securely retrieved signing key from " << provider->Name()
              << " (Vault ID: " << vault_id << ")\n";
  } else if (!key_path.empty()) {
    auto kbytes = tooling::ReadFile(key_path);
    if (!kbytes.has_value() || kbytes->size() != integrity::kEd25519PrivateKeyLen) {
      std::cerr << "Error: Unable to read valid Ed25519 private key from " << key_path << "\n";
      return 1;
    }
    auto priv = integrity::Ed25519PrivateKey::FromBytes(kbytes->data(), kbytes->size());
    if (!priv.has_value()) {
      std::cerr << "Error: Invalid private key bytes\n";
      return 1;
    }
    // Reconstruct public key from private key
    // For Ed25519, public key can be derived or loaded
    std::string pub_path = key_path;
    if (pub_path.size() >= 5 && pub_path.substr(pub_path.size() - 5) == ".priv") {
      pub_path = pub_path.substr(0, pub_path.size() - 5) + ".pub";
    }
    auto pbytes = tooling::ReadFile(pub_path);
    if (!pbytes.has_value() || pbytes->size() != 32) {
      std::cerr << "Error: Matching public key file " << pub_path << " not found\n";
      return 1;
    }
    integrity::Ed25519PublicKey pub{};
    std::memcpy(pub.data(), pbytes->data(), 32);

    // Cryptographically verify that the public key matches the private key
    std::vector<std::uint8_t> probe_bytes = {'R', 'T', 'P', 'r', 'o', 't', 'e', 'c', 't', 'K', 'e', 'y'};
    auto sig = integrity::SignManifestBytes(probe_bytes, *priv);
    if (!sig.has_value() || !integrity::VerifyManifestSignature(probe_bytes, *sig, pub)) {
      std::cerr << "Error: Loaded public key " << pub_path << " does not match private key " << key_path << "\n";
      return 1;
    }

    key_pair = integrity::Ed25519KeyPair{std::move(*priv), pub};
  } else {
    std::cout << "Generating ephemeral Ed25519 signing key pair for development server...\n"
              << "[NOTICE] For production deployments, specify --vault-id to load protected keys from DPAPI or Secrets Manager.\n";
    key_pair = integrity::GenerateEd25519KeyPair();
    if (!key_pair.has_value()) {
      std::cerr << "Error: Failed to generate Ed25519 key pair\n";
      return 1;
    }
  }

  ActivationService service(db, std::move(key_pair->private_key), key_pair->public_key);
  service.SetRequireActivationCredentials(!insecure_dev_only);
  ActivationServerHttp server(service);
  server.SetAllowInsecureNonLoopback(insecure_dev_only);

  if (admin_token.empty() && !admin_token_file.empty()) {
    auto file_bytes = tooling::ReadFile(admin_token_file);
    if (!file_bytes.has_value()) {
      std::cerr << "Error: Unable to read admin token file: " << admin_token_file << "\n";
      return 1;
    }
    admin_token.assign(reinterpret_cast<const char*>(file_bytes->data()), file_bytes->size());
    while (!admin_token.empty() && (admin_token.back() == '\r' || admin_token.back() == '\n' || admin_token.back() == ' ')) {
      admin_token.pop_back();
    }
  }
  if (admin_token.empty()) {
    const char* env_token = std::getenv("RTPROTECT_ADMIN_TOKEN");
    if (env_token && std::strlen(env_token) > 0) {
      admin_token = env_token;
    }
  }

  if (!admin_token.empty()) {
    server.SetAdminAuthToken(admin_token);
  }

  if (!tls_cert_path.empty() || !tls_key_path.empty()) {
    if (tls_cert_path.empty() || tls_key_path.empty()) {
      std::cerr << "Error: Both --tls-cert and --tls-key must be specified together.\n";
      return 1;
    }
    if (!server.EnableTls(tls_cert_path, tls_key_path)) {
      std::cerr << "Error: Failed to enable TLS with certificate '" << tls_cert_path
                << "' and key '" << tls_key_path << "'. Check file paths and PEM format.\n";
      return 1;
    }
  }

  bool is_loopback = (host == "127.0.0.1" || host == "localhost" || host == "::1");
  if (!is_loopback && !server.is_tls() && !insecure_dev_only) {
    std::cerr << "Error: Refusing to start unencrypted HTTP server on non-loopback host '" << host
              << "'. Pass --tls-cert and --tls-key to enable TLS, or pass --insecure-dev-only to override.\n";
    return 1;
  }

  if (!server.Start(port, host)) {
    std::cerr << "Error: Failed to start HTTP server on " << host << ":" << port << "\n";
    return 1;
  }

  std::signal(SIGINT, SignalHandler);
  std::signal(SIGTERM, SignalHandler);

  std::cout << "RTProtect Activation Server running at " << server.base_url() << "\n"
            << "Public Key:  " << BytesToHex(key_pair->public_key.data(), key_pair->public_key.size()) << "\n";
  if (insecure_dev_only) {
    std::cout << "Admin Token: " << server.admin_auth_token() << " (insecure-dev-only)\n";
  } else {
    std::cout << "Admin Token: [REDACTED; pass --insecure-dev-only to print to stdout]\n";
  }
  std::cout << "Press Ctrl+C to terminate.\n";

  while (!g_stop_requested.load()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }

  std::cout << "\nShutting down server...\n";
  server.Stop();
  db.Save();
  std::cout << "Server stopped cleanly.\n";
  return 0;
}
