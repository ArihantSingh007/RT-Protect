// tooling/activation_server_main.cpp
//
// Standalone network server for RTProtect Activation Authority.
// Serves /activate, /renew, and /deactivate REST endpoints backed by
// persistent database storage and Ed25519 cryptographic token signing.

#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>

#include <openssl/rand.h>

#include "integrity/keys.h"
#include "integrity/signer.h"
#include "licensing/activation_database.h"
#include "licensing/activation_server_http.h"
#include "licensing/activation_service.h"
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
            << "  --register-license <id> <prod> <seats> [vm_root_hex]\n"
            << "                                 Register a license and exit\n"
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

  std::string reg_lic_id;
  std::string reg_prod_id;
  std::uint32_t reg_seats = 1;
  std::string reg_vm_root_hex;

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
    LicenseRecord rec;
    rec.license_id = reg_lic_id;
    rec.product_id = reg_prod_id;
    rec.max_seats = reg_seats;
    rec.status = LicenseRecordStatus::kActive;
    auto now = std::chrono::system_clock::now().time_since_epoch();
    rec.created_at = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(now).count());

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
              << "Canonical vm_root: " << BytesToHex(rec.vm_root.data(), rec.vm_root.size()) << "\n";
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

  // Load or generate Ed25519 signing key
  std::optional<integrity::Ed25519KeyPair> key_pair;
  if (!key_path.empty()) {
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
    key_pair = integrity::Ed25519KeyPair{std::move(*priv), pub};
  } else {
    std::cout << "Generating ephemeral Ed25519 signing key pair for development server...\n";
    key_pair = integrity::GenerateEd25519KeyPair();
    if (!key_pair.has_value()) {
      std::cerr << "Error: Failed to generate Ed25519 key pair\n";
      return 1;
    }
  }

  ActivationService service(db, std::move(key_pair->private_key), key_pair->public_key);
  ActivationServerHttp server(service);

  if (!server.Start(port, host)) {
    std::cerr << "Error: Failed to start HTTP server on " << host << ":" << port << "\n";
    return 1;
  }

  std::signal(SIGINT, SignalHandler);
  std::signal(SIGTERM, SignalHandler);

  std::cout << "RTProtect Activation Server running at " << server.base_url() << "\n"
            << "Public Key: " << BytesToHex(key_pair->public_key.data(), key_pair->public_key.size()) << "\n"
            << "Press Ctrl+C to terminate.\n";

  while (!g_stop_requested.load()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }

  std::cout << "\nShutting down server...\n";
  server.Stop();
  db.Save();
  std::cout << "Server stopped cleanly.\n";
  return 0;
}
