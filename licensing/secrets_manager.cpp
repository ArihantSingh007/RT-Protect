// licensing/secrets_manager.cpp

#include "licensing/secrets_manager.h"

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <shlobj.h>
#endif

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include "integrity/signer.h"
#include "integrity/verifier.h"
#include "tooling/file_io.h"

namespace rtprotect::licensing {

namespace {

namespace fs = std::filesystem;

inline constexpr std::uint32_t kVaultMagic = 0x52545356; // 'RTSV' - RT Server Vault
inline constexpr std::uint32_t kVaultVersion = 1;

const std::uint8_t kVaultEntropy[] = {
  0x52, 0x54, 0x50, 0x5F, 0x53, 0x45, 0x52, 0x56,
  0x45, 0x52, 0x5F, 0x56, 0x41, 0x55, 0x4C, 0x54
};

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


bool VerifyKeyPairCorrespondence(const integrity::Ed25519PrivateKey& priv,
                                 const integrity::Ed25519PublicKey& pub) {
  std::vector<std::uint8_t> probe = {'R', 'T', 'P', 'V', 'a', 'u', 'l', 't', 'P', 'r', 'o', 'b', 'e'};
  auto sig = integrity::SignManifestBytes(probe, priv);
  if (!sig.has_value()) return false;
  return integrity::VerifyManifestSignature(probe, *sig, pub);
}

// -----------------------------------------------------------------------------
// Windows DPAPI Vault Implementation
// -----------------------------------------------------------------------------
class WindowsDpapiVaultProvider : public IServerSecretProvider {
 public:
  explicit WindowsDpapiVaultProvider(std::string base_dir) : base_dir_(std::move(base_dir)) {
    if (base_dir_.empty()) {
#if defined(_WIN32)
      char path[MAX_PATH] = {0};
      if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, path)) && path[0]) {
        base_dir_ = (fs::path(path) / "RTProtect" / "vault").string();
      } else if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, path)) && path[0]) {
        base_dir_ = (fs::path(path) / "RTProtect" / "vault").string();
      } else {
        base_dir_ = (fs::temp_directory_path() / "rtprotect_vault").string();
      }
#else
      base_dir_ = (fs::temp_directory_path() / "rtprotect_vault").string();
#endif
    }
    std::error_code ec;
    fs::create_directories(base_dir_, ec);
  }

  SecretProviderType Type() const override {
    return SecretProviderType::kWindowsDpapiVault;
  }

  const char* Name() const override {
    return "Windows DPAPI Machine/User Vault Provider";
  }

  std::optional<integrity::Ed25519KeyPair> RetrieveSigningKeyPair(
      const std::string& key_identifier,
      std::string* error_out) override {
    fs::path vault_file = fs::path(base_dir_) / (key_identifier + ".vault");
    auto file_bytes = tooling::ReadFile(vault_file.string());
    if (!file_bytes.has_value() || file_bytes->size() < 12) {
      if (error_out) *error_out = "Vault container file missing or too small: " + vault_file.string();
      return std::nullopt;
    }

    const std::uint8_t* p = file_bytes->data();
    std::uint32_t magic = 0;
    std::uint32_t ver = 0;
    std::uint32_t payload_len = 0;
    std::memcpy(&magic, p, 4);
    std::memcpy(&ver, p + 4, 4);
    std::memcpy(&payload_len, p + 8, 4);

    if (magic != kVaultMagic || ver != kVaultVersion || file_bytes->size() < 12 + payload_len) {
      if (error_out) *error_out = "Corrupted or unrecognized vault container format";
      return std::nullopt;
    }

    std::vector<std::uint8_t> decrypted;
#if defined(_WIN32)
    DATA_BLOB in_blob{};
    in_blob.pbData = const_cast<BYTE*>(p + 12);
    in_blob.cbData = static_cast<DWORD>(payload_len);

    DATA_BLOB entropy_blob{};
    entropy_blob.pbData = const_cast<BYTE*>(kVaultEntropy);
    entropy_blob.cbData = sizeof(kVaultEntropy);

    DATA_BLOB out_blob{};
    if (!CryptUnprotectData(&in_blob, nullptr, &entropy_blob, nullptr, nullptr, 0, &out_blob)) {
      if (!CryptUnprotectData(&in_blob, nullptr, &entropy_blob, nullptr, nullptr, CRYPTPROTECT_LOCAL_MACHINE, &out_blob)) {
        if (error_out) *error_out = "CryptUnprotectData failed to decrypt key with OS DPAPI vault";
        return std::nullopt;
      }
    }

    decrypted.assign(out_blob.pbData, out_blob.pbData + out_blob.cbData);
    OPENSSL_cleanse(out_blob.pbData, out_blob.cbData);
    LocalFree(out_blob.pbData);
#else
    if (error_out) *error_out = "DPAPI vault requires Windows environment";
    return std::nullopt;
#endif

    // Decrypted payload format: 32 bytes privkey + 32 bytes pubkey = 64 bytes
    if (decrypted.size() != integrity::kEd25519PrivateKeyLen + integrity::kEd25519PublicKeyLen) {
      OPENSSL_cleanse(decrypted.data(), decrypted.size());
      if (error_out) *error_out = "Decrypted key payload has invalid size (expected 64 bytes)";
      return std::nullopt;
    }

    auto priv = integrity::Ed25519PrivateKey::FromBytes(decrypted.data(), integrity::kEd25519PrivateKeyLen);
    integrity::Ed25519PublicKey pub{};
    std::memcpy(pub.data(), decrypted.data() + integrity::kEd25519PrivateKeyLen, integrity::kEd25519PublicKeyLen);
    OPENSSL_cleanse(decrypted.data(), decrypted.size());

    if (!priv.has_value()) {
      if (error_out) *error_out = "Malformed private key bytes in vault";
      return std::nullopt;
    }

    if (!VerifyKeyPairCorrespondence(*priv, pub)) {
      if (error_out) *error_out = "Cryptographic integrity failure: stored public key does not match private key";
      return std::nullopt;
    }

    return integrity::Ed25519KeyPair{std::move(*priv), pub};
  }

  bool StoreSigningKeyPair(
      const std::string& key_identifier,
      const integrity::Ed25519KeyPair& key_pair,
      std::string* error_out) override {
    if (!VerifyKeyPairCorrespondence(key_pair.private_key, key_pair.public_key)) {
      if (error_out) *error_out = "Cannot store mismatched key pair";
      return false;
    }

    std::vector<std::uint8_t> raw_payload(64);
    std::memcpy(raw_payload.data(), key_pair.private_key.data(), 32);
    std::memcpy(raw_payload.data() + 32, key_pair.public_key.data(), 32);

    std::vector<std::uint8_t> encrypted;
#if defined(_WIN32)
    DATA_BLOB in_blob{};
    in_blob.pbData = raw_payload.data();
    in_blob.cbData = static_cast<DWORD>(raw_payload.size());

    DATA_BLOB entropy_blob{};
    entropy_blob.pbData = const_cast<BYTE*>(kVaultEntropy);
    entropy_blob.cbData = sizeof(kVaultEntropy);

    DATA_BLOB out_blob{};
    // Prefer machine scope if available so service can run under LOCAL_SYSTEM or service account
    if (!CryptProtectData(&in_blob, L"RTProtect Signing Key", &entropy_blob, nullptr, nullptr, CRYPTPROTECT_LOCAL_MACHINE, &out_blob)) {
      if (!CryptProtectData(&in_blob, L"RTProtect Signing Key", &entropy_blob, nullptr, nullptr, 0, &out_blob)) {
        OPENSSL_cleanse(raw_payload.data(), raw_payload.size());
        if (error_out) *error_out = "CryptProtectData failed to encrypt key with OS DPAPI";
        return false;
      }
    }

    encrypted.assign(out_blob.pbData, out_blob.pbData + out_blob.cbData);
    LocalFree(out_blob.pbData);
#else
    OPENSSL_cleanse(raw_payload.data(), raw_payload.size());
    if (error_out) *error_out = "DPAPI vault requires Windows environment";
    return false;
#endif

    OPENSSL_cleanse(raw_payload.data(), raw_payload.size());

    std::vector<std::uint8_t> container(12 + encrypted.size());
    std::uint32_t magic = kVaultMagic;
    std::uint32_t ver = kVaultVersion;
    std::uint32_t payload_len = static_cast<std::uint32_t>(encrypted.size());
    std::memcpy(container.data(), &magic, 4);
    std::memcpy(container.data() + 4, &ver, 4);
    std::memcpy(container.data() + 8, &payload_len, 4);
    std::memcpy(container.data() + 12, encrypted.data(), encrypted.size());

    fs::path vault_file = fs::path(base_dir_) / (key_identifier + ".vault");
    if (!tooling::WriteSecretFile(vault_file.string(), container.data(), container.size())) {
      if (error_out) *error_out = "Failed to write vault container file: " + vault_file.string();
      return false;
    }

    return true;
  }

  bool DeleteSigningKeyPair(
      const std::string& key_identifier,
      std::string* error_out) override {
    fs::path vault_file = fs::path(base_dir_) / (key_identifier + ".vault");
    (void)error_out;
    std::error_code ec;
    if (fs::exists(vault_file)) {
      fs::remove(vault_file, ec);
      if (ec) {
        if (error_out) *error_out = "Failed to remove vault file: " + ec.message();
        return false;
      }
    }
    return true;
  }

 private:
  std::string base_dir_;
};

// -----------------------------------------------------------------------------
// Environment Secret Provider (Cloud KMS / Secret Manager Injection)
// -----------------------------------------------------------------------------
class EnvironmentSecretProvider : public IServerSecretProvider {
 public:
  SecretProviderType Type() const override {
    return SecretProviderType::kEnvironmentVault;
  }

  const char* Name() const override {
    return "Cloud Environment Injection Secret Provider";
  }

  std::optional<integrity::Ed25519KeyPair> RetrieveSigningKeyPair(
      const std::string& key_identifier,
      std::string* error_out) override {
    std::string env_name = key_identifier;
    if (env_name.empty()) env_name = "RTPROTECT_SIGNING_KEY";

    const char* val = std::getenv(env_name.c_str());
    if (!val || std::strlen(val) == 0) {
      if (error_out) *error_out = "Environment variable not found or empty: " + env_name;
      return std::nullopt;
    }

    std::string raw_hex(val);
    std::vector<std::uint8_t> key_bytes;

    if (raw_hex.size() == 64) {
      // 32-byte private key hex: calculate public key via Ed25519 derive
      key_bytes.resize(32);
      if (!HexToBytes(raw_hex, key_bytes.data(), 32)) {
        if (error_out) *error_out = "Invalid hex formatting in environment variable: " + env_name;
        return std::nullopt;
      }
      auto priv = integrity::Ed25519PrivateKey::FromBytes(key_bytes.data(), 32);
      OPENSSL_cleanse(key_bytes.data(), key_bytes.size());
      if (!priv.has_value()) {
        if (error_out) *error_out = "Malformed Ed25519 private key from environment";
        return std::nullopt;
      }

      // Look for optional companion public key env var
      std::string pub_env = env_name + "_PUB";
      const char* pub_val = std::getenv(pub_env.c_str());
      integrity::Ed25519PublicKey pub{};
      if (pub_val && std::strlen(pub_val) == 64) {
        HexToBytes(pub_val, pub.data(), 32);
        if (!VerifyKeyPairCorrespondence(*priv, pub)) {
          if (error_out) *error_out = "Public key in " + pub_env + " does not match private key in " + env_name;
          return std::nullopt;
        }
      } else {
        if (error_out) *error_out = "Environment variable requires full 64-byte keypair (128 hex chars) or companion " + pub_env;
        return std::nullopt;
      }
      return integrity::Ed25519KeyPair{std::move(*priv), pub};
    } else if (raw_hex.size() == 128) {
      // 64-byte hex (32 bytes private + 32 bytes public)
      key_bytes.resize(64);
      if (!HexToBytes(raw_hex, key_bytes.data(), 64)) {
        if (error_out) *error_out = "Invalid hex formatting in environment variable: " + env_name;
        return std::nullopt;
      }
      auto priv = integrity::Ed25519PrivateKey::FromBytes(key_bytes.data(), 32);
      integrity::Ed25519PublicKey pub{};
      std::memcpy(pub.data(), key_bytes.data() + 32, 32);
      OPENSSL_cleanse(key_bytes.data(), key_bytes.size());

      if (!priv.has_value()) {
        if (error_out) *error_out = "Malformed Ed25519 private key from environment";
        return std::nullopt;
      }
      if (!VerifyKeyPairCorrespondence(*priv, pub)) {
        if (error_out) *error_out = "Cryptographic integrity check failed: environment public key does not match private key";
        return std::nullopt;
      }
      return integrity::Ed25519KeyPair{std::move(*priv), pub};
    } else {
      if (error_out) *error_out = "Environment variable " + env_name + " must be 128 hex characters (32B private + 32B public)";
      return std::nullopt;
    }
  }

  bool StoreSigningKeyPair(
      const std::string&,
      const integrity::Ed25519KeyPair&,
      std::string* error_out) override {
    if (error_out) *error_out = "Environment secret provider is read-only at runtime; inject variables via orchestrator / secrets manager";
    return false;
  }

  bool DeleteSigningKeyPair(const std::string&, std::string* error_out) override {
    if (error_out) *error_out = "Environment secret provider does not support runtime deletion";
    return false;
  }
};

// -----------------------------------------------------------------------------
// Guarded File Secret Provider
// -----------------------------------------------------------------------------
class GuardedFileSecretProvider : public IServerSecretProvider {
 public:
  SecretProviderType Type() const override {
    return SecretProviderType::kGuardedFile;
  }

  const char* Name() const override {
    return "Guarded File Secret Provider";
  }

  std::optional<integrity::Ed25519KeyPair> RetrieveSigningKeyPair(
      const std::string& key_identifier,
      std::string* error_out) override {
    fs::path priv_path(key_identifier);
    auto kbytes = tooling::ReadFile(priv_path.string());
    if (!kbytes.has_value() || kbytes->size() != integrity::kEd25519PrivateKeyLen) {
      if (error_out) *error_out = "Unable to read 32-byte Ed25519 private key from " + priv_path.string();
      return std::nullopt;
    }
    auto priv = integrity::Ed25519PrivateKey::FromBytes(kbytes->data(), kbytes->size());
    OPENSSL_cleanse(kbytes->data(), kbytes->size());

    if (!priv.has_value()) {
      if (error_out) *error_out = "Invalid Ed25519 private key bytes";
      return std::nullopt;
    }

    std::string pub_path_str = priv_path.string();
    if (pub_path_str.size() >= 5 && pub_path_str.substr(pub_path_str.size() - 5) == ".priv") {
      pub_path_str = pub_path_str.substr(0, pub_path_str.size() - 5) + ".pub";
    } else {
      pub_path_str += ".pub";
    }

    auto pbytes = tooling::ReadFile(pub_path_str);
    if (!pbytes.has_value() || pbytes->size() != integrity::kEd25519PublicKeyLen) {
      if (error_out) *error_out = "Matching public key file " + pub_path_str + " missing or invalid size";
      return std::nullopt;
    }

    integrity::Ed25519PublicKey pub{};
    std::memcpy(pub.data(), pbytes->data(), integrity::kEd25519PublicKeyLen);

    if (!VerifyKeyPairCorrespondence(*priv, pub)) {
      if (error_out) *error_out = "Public key in " + pub_path_str + " does not match private key in " + priv_path.string();
      return std::nullopt;
    }

    return integrity::Ed25519KeyPair{std::move(*priv), pub};
  }

  bool StoreSigningKeyPair(
      const std::string& key_identifier,
      const integrity::Ed25519KeyPair& key_pair,
      std::string* error_out) override {
    if (!VerifyKeyPairCorrespondence(key_pair.private_key, key_pair.public_key)) {
      if (error_out) *error_out = "Key pair correspondence failure";
      return false;
    }
    fs::path priv_path(key_identifier);
    if (!tooling::WriteSecretFile(priv_path.string(), key_pair.private_key.data(), key_pair.private_key.size())) {
      if (error_out) *error_out = "Failed to write guarded private key: " + priv_path.string();
      return false;
    }
    std::string pub_path = priv_path.string();
    if (pub_path.size() >= 5 && pub_path.substr(pub_path.size() - 5) == ".priv") {
      pub_path = pub_path.substr(0, pub_path.size() - 5) + ".pub";
    } else {
      pub_path += ".pub";
    }
    if (!tooling::WriteFile(pub_path, key_pair.public_key.data(), key_pair.public_key.size())) {
      if (error_out) *error_out = "Failed to write public key: " + pub_path;
      return false;
    }
    return true;
  }

  bool DeleteSigningKeyPair(const std::string& key_identifier, std::string* error_out) override {
    (void)error_out;
    fs::path priv_path(key_identifier);
    std::string pub_path = priv_path.string();
    if (pub_path.size() >= 5 && pub_path.substr(pub_path.size() - 5) == ".priv") {
      pub_path = pub_path.substr(0, pub_path.size() - 5) + ".pub";
    } else {
      pub_path += ".pub";
    }
    std::error_code ec;
    fs::remove(priv_path, ec);
    fs::remove(pub_path, ec);
    return true;
  }
};

}  // namespace

const char* ToString(SecretProviderType type) {
  switch (type) {
    case SecretProviderType::kWindowsDpapiVault: return "dpapi";
    case SecretProviderType::kEnvironmentVault:  return "env";
    case SecretProviderType::kGuardedFile:       return "file";
  }
  return "unknown";
}

std::optional<SecretProviderType> ParseSecretProviderType(const std::string& str) {
  if (str == "dpapi" || str == "cng" || str == "windows") return SecretProviderType::kWindowsDpapiVault;
  if (str == "env" || str == "environment" || str == "cloud") return SecretProviderType::kEnvironmentVault;
  if (str == "file" || str == "disk") return SecretProviderType::kGuardedFile;
  return std::nullopt;
}

std::unique_ptr<IServerSecretProvider> CreateSecretProvider(
    SecretProviderType type,
    const std::string& vault_storage_dir) {
  switch (type) {
    case SecretProviderType::kWindowsDpapiVault:
      return std::make_unique<WindowsDpapiVaultProvider>(vault_storage_dir);
    case SecretProviderType::kEnvironmentVault:
      return std::make_unique<EnvironmentSecretProvider>();
    case SecretProviderType::kGuardedFile:
      return std::make_unique<GuardedFileSecretProvider>();
  }
  return nullptr;
}

bool ProvisionSigningKeyInVault(
    IServerSecretProvider& provider,
    const std::string& key_identifier,
    const std::string& export_pubkey_path,
    integrity::Ed25519PublicKey* out_pubkey,
    std::string* error_out) {
  auto kp = integrity::GenerateEd25519KeyPair();
  if (!kp.has_value()) {
    if (error_out) *error_out = "Cryptographic RNG failure generating Ed25519 key pair";
    return false;
  }

  if (!provider.StoreSigningKeyPair(key_identifier, *kp, error_out)) {
    return false;
  }

  if (!export_pubkey_path.empty()) {
    if (!tooling::WriteFile(export_pubkey_path, kp->public_key.data(), kp->public_key.size())) {
      if (error_out) *error_out = "Failed to export public verification key to " + export_pubkey_path;
      return false;
    }
  }

  if (out_pubkey) {
    *out_pubkey = kp->public_key;
  }

  return true;
}

}  // namespace rtprotect::licensing
