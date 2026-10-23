// licensing/secrets_manager.h
//
// Enterprise Server-Side Secrets & Key Management Provider for RTProtect Activation Authority.
// Ensures that server-side asymmetric signing keys (Ed25519) and administrative credentials
// reside strictly within hardware or operating system secret stores (Windows DPAPI / CNG,
// Cloud Secret Managers via injected runtime environments, or HSMs) rather than unencrypted
// on-disk configuration files.

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "integrity/keys.h"

namespace rtprotect::licensing {

enum class SecretProviderType {
  kWindowsDpapiVault = 0, // Encrypted under OS machine/logon keys via CryptProtectData
  kEnvironmentVault  = 1, // Secure runtime injection (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault)
  kGuardedFile       = 2  // File storage with explicit access permissions and integrity verification
};

const char* ToString(SecretProviderType type);
std::optional<SecretProviderType> ParseSecretProviderType(const std::string& str);

class IServerSecretProvider {
 public:
  virtual ~IServerSecretProvider() = default;

  virtual SecretProviderType Type() const = 0;
  virtual const char* Name() const = 0;

  // Retrieves an Ed25519 signing key pair from the secret vault.
  // Reconstructs and cryptographically validates that the public key corresponds to the private key.
  virtual std::optional<integrity::Ed25519KeyPair> RetrieveSigningKeyPair(
      const std::string& key_identifier,
      std::string* error_out = nullptr) = 0;

  // Stores an Ed25519 signing key pair into the vault, encrypted at rest.
  virtual bool StoreSigningKeyPair(
      const std::string& key_identifier,
      const integrity::Ed25519KeyPair& key_pair,
      std::string* error_out = nullptr) = 0;

  // Deletes a key from the vault.
  virtual bool DeleteSigningKeyPair(
      const std::string& key_identifier,
      std::string* error_out = nullptr) = 0;
};

// Factory to instantiate a secret provider by type.
std::unique_ptr<IServerSecretProvider> CreateSecretProvider(
    SecretProviderType type,
    const std::string& vault_storage_dir = "");

// Helper to provision a new Ed25519 key pair directly into the vault.
// The private key is encrypted and stored in the vault, while ONLY the 32-byte public key
// is exported to export_pubkey_path, ensuring the private key never touches disk in plaintext.
bool ProvisionSigningKeyInVault(
    IServerSecretProvider& provider,
    const std::string& key_identifier,
    const std::string& export_pubkey_path,
    integrity::Ed25519PublicKey* out_pubkey = nullptr,
    std::string* error_out = nullptr);

}  // namespace rtprotect::licensing
