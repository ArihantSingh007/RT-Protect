// tests/test_secrets_manager.cpp

#include "licensing/secrets_manager.h"

#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>

#include "integrity/signer.h"
#include "integrity/verifier.h"
#include "tests/micro_test.h"

using namespace rtprotect::licensing;
namespace fs = std::filesystem;

namespace {

std::string MakeTempDir(const std::string& prefix) {
  auto ts = std::chrono::high_resolution_clock::now().time_since_epoch().count();
  fs::path p = fs::temp_directory_path() / (prefix + "_" + std::to_string(ts));
  fs::create_directories(p);
  return p.string();
}

std::string BytesToHex(const std::uint8_t* data, std::size_t len) {
  std::ostringstream ss;
  for (std::size_t i = 0; i < len; ++i) {
    char h[3];
    std::snprintf(h, sizeof(h), "%02x", data[i]);
    ss << h;
  }
  return ss.str();
}

}  // namespace

MT_TEST(SecretsManager_ParseProviderType_RejectsCloudAlias) {
  MT_CHECK(ParseSecretProviderType("dpapi") == SecretProviderType::kWindowsDpapiVault);
  MT_CHECK(ParseSecretProviderType("cng") == SecretProviderType::kWindowsDpapiVault);
  MT_CHECK(ParseSecretProviderType("windows") == SecretProviderType::kWindowsDpapiVault);
  MT_CHECK(ParseSecretProviderType("env") == SecretProviderType::kEnvironmentVault);
  MT_CHECK(ParseSecretProviderType("environment") == SecretProviderType::kEnvironmentVault);
  MT_CHECK(ParseSecretProviderType("file") == SecretProviderType::kGuardedFile);
  MT_CHECK(ParseSecretProviderType("disk") == SecretProviderType::kGuardedFile);

  // Security audit requirement: "cloud" alias must be removed to avoid misleading operators
  MT_CHECK(!ParseSecretProviderType("cloud").has_value());
  MT_CHECK(!ParseSecretProviderType("unknown_provider").has_value());
}

MT_TEST(SecretsManager_WindowsDpapiVault_LifecycleAndTraversalProtection) {
  std::string temp_dir = MakeTempDir("test_dpapi_vault");
  auto provider = CreateSecretProvider(SecretProviderType::kWindowsDpapiVault, temp_dir);
  MT_CHECK(provider != nullptr);

  // 1. Path traversal attacks must be rejected
  std::string err;
  auto kp_bad = provider->RetrieveSigningKeyPair("../traversal_key", &err);
  MT_CHECK(!kp_bad.has_value());
  MT_CHECK(err.find("Invalid key identifier") != std::string::npos);

  auto kp_bad2 = provider->RetrieveSigningKeyPair("subdir/key", &err);
  MT_CHECK(!kp_bad2.has_value());
  MT_CHECK(err.find("Invalid key identifier") != std::string::npos);

  auto kp_bad3 = provider->RetrieveSigningKeyPair("subdir\\key", &err);
  MT_CHECK(!kp_bad3.has_value());
  MT_CHECK(err.find("Invalid key identifier") != std::string::npos);

  std::string long_id(65, 'a');
  auto kp_bad4 = provider->RetrieveSigningKeyPair(long_id, &err);
  MT_CHECK(!kp_bad4.has_value());
  MT_CHECK(err.find("Invalid key identifier") != std::string::npos);

  // 2. Generate and store a valid key pair
  auto gen_kp = rtprotect::integrity::GenerateEd25519KeyPair();
  MT_CHECK(gen_kp.has_value());

  std::string valid_id = "master_sign_key_2026";
  MT_CHECK(provider->StoreSigningKeyPair(valid_id, *gen_kp, &err));

  // Verify file exists on disk
  fs::path vault_file = fs::path(temp_dir) / (valid_id + ".vault");
  MT_CHECK(fs::exists(vault_file));

  // 3. Retrieve and verify cryptographic correspondence
  auto loaded_kp = provider->RetrieveSigningKeyPair(valid_id, &err);
  MT_CHECK(loaded_kp.has_value());
  MT_CHECK(loaded_kp->public_key == gen_kp->public_key);

  // Sign with original, verify with loaded
  std::vector<std::uint8_t> payload = {'v', 'a', 'u', 'l', 't', '_', 't', 'e', 's', 't'};
  auto sig = rtprotect::integrity::SignManifestBytes(payload, loaded_kp->private_key);
  MT_CHECK(sig.has_value());
  MT_CHECK(rtprotect::integrity::VerifyManifestSignature(payload, *sig, loaded_kp->public_key));

  // 4. Delete signing key pair
  MT_CHECK(provider->DeleteSigningKeyPair(valid_id, &err));
  MT_CHECK(!fs::exists(vault_file));

  // Deleting again should fail with descriptive error
  MT_CHECK(!provider->DeleteSigningKeyPair(valid_id, &err));
  MT_CHECK(err.find("does not exist") != std::string::npos);

  // Re-retrieval should fail
  auto reloaded = provider->RetrieveSigningKeyPair(valid_id, &err);
  MT_CHECK(!reloaded.has_value());

  std::error_code ec;
  fs::remove_all(temp_dir, ec);
}

MT_TEST(SecretsManager_GuardedFile_AtomicWritesAndDeletion) {
  std::string temp_dir = MakeTempDir("test_file_vault");
  auto provider = CreateSecretProvider(SecretProviderType::kGuardedFile);
  MT_CHECK(provider != nullptr);

  auto gen_kp = rtprotect::integrity::GenerateEd25519KeyPair();
  MT_CHECK(gen_kp.has_value());

  std::string priv_path = (fs::path(temp_dir) / "server.priv").string();
  std::string pub_path = (fs::path(temp_dir) / "server.pub").string();
  std::string err;

  MT_CHECK(provider->StoreSigningKeyPair(priv_path, *gen_kp, &err));
  MT_CHECK(fs::exists(priv_path));
  MT_CHECK(fs::exists(pub_path));

  // Retrieve and verify
  auto loaded_kp = provider->RetrieveSigningKeyPair(priv_path, &err);
  MT_CHECK(loaded_kp.has_value());
  MT_CHECK(loaded_kp->public_key == gen_kp->public_key);

  // Delete key pair
  MT_CHECK(provider->DeleteSigningKeyPair(priv_path, &err));
  MT_CHECK(!fs::exists(priv_path));
  MT_CHECK(!fs::exists(pub_path));

  // Deleting non-existent key pair reports error
  MT_CHECK(!provider->DeleteSigningKeyPair(priv_path, &err));
  MT_CHECK(err.find("do not exist") != std::string::npos);

  std::error_code ec;
  fs::remove_all(temp_dir, ec);
}

MT_TEST(SecretsManager_EnvironmentVault_ReadOnlyAndValidation) {
  auto provider = CreateSecretProvider(SecretProviderType::kEnvironmentVault);
  MT_CHECK(provider != nullptr);

  auto gen_kp = rtprotect::integrity::GenerateEd25519KeyPair();
  MT_CHECK(gen_kp.has_value());

  std::string priv_hex = BytesToHex(gen_kp->private_key.data(), gen_kp->private_key.size());
  std::string pub_hex = BytesToHex(gen_kp->public_key.data(), gen_kp->public_key.size());
  std::string full_hex = priv_hex + pub_hex; // 128 hex chars

#if defined(_WIN32)
  _putenv_s("RTPROTECT_TEST_KEY_ENV", full_hex.c_str());
#else
  setenv("RTPROTECT_TEST_KEY_ENV", full_hex.c_str(), 1);
#endif

  std::string err;
  auto loaded_kp = provider->RetrieveSigningKeyPair("RTPROTECT_TEST_KEY_ENV", &err);
  MT_CHECK(loaded_kp.has_value());
  MT_CHECK(loaded_kp->public_key == gen_kp->public_key);

  // Environment provider must be read-only at runtime
  MT_CHECK(!provider->StoreSigningKeyPair("RTPROTECT_TEST_KEY_ENV", *gen_kp, &err));
  MT_CHECK(err.find("read-only") != std::string::npos);

  MT_CHECK(!provider->DeleteSigningKeyPair("RTPROTECT_TEST_KEY_ENV", &err));
  MT_CHECK(err.find("does not support runtime deletion") != std::string::npos);

#if defined(_WIN32)
  _putenv_s("RTPROTECT_TEST_KEY_ENV", "");
#else
  unsetenv("RTPROTECT_TEST_KEY_ENV");
#endif
}

MT_MAIN()
