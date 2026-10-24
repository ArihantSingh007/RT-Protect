// licensing/countermeasure_config.h
//
// Continuous Response Channel: Cryptographically signed dynamic countermeasure configuration.
// Allows vendors to push updated process blacklists, window titles, driver hashes, and
// risk threshold overrides to live clients during activation/renewal without recompiling or patching binaries.

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "integrity/keys.h"

namespace rtprotect::licensing {

inline constexpr std::uint32_t kCountermeasureConfigMagic = 0x52545043; // 'RTPC'
inline constexpr std::uint32_t kCountermeasureSchemaVersion = 1;

struct CountermeasureConfig {
  std::uint32_t schema_version = kCountermeasureSchemaVersion;
  std::uint64_t sequence_number = 1;      // Monotonic sequence number (anti-rollback)
  std::uint64_t issued_at = 0;            // Unix timestamp seconds
  std::uint64_t expires_at = 0;           // Unix timestamp seconds (0 = perpetual)

  // Dynamic Blacklists
  std::vector<std::string> blacklisted_process_names;
  std::vector<std::uint32_t> blacklisted_process_hashes;
  std::vector<std::string> blacklisted_window_titles;
  std::vector<std::uint32_t> blacklisted_driver_hashes;

  // Dynamic Risk Policy Overrides
  int risk_threshold_restrict = 50;
  int risk_threshold_terminate = 80;
  bool enforce_hardware_breakpoints = true;
  bool enforce_timing_checks = true;
  bool enforce_memory_hooks = true;
  bool enforce_anti_dump = true;

  // Cryptographic Signature
  integrity::Ed25519Signature signature{};
};

// Wire serialization & deserialization
std::vector<std::uint8_t> SerializeCountermeasureConfigForSigning(const CountermeasureConfig& cfg);
std::vector<std::uint8_t> SerializeCountermeasureConfig(const CountermeasureConfig& cfg);
std::optional<CountermeasureConfig> DeserializeCountermeasureConfig(const std::uint8_t* data, std::size_t len);

// Vendor signing & client verification
bool SignCountermeasureConfig(CountermeasureConfig& cfg, const integrity::Ed25519PrivateKey& privkey);
bool VerifyCountermeasureConfigSignature(const CountermeasureConfig& cfg, const integrity::Ed25519PublicKey& pubkey);

// Local persistence in secure token storage
bool SaveCountermeasureConfig(const std::string& product_id, const CountermeasureConfig& cfg);
std::optional<CountermeasureConfig> LoadCountermeasureConfig(const std::string& product_id);

// Dynamic notification hook for anti-tamper runtime decoupled from licensing transport
using CountermeasureUpdateHook = void (*)(const CountermeasureConfig& cfg);
void SetCountermeasureUpdateHook(CountermeasureUpdateHook hook);
void NotifyCountermeasureUpdate(const CountermeasureConfig& cfg);

}  // namespace rtprotect::licensing
