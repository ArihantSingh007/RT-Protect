// licensing/activation_service.h
//
// Vendor-side online activation authority business logic.
// Implements /activate, /renew, and /deactivate operations with seat enforcement,
// ephemeral transport encryption, and anti-replay nonce tracking.

#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "crypto/aead.h"
#include "integrity/keys.h"
#include "licensing/activation.h"
#include "licensing/activation_database.h"
#include "licensing/countermeasure_config.h"
#include "licensing/rate_limiter.h"

namespace rtprotect::licensing {

struct ActivateRequest {
  std::string license_key;
  std::string device_fingerprint;
  std::string product_id;
  std::string client_version = "1.0.0";
  std::uint64_t client_timestamp = 0;
  std::array<std::uint8_t, 32> client_nonce{};
  std::string client_ip = "127.0.0.1";
  std::string activation_credential; // Secret activation secret (separated from public license ID)

  ActivateRequest() = default;
  ActivateRequest(std::string lk, std::string df, std::string pid, std::string ver = "1.0.0",
                  std::uint64_t ts = 0, std::array<std::uint8_t, 32> nonce = {},
                  std::string ip = "127.0.0.1", std::string cred = "")
      : license_key(std::move(lk)), device_fingerprint(std::move(df)), product_id(std::move(pid)),
        client_version(std::move(ver)), client_timestamp(ts), client_nonce(nonce),
        client_ip(std::move(ip)), activation_credential(std::move(cred)) {}
};

struct ActivateResponse {
  ActivationStatus status = ActivationStatus::kMalformed;
  std::string error_message;
  std::array<std::uint8_t, 32> server_nonce{};
  std::string encrypted_token_hex;
  std::string countermeasure_config_hex; // Optional serialized/signed countermeasure update
  std::optional<ActivationToken> token; // Decrypted token for direct in-process callers
};

struct RenewRequest {
  std::string token_hex; // Serialized ActivationToken in hex
  std::string device_fingerprint;
  std::array<std::uint8_t, 32> client_nonce{};
  std::string client_ip = "127.0.0.1";
};

struct RenewResponse {
  ActivationStatus status = ActivationStatus::kMalformed;
  std::string error_message;
  std::array<std::uint8_t, 32> server_nonce{};
  std::string encrypted_token_hex;
  std::string countermeasure_config_hex; // Optional serialized/signed countermeasure update
  std::optional<ActivationToken> token;
};

struct DeactivateRequest {
  std::string token_hex;
  std::string device_fingerprint;
  std::string client_ip = "127.0.0.1";
};

struct DeactivateResponse {
  bool success = false;
  std::string error_message;
};

class ActivationService {
 public:
  ActivationService(ActivationDatabase& db,
                    integrity::Ed25519PrivateKey signing_key,
                    const integrity::Ed25519PublicKey& verification_key);

  // In-process business logic
  ActivateResponse ProcessActivate(const ActivateRequest& req, std::uint64_t current_time = 0, bool check_rate_limit = true);
  ActivateResponse ProcessOfflineGrant(const ActivateRequest& req, std::uint32_t offline_days = 14, std::uint64_t current_time = 0, bool check_rate_limit = true);
  RenewResponse ProcessRenew(const RenewRequest& req, std::uint64_t current_time = 0, bool check_rate_limit = true);
  DeactivateResponse ProcessDeactivate(const DeactivateRequest& req, std::uint64_t current_time = 0);

  // JSON REST handlers (for HTTP daemon)
  std::string HandleActivateJson(const std::string& json_body,
                                 std::uint64_t current_time = 0,
                                 const std::string& client_ip = "127.0.0.1");
  std::string HandleOfflineGrantJson(const std::string& json_body,
                                     std::uint64_t current_time = 0,
                                     const std::string& client_ip = "127.0.0.1");
  std::string HandleRenewJson(const std::string& json_body,
                              std::uint64_t current_time = 0,
                              const std::string& client_ip = "127.0.0.1");
  std::string HandleDeactivateJson(const std::string& json_body,
                                  std::uint64_t current_time = 0,
                                  const std::string& client_ip = "127.0.0.1");

  // Abuse analytics & operational telemetry (Stage 2)
  double ComputeSeatChurnRisk(const std::string& license_id, std::uint64_t current_time = 0) const;
  std::vector<ActivationEvent> GetRecentEvents(const std::string& license_id = "", std::size_t limit = 100) const;

  // Continuous Response Countermeasure updates
  void SetCountermeasureConfig(const CountermeasureConfig& config) { countermeasure_config_ = config; }
  std::optional<CountermeasureConfig> GetCountermeasureConfig() const { return countermeasure_config_; }

  // Configures whether licenses must have an activation credential verifier (default: false for test/dev, enabled for production)
  void SetRequireActivationCredentials(bool req) { require_activation_credentials_ = req; }
  bool require_activation_credentials() const { return require_activation_credentials_; }

  const integrity::Ed25519PublicKey& public_key() const { return verification_key_; }
  const ActivationDatabase& database() const { return db_; }
  ActivationDatabase& database() { return db_; }
  RateLimiter& license_rate_limiter() { return license_rate_limiter_; }
  const RateLimiter& license_rate_limiter() const { return license_rate_limiter_; }
  RateLimiter& ip_rate_limiter() { return ip_rate_limiter_; }
  const RateLimiter& ip_rate_limiter() const { return ip_rate_limiter_; }

 private:
  ActivationDatabase& db_;
  integrity::Ed25519PrivateKey signing_key_;
  integrity::Ed25519PublicKey verification_key_;
  RateLimiter license_rate_limiter_{1.0, 10.0}; // 1 req/sec, burst 10 requests per license
  RateLimiter ip_rate_limiter_{5.0, 20.0};      // 5 req/sec, burst 20 requests per IP
  bool require_activation_credentials_{false};
  std::optional<CountermeasureConfig> countermeasure_config_;
};

}  // namespace rtprotect::licensing
