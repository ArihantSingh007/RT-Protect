// licensing/activation_server.h
//
// Vendor-side activation authority: ticket issuance, cryptographic signing,
// concurrency cap enforcement, and license/ticket revocation lists.
//
// NEVER linked into client-distributed applications.

#pragma once

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "integrity/keys.h"
#include "licensing/activation.h"

namespace rtprotect::licensing {

struct ActiveSession {
  std::string ticket_id;
  std::string hardware_id;
  std::uint64_t issued_at = 0;
  std::uint64_t expires_at = 0;
};

struct RegisteredLicensePolicy {
  std::string license_id;
  std::uint32_t max_concurrency = 1;
};

class ActivationManager {
 public:
  ActivationManager() = default;

  // Registers a license with an allowed concurrency limit (defaults to 1 seat)
  void RegisterLicense(const std::string& license_id, std::uint32_t max_concurrency = 1);

  // Revocation management
  bool RevokeLicense(const std::string& license_id, const std::string& reason = "Revoked by vendor");
  bool RevokeTicket(const std::string& ticket_id, const std::string& reason = "Revoked by vendor");
  bool UnrevokeLicense(const std::string& license_id);
  bool UnrevokeTicket(const std::string& ticket_id);

  bool IsLicenseRevoked(const std::string& license_id) const;
  bool IsTicketRevoked(const std::string& ticket_id) const;

  struct IssueTicketResult {
    ActivationStatus status;
    std::optional<ActivationTicket> ticket;
    std::string error_message;
  };

  // Issues and cryptographically signs a short-lived activation ticket
  IssueTicketResult IssueTicket(const ActivationRequest& req,
                                const integrity::Ed25519PrivateKey& privkey,
                                std::uint64_t validity_seconds = 86400,
                                std::uint64_t current_time = 0);

  // Concurrency tracking and cleanup
  std::size_t GetActiveDeviceCount(const std::string& license_id, std::uint64_t current_time = 0) const;
  void CleanupExpiredSessions(std::uint64_t current_time = 0);

  // JSON export / import for persistence
  std::string ExportRevocationListJson() const;
  bool ImportRevocationListJson(const std::string& json_str);

 private:
  mutable std::mutex mutex_;
  std::unordered_map<std::string, RegisteredLicensePolicy> licenses_;
  std::unordered_map<std::string, std::string> revoked_licenses_; // license_id -> reason
  std::unordered_map<std::string, std::string> revoked_tickets_;  // ticket_id -> reason
  std::unordered_map<std::string, std::vector<ActiveSession>> active_sessions_; // license_id -> sessions
};

// Signs an activation ticket with the vendor Ed25519 private key
bool SignActivationTicket(ActivationTicket& ticket, const integrity::Ed25519PrivateKey& privkey);

}  // namespace rtprotect::licensing
