// licensing/activation_database.h
//
// Persistent database layer for RTProtect Activation Authority.
// Stores licenses, active device sessions, and anti-replay nonces.

#pragma once

#include <array>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace rtprotect::licensing {

enum class LicenseRecordStatus {
  kActive = 0,
  kRevoked,
  kRefunded
};

const char* ToString(LicenseRecordStatus status);
std::optional<LicenseRecordStatus> ParseLicenseRecordStatus(const std::string& s);

enum class ActivationEventType {
  kActivationSuccess = 0,
  kActivationFailed,
  kSeatLimitExceeded,
  kRenewalSuccess,
  kRenewalFailed,
  kDeactivation,
  kRateLimited,
  kReplayBlocked
};

const char* ToString(ActivationEventType type);
std::optional<ActivationEventType> ParseActivationEventType(const std::string& s);

struct ActivationEvent {
  std::uint64_t timestamp = 0;
  ActivationEventType type = ActivationEventType::kActivationSuccess;
  std::string license_id;
  std::string device_fingerprint;
  std::string ip_address = "127.0.0.1";
  std::string details;
};

struct LicenseRecord {
  std::string license_id;
  std::string product_id;
  LicenseRecordStatus status = LicenseRecordStatus::kActive;
  std::uint32_t max_seats = 1;
  std::array<std::uint8_t, 32> vm_root{};
  std::uint64_t created_at = 0;
};

struct ActivationRecord {
  std::string license_id;
  std::string device_fingerprint;
  std::uint64_t first_seen = 0;
  std::uint64_t last_seen = 0;
  std::uint64_t sequence_number = 1;
};

struct SeatReservationResult {
  bool success = false;
  bool is_new_seat = false;
  std::uint64_t sequence_number = 1;
  std::uint64_t first_seen = 0;
  std::string error;
};

class ActivationDatabase {
 public:
  ActivationDatabase() = default;
  explicit ActivationDatabase(const std::string& db_path);

  // Opens and loads database from file; creates empty database if file doesn't exist
  bool Open(const std::string& db_path);

  // Saves current database state atomically to disk
  bool Save(const std::string& db_path = "");

  // License management
  bool RegisterLicense(const LicenseRecord& record);
  std::optional<LicenseRecord> GetLicense(const std::string& license_id) const;
  bool UpdateLicenseStatus(const std::string& license_id, LicenseRecordStatus status);

  // Activation & seat tracking
  std::size_t GetActiveSeatCount(const std::string& license_id) const;
  std::vector<ActivationRecord> GetActivations(const std::string& license_id) const;
  std::optional<ActivationRecord> GetActivation(const std::string& license_id,
                                                const std::string& device_fingerprint) const;
  bool RecordActivation(const ActivationRecord& record);
  bool RemoveActivation(const std::string& license_id, const std::string& device_fingerprint);

  // Atomic seat reservation and lifecycle lease management
  SeatReservationResult ReserveSeatAtomic(const std::string& license_id,
                                          const std::string& device_fingerprint,
                                          std::uint32_t max_seats,
                                          std::uint64_t current_time,
                                          std::uint64_t stale_timeout_seconds = 30 * 86400);

  // Anti-replay nonce tracking
  bool IsNonceUsed(const std::string& nonce_hex) const;
  bool RecordNonce(const std::string& nonce_hex, std::uint64_t expires_at);
  bool ConsumeNonceIfUnused(const std::string& nonce_hex, std::uint64_t expires_at, std::uint64_t current_time = 0);
  void PruneExpiredNonces(std::uint64_t current_time);

  // Structured audit event logging & abuse analytics (Stage 2)
  bool RecordEvent(const ActivationEvent& event);
  std::vector<ActivationEvent> GetRecentEvents(const std::string& license_id = "", std::size_t limit = 100) const;
  double ComputeSeatChurnRisk(const std::string& license_id,
                              std::uint64_t current_time,
                              std::uint64_t window_seconds = 7 * 86400) const;

  // Clear all data (for testing)
  void Clear();

  const std::string& db_path() const { return db_path_; }

 private:
  bool SaveLocked() const;

  mutable std::mutex mutex_;
  std::string db_path_;
  std::unordered_map<std::string, LicenseRecord> licenses_;
  std::unordered_map<std::string, std::vector<ActivationRecord>> activations_; // license_id -> activations
  std::unordered_map<std::string, std::uint64_t> used_nonces_;                 // nonce_hex -> expires_at
  std::vector<ActivationEvent> events_;                                        // audit event log
};

}  // namespace rtprotect::licensing
