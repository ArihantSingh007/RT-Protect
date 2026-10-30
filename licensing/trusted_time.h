// licensing/trusted_time.h
//
// Trusted time verification and anti-clock-tampering engine.
// Combines monotonic steady clocks, persistent server timestamp anchoring,
// and cross-validation against HTTP Date headers to prevent users from
// rolling back local system clocks to bypass token expiration windows.

#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

#include "licensing/activation.h"

namespace rtprotect::licensing {

enum class TimeValidationResult {
  kValid,
  kInGracePeriod,
  kExpired,
  kClockTampered,
  kNotYetValid
};

struct TrustedTimeState {
  std::uint64_t last_known_server_time = 0;
  std::uint64_t last_known_wall_time = 0;
  std::uint64_t accumulated_monotonic_seconds = 0;
  std::uint64_t last_boot_id = 0;
  std::uint64_t last_session_uptime_seconds = 0;
  bool tamper_detected = false;
};

class TrustedTime {
 public:
  // Allowed forward/backward clock drift tolerance (5 minutes for NTP sync differences)
  static constexpr std::uint64_t kAllowedSkewSeconds = 300;

  // Maximum allowed drift between wall clock and uptime within the same continuous boot session (15 seconds)
  static constexpr std::uint64_t kAllowedDriftSeconds = 15;

  // Large backward clock inconsistency threshold (1 hour) that triggers immediate tamper detection
  static constexpr std::uint64_t kLargeInconsistencySeconds = 3600;

  // Test time providers to allow deterministic testing of reboots, steady clock, and wall clock
  using WallTimeProvider = std::uint64_t (*)();
  using UptimeProvider = std::uint64_t (*)();
  using BootIdProvider = std::uint64_t (*)();

  static void SetTimeProvidersForTesting(WallTimeProvider wall_fn,
                                        UptimeProvider uptime_fn,
                                        BootIdProvider boot_id_fn);
  static void ResetTimeProvidersForTesting();
  static void ResetProcessBaselineForTesting(std::uint64_t start_wall, std::uint64_t start_steady);
  static void InitializeProcessBaseline();

  // Queries current boot identity and uptime (uses test providers if registered)
  static std::uint64_t GetCurrentBootId();
  static std::uint64_t GetCurrentSystemUptime();

  // Anchors verified server timestamp from online token issuance/renewal
  static bool AnchorServerTime(const std::string& product_id, std::uint64_t server_timestamp);

  // Evaluates current time against persistent anchors and monotonic clocks.
  // Returns estimated trusted unix timestamp in seconds, or std::nullopt if clock is rolled back/tampered.
  static std::optional<std::uint64_t> GetTrustedTime(const std::string& product_id);

  // Validates an activation token against trusted time
  static TimeValidationResult ValidateToken(const std::string& product_id,
                                           const ActivationToken& token,
                                           bool allow_grace = true);

  // Parses RFC 2616 / 7231 Date header format (e.g. "Wed, 21 Oct 2026 12:00:00 GMT") into Unix timestamp
  static std::optional<std::uint64_t> ParseHttpDate(const std::string& http_date_str);

  // Resets local time state for product (used in testing)
  static void ResetTimeStateForTesting(const std::string& product_id);
};

}  // namespace rtprotect::licensing
