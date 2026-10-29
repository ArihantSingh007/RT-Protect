// tests/test_trusted_time.cpp

#include "licensing/trusted_time.h"
#include "licensing/activation.h"
#include "licensing/secure_storage.h"
#include "tests/micro_test.h"

#include <chrono>

using namespace rtprotect::licensing;

namespace {

std::uint64_t GetCurrentEpoch() {
  auto now = std::chrono::system_clock::now().time_since_epoch();
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(now).count());
}

}  // namespace

MT_TEST(TrustedTime_ParseHttpDate_StandardFormats) {
  // RFC 7231 format
  auto t1 = TrustedTime::ParseHttpDate("Wed, 21 Oct 2026 12:00:00 GMT");
  MT_CHECK(t1.has_value());
  MT_CHECK(*t1 > 1700000000);

  // Without weekday prefix
  auto t2 = TrustedTime::ParseHttpDate("21 Oct 2026 12:00:00 GMT");
  MT_CHECK(t2.has_value());
  MT_CHECK(*t1 == *t2);

  // Invalid date string
  auto t3 = TrustedTime::ParseHttpDate("Not a valid date");
  MT_CHECK(!t3.has_value());
}

MT_TEST(TrustedTime_AnchorServerTime_And_NormalValidation) {
  std::string prod = "test_time_prod_valid";
  TrustedTime::ResetTimeStateForTesting(prod);

  std::uint64_t now = GetCurrentEpoch();
  MT_CHECK(TrustedTime::AnchorServerTime(prod, now));

  auto trusted = TrustedTime::GetTrustedTime(prod);
  MT_CHECK(trusted.has_value());
  MT_CHECK(*trusted >= now);

  ActivationToken tok;
  tok.license_id = "lic-time-001";
  tok.issued_at = now - 60;
  tok.expires_at = now + 86400 * 14;              // 14 days
  tok.grace_expires_at = tok.expires_at + 86400 * 3; // 3 days grace

  auto res = TrustedTime::ValidateToken(prod, tok);
  MT_CHECK(res == TimeValidationResult::kValid);

  TrustedTime::ResetTimeStateForTesting(prod);
}

MT_TEST(TrustedTime_DetectsClockRollback_BehindServerAnchor) {
  std::string prod = "test_time_prod_rollback";
  TrustedTime::ResetTimeStateForTesting(prod);

  std::uint64_t now = GetCurrentEpoch();

  // Anchor server time far into the future (simulating a future server anchor or clock set back 1 year)
  std::uint64_t future_server_time = now + 365 * 86400;
  MT_CHECK(TrustedTime::AnchorServerTime(prod, future_server_time));

  // Current system clock is now behind the known authenticated server time
  // This must immediately trigger clock tampering detection
  auto trusted = TrustedTime::GetTrustedTime(prod);
  MT_CHECK(!trusted.has_value());

  ActivationToken tok;
  tok.license_id = "lic-time-rollback";
  tok.issued_at = now - 3600;
  tok.expires_at = now + 86400;
  tok.grace_expires_at = tok.expires_at + 86400;

  auto res = TrustedTime::ValidateToken(prod, tok);
  MT_CHECK(res == TimeValidationResult::kClockTampered);

  TrustedTime::ResetTimeStateForTesting(prod);
}

MT_TEST(TrustedTime_HandlesGracePeriod_And_Expiration) {
  std::string prod = "test_time_prod_grace";
  TrustedTime::ResetTimeStateForTesting(prod);

  std::uint64_t now = GetCurrentEpoch();
  MT_CHECK(TrustedTime::AnchorServerTime(prod, now));

  // 1. Token in grace period (expires_at passed, but grace_expires_at not reached)
  ActivationToken grace_tok;
  grace_tok.issued_at = now - 86400 * 15;
  grace_tok.expires_at = now - 3600;          // Expired 1 hour ago
  grace_tok.grace_expires_at = now + 86400;   // Grace valid for 24 more hours

  MT_CHECK(TrustedTime::ValidateToken(prod, grace_tok, true) == TimeValidationResult::kInGracePeriod);
  MT_CHECK(TrustedTime::ValidateToken(prod, grace_tok, false) == TimeValidationResult::kExpired);

  // 2. Token fully expired past grace window
  ActivationToken expired_tok;
  expired_tok.issued_at = now - 86400 * 30;
  expired_tok.expires_at = now - 86400 * 10;
  expired_tok.grace_expires_at = now - 86400 * 5;

  MT_CHECK(TrustedTime::ValidateToken(prod, expired_tok, true) == TimeValidationResult::kExpired);

  // 3. Token issued in future (future postdated)
  ActivationToken future_tok;
  future_tok.issued_at = now + 86400 * 10; // Issued 10 days in future
  future_tok.expires_at = future_tok.issued_at + 86400 * 14;
  future_tok.grace_expires_at = future_tok.expires_at + 86400 * 3;

  MT_CHECK(TrustedTime::ValidateToken(prod, future_tok) == TimeValidationResult::kNotYetValid);

  TrustedTime::ResetTimeStateForTesting(prod);
}

static std::uint64_t s_mock_wall = 1700000000;
static std::uint64_t s_mock_uptime = 100;
static std::uint64_t s_mock_boot_id = 1;

static std::uint64_t MockWall() { return s_mock_wall; }
static std::uint64_t MockUptime() { return s_mock_uptime; }
static std::uint64_t MockBootId() { return s_mock_boot_id; }

MT_TEST(TrustedTime_FreezeAndReboot_Detected) {
  std::string prod = "test_time_prod_freeze";
  TrustedTime::ResetTimeStateForTesting(prod);

  s_mock_wall = 1700000000;
  s_mock_uptime = 10;
  s_mock_boot_id = 101;
  TrustedTime::SetTimeProvidersForTesting(MockWall, MockUptime, MockBootId);

  // Initial anchor at server time 1700000000
  MT_CHECK(TrustedTime::AnchorServerTime(prod, 1700000000));

  // Boot 1: Machine runs for 200s, but wall clock is frozen at 1700000000
  s_mock_uptime = 210;
  auto t1 = TrustedTime::GetTrustedTime(prod);
  MT_CHECK(t1.has_value()); // Within 300s skew tolerance

  // Boot 2: Attacker reboots the machine! (new boot_id, uptime resets to 10s)
  s_mock_boot_id = 102;
  s_mock_uptime = 10;
  auto t2 = TrustedTime::GetTrustedTime(prod);
  MT_CHECK(t2.has_value());

  // Boot 2 runs for another 200s (total active monotonic time = 200 + 200 = 400s > 300s skew)
  // But wall clock is STILL frozen at 1700000000!
  s_mock_uptime = 210;
  auto t3 = TrustedTime::GetTrustedTime(prod);
  // Must catch clock freeze across reboots!
  MT_CHECK(!t3.has_value());

  ActivationToken tok;
  tok.license_id = "lic-freeze";
  tok.issued_at = 1700000000;
  tok.expires_at = 1700086400;
  tok.grace_expires_at = tok.expires_at + 86400;

  auto res = TrustedTime::ValidateToken(prod, tok);
  MT_CHECK(res == TimeValidationResult::kClockTampered);

  TrustedTime::ResetTimeStateForTesting(prod);
}

MT_TEST(TrustedTime_WriteThrottling_AvoidsAmplification) {
  std::string prod = "test_time_prod_throttle";
  TrustedTime::ResetTimeStateForTesting(prod);

  s_mock_wall = 1700000000;
  s_mock_uptime = 10;
  s_mock_boot_id = 201;
  TrustedTime::SetTimeProvidersForTesting(MockWall, MockUptime, MockBootId);

  MT_CHECK(TrustedTime::AnchorServerTime(prod, 1700000000));

  // Multiple rapid queries within 10 seconds
  for (int i = 0; i < 50; ++i) {
    s_mock_wall += 1;
    s_mock_uptime += 1;
    auto t = TrustedTime::GetTrustedTime(prod);
    MT_CHECK(t.has_value());
  }

  TrustedTime::ResetTimeStateForTesting(prod);
}

MT_TEST(TrustedTime_OfflineExpiry_WithClockSkew) {
  std::string prod = "test_time_prod_offline_skew";
  TrustedTime::ResetTimeStateForTesting(prod);

  s_mock_wall = 1700000000;
  s_mock_uptime = 10;
  s_mock_boot_id = 301;
  TrustedTime::SetTimeProvidersForTesting(MockWall, MockUptime, MockBootId);

  MT_CHECK(TrustedTime::AnchorServerTime(prod, 1700000000));

  ActivationToken tok;
  tok.license_id = "lic-offline-skew";
  tok.issued_at = 1700000000;
  tok.expires_at = 1700001000; // Valid for 1000 seconds
  tok.grace_expires_at = 1700001000; // No grace

  // Attacker advances wall clock by only 50s (clock set to 1700000050)
  // But monotonic uptime advanced by 1200s (system was on for 1200s)!
  // Real active progression = 1700000000 + 1200 = 1700001200 > expires_at (1700001000).
  // Therefore, token must expire!
  s_mock_wall = 1700001050; // wall clock kept near expiry
  s_mock_uptime = 1250;     // uptime past expiry
  auto res = TrustedTime::ValidateToken(prod, tok);
  MT_CHECK(res == TimeValidationResult::kExpired);

  TrustedTime::ResetTimeStateForTesting(prod);
}

MT_MAIN()
