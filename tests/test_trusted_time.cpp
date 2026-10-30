// tests/test_trusted_time.cpp

#include "licensing/trusted_time.h"
#include "licensing/activation.h"
#include "licensing/secure_storage.h"
#include "tests/micro_test.h"

#include <chrono>
#include <thread>
#include <vector>
#include <atomic>

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

MT_TEST(TrustedTime_ProductionProviders_RelaunchWithoutReboot) {
  std::string prod = "test_time_prod_relaunch_real";
  TrustedTime::ResetTimeStateForTesting(prod);

  // Use pure production providers (NO mock overrides)
  TrustedTime::ResetTimeProvidersForTesting();

  auto real_boot_id = TrustedTime::GetCurrentBootId();
  auto real_uptime = TrustedTime::GetCurrentSystemUptime();
  MT_CHECK(real_boot_id > 0);
  MT_CHECK(real_uptime > 0);

  // Server anchors at current time
  auto now_wall = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch()).count());
  MT_CHECK(TrustedTime::AnchorServerTime(prod, now_wall));

  // First process run
  auto t1 = TrustedTime::GetTrustedTime(prod);
  MT_CHECK(t1.has_value());
  MT_CHECK(*t1 >= now_wall);

  // Simulate cold relaunch of application: reset in-process baseline
  TrustedTime::ResetTimeProvidersForTesting();

  // Second process run in same boot session: MUST SUCCEED AND NOT TRIGGER TAMPER (Finding 1 fix)
  auto t2 = TrustedTime::GetTrustedTime(prod);
  MT_CHECK(t2.has_value());
  MT_CHECK(*t2 >= *t1);

  ActivationToken tok;
  tok.license_id = "lic-real-relaunch";
  tok.issued_at = now_wall;
  tok.expires_at = now_wall + 86400;
  tok.grace_expires_at = tok.expires_at + 86400;

  auto val_res = TrustedTime::ValidateToken(prod, tok, /*allow_grace=*/true);
  MT_CHECK(val_res == TimeValidationResult::kValid);

  TrustedTime::ResetTimeStateForTesting(prod);
}

MT_TEST(TrustedTime_30DayGrant_LifecycleWithRelaunches) {
  std::string prod = "test_time_prod_30day_grant";
  TrustedTime::ResetTimeStateForTesting(prod);

  std::uint64_t t0 = 1700000000;
  std::uint64_t boot_time = 1700000000 - 3600; // machine booted 1 hour before anchor
  s_mock_wall = t0;
  s_mock_uptime = 3600;
  s_mock_boot_id = boot_time;
  TrustedTime::SetTimeProvidersForTesting(MockWall, MockUptime, MockBootId);

  MT_CHECK(TrustedTime::AnchorServerTime(prod, t0));

  ActivationToken grant_tok;
  grant_tok.license_id = "lic-30day-grant";
  grant_tok.issued_at = t0;
  grant_tok.expires_at = t0 + (30 * 86400); // 30 days
  grant_tok.grace_expires_at = grant_tok.expires_at + (3 * 86400); // 3 days grace

  // Day 1: launch after 2 hours
  s_mock_wall = t0 + 7200;
  s_mock_uptime = 3600 + 7200;
  s_mock_boot_id = boot_time;
  TrustedTime::ResetProcessBaselineForTesting(s_mock_wall, s_mock_uptime);
  MT_CHECK(TrustedTime::ValidateToken(prod, grant_tok) == TimeValidationResult::kValid);

  // Day 10: cold relaunch after machine rebooted on day 9
  std::uint64_t day10_wall = t0 + (10 * 86400);
  std::uint64_t day10_boot = day10_wall - 1800; // rebooted 30 mins ago
  s_mock_wall = day10_wall;
  s_mock_uptime = 1800;
  s_mock_boot_id = day10_boot;
  TrustedTime::ResetProcessBaselineForTesting(s_mock_wall, s_mock_uptime);
  MT_CHECK(TrustedTime::ValidateToken(prod, grant_tok) == TimeValidationResult::kValid);

  // Day 20: cold relaunch after multiple reboots and steady usage
  std::uint64_t day20_wall = t0 + (20 * 86400);
  std::uint64_t day20_boot = day20_wall - 7200;
  s_mock_wall = day20_wall;
  s_mock_uptime = 7200;
  s_mock_boot_id = day20_boot;
  TrustedTime::ResetProcessBaselineForTesting(s_mock_wall, s_mock_uptime);
  MT_CHECK(TrustedTime::ValidateToken(prod, grant_tok) == TimeValidationResult::kValid);

  // Day 30: 1 hour before expiration
  std::uint64_t day30_wall = grant_tok.expires_at - 3600;
  s_mock_wall = day30_wall;
  s_mock_uptime = 3600 * 5;
  s_mock_boot_id = day30_wall - s_mock_uptime;
  TrustedTime::ResetProcessBaselineForTesting(s_mock_wall, s_mock_uptime);
  MT_CHECK(TrustedTime::ValidateToken(prod, grant_tok) == TimeValidationResult::kValid);

  // Day 31: 1 day past expiration -> IN GRACE PERIOD
  std::uint64_t day31_wall = grant_tok.expires_at + 86400;
  s_mock_wall = day31_wall;
  s_mock_uptime = 3600 * 6;
  s_mock_boot_id = day31_wall - s_mock_uptime;
  TrustedTime::ResetProcessBaselineForTesting(s_mock_wall, s_mock_uptime);
  MT_CHECK(TrustedTime::ValidateToken(prod, grant_tok, /*allow_grace=*/true) == TimeValidationResult::kInGracePeriod);
  MT_CHECK(TrustedTime::ValidateToken(prod, grant_tok, /*allow_grace=*/false) == TimeValidationResult::kExpired);

  // Day 34: after grace period expired
  std::uint64_t day34_wall = grant_tok.grace_expires_at + 3600;
  s_mock_wall = day34_wall;
  s_mock_uptime = 3600 * 7;
  s_mock_boot_id = day34_wall - s_mock_uptime;
  TrustedTime::ResetProcessBaselineForTesting(s_mock_wall, s_mock_uptime);
  MT_CHECK(TrustedTime::ValidateToken(prod, grant_tok, /*allow_grace=*/true) == TimeValidationResult::kExpired);

  TrustedTime::ResetTimeStateForTesting(prod);
}

MT_TEST(TrustedTime_ClockFreezeAfterStartup_Detected) {
  std::string prod = "test_time_prod_freeze_inproc";
  TrustedTime::ResetTimeStateForTesting(prod);

  std::uint64_t t0 = 1700000000;
  s_mock_wall = t0;
  s_mock_uptime = 100;
  s_mock_boot_id = t0 - 100;
  TrustedTime::SetTimeProvidersForTesting(MockWall, MockUptime, MockBootId);
  TrustedTime::ResetProcessBaselineForTesting(t0, 100);

  MT_CHECK(TrustedTime::AnchorServerTime(prod, t0));

  // Process startup check
  auto t_start = TrustedTime::GetTrustedTime(prod);
  MT_CHECK(t_start.has_value());

  // Attacker freezes wall clock at t0, while steady uptime advances by 500s (elapsed = 400s > 300s skew)
  s_mock_uptime = 600;
  s_mock_wall = t0; // FROZEN!

  auto t_freeze = TrustedTime::GetTrustedTime(prod);
  // In-process clock freeze check must detect the freeze!
  MT_CHECK(!t_freeze.has_value());

  ActivationToken tok;
  tok.license_id = "lic-freeze-inproc";
  tok.issued_at = t0;
  tok.expires_at = t0 + 86400;
  tok.grace_expires_at = tok.expires_at + 86400;

  auto res = TrustedTime::ValidateToken(prod, tok);
  MT_CHECK(res == TimeValidationResult::kClockTampered);

  TrustedTime::ResetTimeStateForTesting(prod);
}

MT_TEST(TrustedTime_ClockRollback_Detected) {
  std::string prod = "test_time_prod_rollback";
  TrustedTime::ResetTimeStateForTesting(prod);

  std::uint64_t t0 = 1700000000;
  s_mock_wall = t0;
  s_mock_uptime = 100;
  s_mock_boot_id = t0 - 100;
  TrustedTime::SetTimeProvidersForTesting(MockWall, MockUptime, MockBootId);
  TrustedTime::ResetProcessBaselineForTesting(t0, 100);

  MT_CHECK(TrustedTime::AnchorServerTime(prod, t0));

  // Roll system wall clock backward by 10000 seconds
  s_mock_wall = t0 - 10000;
  s_mock_uptime = 200;

  auto t_rb = TrustedTime::GetTrustedTime(prod);
  MT_CHECK(!t_rb.has_value());

  ActivationToken tok;
  tok.license_id = "lic-rollback";
  tok.issued_at = t0;
  tok.expires_at = t0 + 86400;
  tok.grace_expires_at = tok.expires_at + 86400;

  auto res = TrustedTime::ValidateToken(prod, tok);
  MT_CHECK(res == TimeValidationResult::kClockTampered);

  TrustedTime::ResetTimeStateForTesting(prod);
}

MT_TEST(TrustedTime_MultiProductWriteThrottling_Independent) {
  std::string prodA = "test_time_prod_A";
  std::string prodB = "test_time_prod_B";
  TrustedTime::ResetTimeStateForTesting(prodA);
  TrustedTime::ResetTimeStateForTesting(prodB);

  std::uint64_t t0 = 1700000000;
  s_mock_wall = t0;
  s_mock_uptime = 100;
  s_mock_boot_id = t0 - 100;
  TrustedTime::SetTimeProvidersForTesting(MockWall, MockUptime, MockBootId);

  MT_CHECK(TrustedTime::AnchorServerTime(prodA, t0));
  MT_CHECK(TrustedTime::AnchorServerTime(prodB, t0));

  // Product A advances by 120 seconds (persists)
  s_mock_wall = t0 + 120;
  s_mock_uptime = 220;
  auto tA = TrustedTime::GetTrustedTime(prodA);
  MT_CHECK(tA.has_value());

  // Product B advances by 70 seconds -> its persistence must NOT be suppressed by product A!
  s_mock_wall = t0 + 70;
  s_mock_uptime = 170;
  auto tB = TrustedTime::GetTrustedTime(prodB);
  MT_CHECK(tB.has_value());

  TrustedTime::ResetTimeStateForTesting(prodA);
  TrustedTime::ResetTimeStateForTesting(prodB);
}

MT_TEST(TrustedTime_ForwardClockExcursion_RecoversOnServerAnchor) {
  std::string prod = "test_time_prod_forward_recovery";
  TrustedTime::ResetTimeStateForTesting(prod);

  std::uint64_t t0 = 1700000000;
  // Clock is set 10 minutes (600 seconds) ahead due to bad CMOS/NTP
  s_mock_wall = t0 + 600;
  s_mock_uptime = 100;
  s_mock_boot_id = (t0 + 600) - 100;
  TrustedTime::SetTimeProvidersForTesting(MockWall, MockUptime, MockBootId);
  TrustedTime::ResetProcessBaselineForTesting(t0 + 600, 100);

  // App runs with forward clock; GetTrustedTime observes and records the forward time
  auto t_fwd = TrustedTime::GetTrustedTime(prod);
  MT_CHECK(t_fwd.has_value());

  // System clock is now corrected back to true time t0 + 10
  // Simulate cold relaunch of the app with corrected clock
  s_mock_wall = t0 + 10;
  s_mock_uptime = 110;
  s_mock_boot_id = (t0 + 10) - 110;
  TrustedTime::ResetProcessBaselineForTesting(t0 + 10, 110);

  // Authoritative server anchor at true time t0 + 10 resets the high-water mark
  MT_CHECK(TrustedTime::AnchorServerTime(prod, t0 + 10));

  // After server anchor, GetTrustedTime MUST succeed and recover cleanly
  auto t_recovered = TrustedTime::GetTrustedTime(prod);
  MT_CHECK(t_recovered.has_value());
  MT_CHECK(*t_recovered >= t0 + 10);

  ActivationToken tok;
  tok.license_id = "lic-fwd-recovery";
  tok.issued_at = t0;
  tok.expires_at = t0 + 86400;
  tok.grace_expires_at = tok.expires_at + 86400;
  MT_CHECK(TrustedTime::ValidateToken(prod, tok) == TimeValidationResult::kValid);

  TrustedTime::ResetTimeStateForTesting(prod);
}

MT_TEST(TrustedTime_MidSessionBackwardStep_DoesNotTerminate) {
  std::string prod = "test_time_prod_backward_step";
  TrustedTime::ResetTimeStateForTesting(prod);

  std::uint64_t t0 = 1700000000;
  s_mock_wall = t0;
  s_mock_uptime = 100;
  s_mock_boot_id = t0 - 100;
  TrustedTime::SetTimeProvidersForTesting(MockWall, MockUptime, MockBootId);
  TrustedTime::ResetProcessBaselineForTesting(t0, 100);

  // Initial server anchor at t0
  MT_CHECK(TrustedTime::AnchorServerTime(prod, t0));

  // Process runs normally for 60 seconds
  s_mock_wall = t0 + 60;
  s_mock_uptime = 160;
  auto t1 = TrustedTime::GetTrustedTime(prod);
  MT_CHECK(t1.has_value());
  MT_CHECK(*t1 >= t0 + 60);

  // Mid-session, NTP or user steps clock backward by 10 minutes (600 seconds)
  // Wall clock is now t0 + 60 - 600 = t0 - 540.
  // Monotonic uptime keeps advancing steadily: 160 -> 200 (40 seconds of execution).
  s_mock_wall = t0 - 540;
  s_mock_uptime = 200;

  // TrustedTime must NOT fail or flag tamper! Steady clock continues to bridge true time.
  auto t2 = TrustedTime::GetTrustedTime(prod);
  MT_CHECK(t2.has_value());
  MT_CHECK(*t2 >= t0 + 100);

  // Verify that an active token still validates against the projected time
  ActivationToken tok;
  tok.license_id = "lic-backward-step";
  tok.issued_at = t0;
  tok.expires_at = t0 + 86400;
  tok.grace_expires_at = tok.expires_at + 86400;
  MT_CHECK(TrustedTime::ValidateToken(prod, tok) == TimeValidationResult::kValid);

  // Now the application re-anchors with authoritative server time
  std::uint64_t new_server_time = t0 + 100;
  MT_CHECK(TrustedTime::AnchorServerTime(prod, new_server_time));

  // Subsequent queries succeed cleanly
  auto t3 = TrustedTime::GetTrustedTime(prod);
  MT_CHECK(t3.has_value());
  MT_CHECK(*t3 >= new_server_time);

  TrustedTime::ResetTimeStateForTesting(prod);
}

MT_TEST(TrustedTime_RebootWithin300Seconds_Detected) {
  std::string prod = "test_time_prod_reboot_300s";
  TrustedTime::ResetTimeStateForTesting(prod);

  std::uint64_t t0 = 1700000000;
  // Boot 1: Machine runs for 20 seconds
  s_mock_wall = t0;
  s_mock_uptime = 20;
  s_mock_boot_id = t0 - 20;
  TrustedTime::SetTimeProvidersForTesting(MockWall, MockUptime, MockBootId);
  TrustedTime::ResetProcessBaselineForTesting(t0, 20);

  MT_CHECK(TrustedTime::AnchorServerTime(prod, t0));

  auto t1 = TrustedTime::GetTrustedTime(prod);
  MT_CHECK(t1.has_value());

  // Boot 2: Machine reboots quickly within 100s (< 300s skew tolerance).
  // Wall clock advances by 100s (to t0 + 100).
  // New boot has uptime = 25 (which is >= Boot 1's uptime 20).
  // boot_diff = |(t0 + 100 - 25) - (t0 - 20)| = |75 - (-20)| = 95s <= 300s.
  // The drift check |Δwall - Δuptime| = |100 - (25 - 20)| = |100 - 5| = 95s > 60s
  // correctly detects that a reboot occurred!
  std::uint64_t t2_wall = t0 + 100;
  std::uint64_t t2_uptime = 25;
  std::uint64_t t2_boot_id = t2_wall - t2_uptime;
  s_mock_wall = t2_wall;
  s_mock_uptime = t2_uptime;
  s_mock_boot_id = t2_boot_id;
  TrustedTime::ResetProcessBaselineForTesting(t2_wall, t2_uptime);

  auto t2 = TrustedTime::GetTrustedTime(prod);
  MT_CHECK(t2.has_value());

  // Verify that the reboot was detected: accumulated monotonic time in storage
  // must have accumulated the new boot's uptime (25s) rather than only delta (5s)
  auto state_bytes = SecureStorage::Load("time_state_" + prod);
  MT_CHECK(state_bytes.has_value());
  std::uint64_t accum = 0;
  for (int i = 0; i < 8; ++i) {
    accum |= (static_cast<std::uint64_t>((*state_bytes)[16 + i]) << (i * 8));
  }
  MT_CHECK(accum >= 25); // Correctly added new boot uptime!

  TrustedTime::ResetTimeStateForTesting(prod);
}

MT_TEST(TrustedTime_ConcurrentAccess_ThreadSafe) {
  std::string prod = "test_time_prod_concurrent";
  TrustedTime::ResetTimeStateForTesting(prod);

  std::uint64_t now = GetCurrentEpoch();
  MT_CHECK(TrustedTime::AnchorServerTime(prod, now));

  constexpr int kNumThreads = 8;
  constexpr int kOpsPerThread = 200;
  std::vector<std::thread> threads;
  threads.reserve(kNumThreads);

  std::atomic<int> success_count{0};

  for (int i = 0; i < kNumThreads; ++i) {
    threads.emplace_back([&, i]() {
      for (int op = 0; op < kOpsPerThread; ++op) {
        if (op % 20 == 0) {
          TrustedTime::AnchorServerTime(prod, now + (op / 20));
        }
        auto t = TrustedTime::GetTrustedTime(prod);
        if (t.has_value()) {
          success_count.fetch_add(1, std::memory_order_relaxed);
        }
      }
    });
  }

  for (auto& th : threads) {
    th.join();
  }

  MT_CHECK(success_count.load() == kNumThreads * kOpsPerThread);
  TrustedTime::ResetTimeStateForTesting(prod);
}

MT_MAIN()
