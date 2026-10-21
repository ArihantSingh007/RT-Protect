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

MT_MAIN()
