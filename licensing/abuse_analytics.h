// licensing/abuse_analytics.h
//
// Real-time Abuse-Pattern Analytics & Anomaly Detection Engine for RTProtect Activation Authority.
// Detects high-risk behavioral anomalies:
//   - Shared-Key Syndrome: single license key activated across multiple distinct hardware fingerprints
//     and IP subnets beyond allowed seat limits.
//   - Rapid Seat Churn: frequent seat turnover/re-allocations within rolling time windows.
//   - Subnet Dispersion: simultaneous or near-simultaneous activations arriving from disparate /24 or /16 subnets.
//   - Activation Bursts: abnormal bursts of activation attempts indicating automated credential stuffing.
//   - Replay / Brute-Force Attacks: concentrated nonce replay or rate-limiting blockades.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "licensing/activation_database.h"

namespace rtprotect::licensing {

enum class RiskSeverity {
  kLow = 0,      // Normal usage
  kMedium,       // Elevated turnover / minor subnet dispersion
  kHigh,         // Shared-key symptoms / rapid churn
  kCritical      // Confirmed key sharing / multi-subnet piracy burst
};

const char* ToString(RiskSeverity severity);

enum class RecommendedAction {
  kAllow = 0,
  kMonitor,
  kFlagForReview,
  kSuspendLicense
};

const char* ToString(RecommendedAction action);

struct LicenseAnomalyFlag {
  std::string flag_code;
  std::string description;
  double score_impact = 0.0;
};

struct LicenseRiskReport {
  std::string license_id;
  std::string product_id;
  std::uint32_t max_seats = 1;
  std::size_t active_seats = 0;
  std::size_t distinct_devices_window = 0;
  std::size_t distinct_subnets_window = 0;
  std::size_t abuse_events_count = 0;
  std::size_t total_events_window = 0;
  double risk_score = 0.0; // 0.0 to 1.0
  RiskSeverity severity = RiskSeverity::kLow;
  RecommendedAction action = RecommendedAction::kAllow;
  std::vector<LicenseAnomalyFlag> anomaly_flags;
};

struct AbuseAnalyticsSummary {
  std::uint64_t evaluated_at = 0;
  std::uint64_t window_seconds = 0;
  std::size_t total_licenses_analyzed = 0;
  std::size_t low_risk_count = 0;
  std::size_t medium_risk_count = 0;
  std::size_t high_risk_count = 0;
  std::size_t critical_risk_count = 0;
  std::vector<LicenseRiskReport> flagged_licenses; // medium, high, and critical
};

class AbuseAnalyticsEngine {
 public:
  // Evaluates risk across all licenses in the database within the given rolling window (default: 7 days)
  static AbuseAnalyticsSummary Analyze(const ActivationDatabase& db,
                                       std::uint64_t current_time = 0,
                                       std::uint64_t window_seconds = 7 * 86400);

  // Evaluates risk for a specific license ID
  static LicenseRiskReport AnalyzeLicense(const ActivationDatabase& db,
                                          const std::string& license_id,
                                          std::uint64_t current_time = 0,
                                          std::uint64_t window_seconds = 7 * 86400);

  // Formats the analytics report into JSON for the /analytics REST endpoint
  static std::string ToJson(const AbuseAnalyticsSummary& summary);
};

}  // namespace rtprotect::licensing
