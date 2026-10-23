// licensing/abuse_analytics.cpp
//
// Real-time Abuse-Pattern Analytics & Anomaly Detection Engine implementation.

#include "licensing/abuse_analytics.h"

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace rtprotect::licensing {

namespace {

std::string ExtractSubnet(const std::string& ip) {
  if (ip.empty() || ip == "127.0.0.1" || ip == "localhost" || ip == "::1") {
    return "127.0.0.0/8";
  }
  // IPv4 /24 subnet extraction (e.g. 192.168.1.100 -> 192.168.1.0/24)
  std::size_t dot1 = ip.find('.');
  if (dot1 != std::string::npos) {
    std::size_t dot2 = ip.find('.', dot1 + 1);
    if (dot2 != std::string::npos) {
      std::size_t dot3 = ip.find('.', dot2 + 1);
      if (dot3 != std::string::npos) {
        return ip.substr(0, dot3) + ".0/24";
      }
    }
  }
  // IPv6 prefix extraction
  std::size_t colon3 = 0;
  int colon_count = 0;
  for (std::size_t i = 0; i < ip.size(); ++i) {
    if (ip[i] == ':') {
      colon_count++;
      if (colon_count == 3) {
        colon3 = i;
        break;
      }
    }
  }
  if (colon3 > 0) {
    return ip.substr(0, colon3) + "::/48";
  }
  return ip;
}

std::string EscapeJson(const std::string& s) {
  std::ostringstream o;
  for (char c : s) {
    if (c == '"') o << "\\\"";
    else if (c == '\\') o << "\\\\";
    else if (c == '\b') o << "\\b";
    else if (c == '\f') o << "\\f";
    else if (c == '\n') o << "\\n";
    else if (c == '\r') o << "\\r";
    else if (c == '\t') o << "\\t";
    else if (static_cast<unsigned char>(c) < 32) {
      o << "\\u00" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    } else {
      o << c;
    }
  }
  return o.str();
}

}  // namespace

const char* ToString(RiskSeverity severity) {
  switch (severity) {
    case RiskSeverity::kLow: return "LOW";
    case RiskSeverity::kMedium: return "MEDIUM";
    case RiskSeverity::kHigh: return "HIGH";
    case RiskSeverity::kCritical: return "CRITICAL";
  }
  return "UNKNOWN";
}

const char* ToString(RecommendedAction action) {
  switch (action) {
    case RecommendedAction::kAllow: return "ALLOW";
    case RecommendedAction::kMonitor: return "MONITOR";
    case RecommendedAction::kFlagForReview: return "FLAG_FOR_REVIEW";
    case RecommendedAction::kSuspendLicense: return "SUSPEND_LICENSE";
  }
  return "UNKNOWN";
}

LicenseRiskReport AbuseAnalyticsEngine::AnalyzeLicense(
    const ActivationDatabase& db,
    const std::string& license_id,
    std::uint64_t current_time,
    std::uint64_t window_seconds) {
  LicenseRiskReport report;
  report.license_id = license_id;

  if (current_time == 0) {
    auto now = std::chrono::system_clock::now().time_since_epoch();
    current_time = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(now).count());
  }
  std::uint64_t window_start = (current_time > window_seconds) ? (current_time - window_seconds) : 0;

  auto lic_opt = db.GetLicense(license_id);
  if (lic_opt.has_value()) {
    report.product_id = lic_opt->product_id;
    report.max_seats = (lic_opt->max_seats > 0) ? lic_opt->max_seats : 1;
  }

  auto activations = db.GetActivations(license_id);
  report.active_seats = activations.size();

  std::unordered_set<std::string> devices_in_window;
  std::unordered_set<std::string> subnets_in_window;

  for (const auto& a : activations) {
    if (a.last_seen >= window_start) {
      devices_in_window.insert(a.device_fingerprint);
    }
  }

  auto events = db.GetRecentEvents(license_id, 1000);
  std::size_t total_events = 0;
  std::size_t abuse_events = 0;
  std::size_t replay_count = 0;
  std::size_t rate_limit_count = 0;
  std::size_t seat_exhaust_count = 0;
  std::size_t churn_swaps = 0;

  for (const auto& ev : events) {
    if (ev.timestamp >= window_start) {
      total_events++;
      if (!ev.device_fingerprint.empty()) {
        devices_in_window.insert(ev.device_fingerprint);
      }
      if (!ev.ip_address.empty()) {
        subnets_in_window.insert(ExtractSubnet(ev.ip_address));
      }

      if (ev.type == ActivationEventType::kReplayBlocked) {
        replay_count++;
        abuse_events++;
      } else if (ev.type == ActivationEventType::kRateLimited) {
        rate_limit_count++;
        abuse_events++;
      } else if (ev.type == ActivationEventType::kSeatLimitExceeded) {
        seat_exhaust_count++;
        abuse_events++;
      } else if (ev.type == ActivationEventType::kActivationFailed) {
        abuse_events++;
      } else if (ev.type == ActivationEventType::kDeactivation) {
        churn_swaps++;
      }
    }
  }

  report.distinct_devices_window = devices_in_window.size();
  report.distinct_subnets_window = subnets_in_window.size();
  report.abuse_events_count = abuse_events;
  report.total_events_window = total_events;

  double raw_score = 0.0;

  // 1. Shared-Key Syndrome Detection
  if (report.distinct_devices_window > report.max_seats) {
    std::size_t excess = report.distinct_devices_window - report.max_seats;
    double impact = (std::min)(0.50, static_cast<double>(excess) * 0.15);
    raw_score += impact;
    LicenseAnomalyFlag flag;
    flag.flag_code = "SHARED_KEY_SYNDROME";
    flag.description = "Hardware fingerprint count (" + std::to_string(report.distinct_devices_window) +
                       ") exceeds licensed seat quota (" + std::to_string(report.max_seats) + ")";
    flag.score_impact = impact;
    report.anomaly_flags.push_back(flag);
  }

  // 2. Subnet Dispersion Detection
  std::size_t expected_max_subnets = (std::max)(static_cast<std::size_t>(2), static_cast<std::size_t>(report.max_seats * 2));
  if (report.distinct_subnets_window > expected_max_subnets) {
    std::size_t excess_subnets = report.distinct_subnets_window - expected_max_subnets;
    double impact = (std::min)(0.35, static_cast<double>(excess_subnets) * 0.10);
    raw_score += impact;
    LicenseAnomalyFlag flag;
    flag.flag_code = "SUBNET_DISPERSION";
    flag.description = "Simultaneous activations across " + std::to_string(report.distinct_subnets_window) +
                       " disparate network subnets";
    flag.score_impact = impact;
    report.anomaly_flags.push_back(flag);
  }

  // 3. Rapid Seat Churn Detection
  if (churn_swaps > static_cast<std::size_t>(report.max_seats * 3)) {
    double impact = (std::min)(0.25, static_cast<double>(churn_swaps) * 0.05);
    raw_score += impact;
    LicenseAnomalyFlag flag;
    flag.flag_code = "RAPID_SEAT_CHURN";
    flag.description = "Abnormal deactivation/swap frequency (" + std::to_string(churn_swaps) +
                       " operations in window)";
    flag.score_impact = impact;
    report.anomaly_flags.push_back(flag);
  }

  // 4. Replay and Brute-force Spikes
  if (replay_count > 0 || rate_limit_count >= 5) {
    double impact = (std::min)(0.40, static_cast<double>(replay_count) * 0.15 + static_cast<double>(rate_limit_count) * 0.03);
    raw_score += impact;
    LicenseAnomalyFlag flag;
    flag.flag_code = "REPLAY_OR_BRUTE_FORCE_SPIKE";
    flag.description = "Detected " + std::to_string(replay_count) + " cryptographic replay attempts and " +
                       std::to_string(rate_limit_count) + " rate-limit triggers";
    flag.score_impact = impact;
    report.anomaly_flags.push_back(flag);
  }

  // 5. Seat Limit Exhaustion Bursts
  if (seat_exhaust_count >= 3) {
    double impact = (std::min)(0.25, static_cast<double>(seat_exhaust_count) * 0.05);
    raw_score += impact;
    LicenseAnomalyFlag flag;
    flag.flag_code = "SEAT_LIMIT_EXHAUSTION_SPIKE";
    flag.description = "Repeated seat rejection bursts (" + std::to_string(seat_exhaust_count) +
                       " blocked activations)";
    flag.score_impact = impact;
    report.anomaly_flags.push_back(flag);
  }

  report.risk_score = (std::min)(1.0, (std::max)(0.0, raw_score));

  // Determine Severity and Action
  if (report.risk_score >= 0.75) {
    report.severity = RiskSeverity::kCritical;
    report.action = RecommendedAction::kSuspendLicense;
  } else if (report.risk_score >= 0.50) {
    report.severity = RiskSeverity::kHigh;
    report.action = RecommendedAction::kFlagForReview;
  } else if (report.risk_score >= 0.25) {
    report.severity = RiskSeverity::kMedium;
    report.action = RecommendedAction::kMonitor;
  } else {
    report.severity = RiskSeverity::kLow;
    report.action = RecommendedAction::kAllow;
  }

  return report;
}

AbuseAnalyticsSummary AbuseAnalyticsEngine::Analyze(
    const ActivationDatabase& db,
    std::uint64_t current_time,
    std::uint64_t window_seconds) {
  AbuseAnalyticsSummary summary;
  if (current_time == 0) {
    auto now = std::chrono::system_clock::now().time_since_epoch();
    current_time = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(now).count());
  }
  summary.evaluated_at = current_time;
  summary.window_seconds = window_seconds;

  auto licenses = db.GetAllLicenses();
  summary.total_licenses_analyzed = licenses.size();

  for (const auto& lic : licenses) {
    auto rep = AnalyzeLicense(db, lic.license_id, current_time, window_seconds);
    switch (rep.severity) {
      case RiskSeverity::kLow:
        summary.low_risk_count++;
        break;
      case RiskSeverity::kMedium:
        summary.medium_risk_count++;
        summary.flagged_licenses.push_back(rep);
        break;
      case RiskSeverity::kHigh:
        summary.high_risk_count++;
        summary.flagged_licenses.push_back(rep);
        break;
      case RiskSeverity::kCritical:
        summary.critical_risk_count++;
        summary.flagged_licenses.push_back(rep);
        break;
    }
  }

  // Sort flagged licenses by descending risk score
  std::sort(summary.flagged_licenses.begin(), summary.flagged_licenses.end(),
            [](const LicenseRiskReport& a, const LicenseRiskReport& b) {
              return a.risk_score > b.risk_score;
            });

  return summary;
}

std::string AbuseAnalyticsEngine::ToJson(const AbuseAnalyticsSummary& summary) {
  std::ostringstream ss;
  ss << "{\n"
     << "  \"evaluated_at\": " << summary.evaluated_at << ",\n"
     << "  \"window_seconds\": " << summary.window_seconds << ",\n"
     << "  \"summary\": {\n"
     << "    \"total_licenses_analyzed\": " << summary.total_licenses_analyzed << ",\n"
     << "    \"low_risk\": " << summary.low_risk_count << ",\n"
     << "    \"medium_risk\": " << summary.medium_risk_count << ",\n"
     << "    \"high_risk\": " << summary.high_risk_count << ",\n"
     << "    \"critical_risk\": " << summary.critical_risk_count << "\n"
     << "  },\n"
     << "  \"flagged_licenses\": [\n";

  for (std::size_t i = 0; i < summary.flagged_licenses.size(); ++i) {
    const auto& fl = summary.flagged_licenses[i];
    ss << "    {\n"
       << "      \"license_id\": \"" << EscapeJson(fl.license_id) << "\",\n"
       << "      \"product_id\": \"" << EscapeJson(fl.product_id) << "\",\n"
       << "      \"max_seats\": " << fl.max_seats << ",\n"
       << "      \"active_seats\": " << fl.active_seats << ",\n"
       << "      \"distinct_devices\": " << fl.distinct_devices_window << ",\n"
       << "      \"distinct_subnets\": " << fl.distinct_subnets_window << ",\n"
       << "      \"abuse_events\": " << fl.abuse_events_count << ",\n"
       << "      \"risk_score\": " << std::fixed << std::setprecision(3) << fl.risk_score << ",\n"
       << "      \"severity\": \"" << ToString(fl.severity) << "\",\n"
       << "      \"recommended_action\": \"" << ToString(fl.action) << "\",\n"
       << "      \"anomaly_flags\": [\n";
    for (std::size_t j = 0; j < fl.anomaly_flags.size(); ++j) {
      const auto& af = fl.anomaly_flags[j];
      ss << "        {\n"
         << "          \"code\": \"" << EscapeJson(af.flag_code) << "\",\n"
         << "          \"description\": \"" << EscapeJson(af.description) << "\",\n"
         << "          \"impact\": " << std::fixed << std::setprecision(3) << af.score_impact << "\n"
         << "        }" << (j + 1 < fl.anomaly_flags.size() ? "," : "") << "\n";
    }
    ss << "      ]\n"
       << "    }" << (i + 1 < summary.flagged_licenses.size() ? "," : "") << "\n";
  }

  ss << "  ]\n"
     << "}\n";
  return ss.str();
}

}  // namespace rtprotect::licensing
