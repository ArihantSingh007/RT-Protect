// antitamper/risk_policy.h
//
// Defense-in-depth runtime risk assessment and configurable response policy.
//
// Signals (debugger detection, hardware breakpoints, timing anomalies,
// virtualization indicators) are treated as risk metrics, not infallible proof
// of piracy.
//
// Configurable policy options:
//   - kReportOnly: Records or logs diagnostics without altering execution.
//   - kRestrict: Signals application logic to degrade or restrict sensitive features.
//   - kTerminate: Safely terminates the process (fail-closed) without corrupting user data.

#pragma once

#include <string>

namespace rtprotect::antitamper {

enum class RiskAction {
  kReportOnly = 0,
  kRestrict,
  kTerminate
};

struct RiskAssessment {
  bool debugger_present = false;
  bool remote_debugger_present = false;
  bool hardware_breakpoints_detected = false;
  bool timing_anomaly_detected = false;
  bool hypervisor_detected = false;
  std::string hypervisor_vendor;
  bool memory_tampered = false;

  int risk_score = 0;  // 0 (clean) to 100 (high risk)

  bool HasHighRisk() const { return risk_score >= 50; }
};

// Evaluates the current execution environment and compiles a RiskAssessment.
RiskAssessment AssessEnvironmentRisk();

// Applies the configured risk action based on assessment results.
// If action is kTerminate and risk exceeds threshold, cleanly exits with code 1.
// Returns true if execution is permitted to proceed, false if restricted.
bool EnforceRiskPolicy(RiskAction action, const RiskAssessment& assessment);

}  // namespace rtprotect::antitamper
