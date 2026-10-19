// antitamper/risk_policy.cpp

#include "antitamper/risk_policy.h"
#include "antitamper/anti_debug.h"
#include "antitamper/env_detect.h"

#include <cstdlib>

namespace rtprotect::antitamper {

RiskAssessment AssessEnvironmentRisk() {
  RiskAssessment r;
  r.debugger_present = CheckDebuggerPresent();
  r.remote_debugger_present = CheckRemoteDebugger();
  r.hardware_breakpoints_detected = CheckHardwareBreakpoints();
  r.timing_anomaly_detected = CheckExecutionTimingAnomaly();
  r.hypervisor_detected = CheckHypervisorPresent();
  if (r.hypervisor_detected) {
    r.hypervisor_vendor = GetHypervisorVendor();
  }

  int score = 0;
  if (r.debugger_present) score += 40;
  if (r.remote_debugger_present) score += 40;
  if (r.hardware_breakpoints_detected) score += 50;
  if (r.timing_anomaly_detected) score += 30;
  if (r.hypervisor_detected) score += 15; // Low risk by itself to avoid penalizing legitimate VMs

  if (score > 100) score = 100;
  r.risk_score = score;
  return r;
}

bool EnforceRiskPolicy(RiskAction action, const RiskAssessment& assessment) {
  switch (action) {
    case RiskAction::kReportOnly:
      return true;

    case RiskAction::kRestrict:
      return !assessment.HasHighRisk();

    case RiskAction::kTerminate:
      if (assessment.HasHighRisk()) {
        std::exit(1);
      }
      return true;
  }
  return true;
}

}  // namespace rtprotect::antitamper
