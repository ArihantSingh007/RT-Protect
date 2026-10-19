// tests/test_antitamper.cpp

#include "antitamper/anti_debug.h"
#include "antitamper/env_detect.h"
#include "antitamper/risk_policy.h"
#include "tests/micro_test.h"

using namespace rtprotect::antitamper;

MT_TEST(AntiTamper_DebuggerChecks_ExecuteWithoutFaulting) {
  bool dbg = CheckDebuggerPresent();
  bool rdbg = CheckRemoteDebugger();
  bool hw_bp = CheckHardwareBreakpoints();
  (void)dbg;
  (void)rdbg;
  (void)hw_bp;
  MT_CHECK(true);
}

MT_TEST(AntiTamper_TimingCheck_NormalExecution_DoesNotTrigger) {
  // In normal test execution without a breakpoint, timing loop should complete well within 0.25s
  bool anomaly = CheckExecutionTimingAnomaly();
  MT_CHECK(!anomaly);
}

MT_TEST(AntiTamper_EnvironmentChecks_ExecuteCleanly) {
  bool is_vm = CheckHypervisorPresent();
  std::string vendor = GetHypervisorVendor();
  if (is_vm) {
    MT_CHECK(!vendor.empty());
  }
}

MT_TEST(AntiTamper_RiskAssessment_CalculatesScore) {
  RiskAssessment r = AssessEnvironmentRisk();
  MT_CHECK(r.risk_score >= 0 && r.risk_score <= 100);
}

MT_TEST(AntiTamper_EnforcePolicy_ReportOnly_AlwaysPasses) {
  RiskAssessment r;
  r.risk_score = 90; // High risk
  bool ok = EnforceRiskPolicy(RiskAction::kReportOnly, r);
  MT_CHECK(ok);
}

MT_TEST(AntiTamper_EnforcePolicy_Restrict_BlocksOnHighRisk) {
  RiskAssessment clean;
  clean.risk_score = 10;
  MT_CHECK(EnforceRiskPolicy(RiskAction::kRestrict, clean));

  RiskAssessment high_risk;
  high_risk.risk_score = 75;
  MT_CHECK(!EnforceRiskPolicy(RiskAction::kRestrict, high_risk));
}

MT_MAIN()
