// tests/test_antitamper.cpp

#include "antitamper/anti_debug.h"
#include "antitamper/anti_dump.h"
#include "antitamper/dynamic_import.h"
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
  (void)is_vm;
  (void)vendor;
  // Non-crashing execution is verified; vendor string may be empty even in hypervisors
  MT_CHECK(true);
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

MT_TEST(AntiTamper_DeriveRiskSalt_DistinguishesCleanAndPoisoned) {
  RiskAssessment clean;
  clean.risk_score = 0;

  RiskAssessment poisoned;
  poisoned.debugger_present = true;
  poisoned.risk_score = 40;

  auto salt_clean = DeriveRiskSalt(clean);
  auto salt_poisoned = DeriveRiskSalt(poisoned);

  MT_CHECK(salt_clean.size() == 32);
  MT_CHECK(salt_poisoned.size() == 32);
  MT_CHECK(salt_clean != salt_poisoned);
}

MT_TEST(AntiTamper_DeriveTamperBoundKey_PerturbsKeyUnderTampering) {
  auto master = rtprotect::crypto::Aes256Key::Generate();

  RiskAssessment clean;
  clean.risk_score = 0;

  RiskAssessment tampered;
  tampered.hardware_breakpoints_detected = true;
  tampered.risk_score = 50;

  auto key_clean = DeriveTamperBoundKey(master, clean, "virtualized-routine-1");
  auto key_tampered = DeriveTamperBoundKey(master, tampered, "virtualized-routine-1");

  // The keys must diverge: tamper poisons the derived key
  MT_CHECK(std::memcmp(key_clean.bytes().data(), key_tampered.bytes().data(), 32) != 0);
}

MT_TEST(AntiTamper_DeriveTamperPerturbation_CleanIsZero) {
  RiskAssessment clean;
  clean.risk_score = 0;
  MT_CHECK(DeriveTamperPerturbation(clean) == 0);

  RiskAssessment tampered;
  tampered.debugger_present = true;
  tampered.risk_score = 40;
  MT_CHECK(DeriveTamperPerturbation(tampered) != 0);
}

MT_TEST(AntiTamper_MemoryTamperCheck_CleanBinary_DoesNotTrigger) {
  bool tampered = CheckMemoryTampered();
  MT_CHECK(!tampered);
}

MT_TEST(AntiTamper_ScatterTamperCheck_CleanState_PreservesAccumulator) {
  std::uint64_t acc = 0x1234567890ABCDEFULL;
  ScatterTamperCheck("unit_test_checkpoint", &acc);
  MT_CHECK(acc == 0x1234567890ABCDEFULL);
}

MT_TEST(AntiTamper_Watchdog_StartsAndStopsCleanly) {
  StartHardwareBreakpointWatchdog(20);
  MT_CHECK(!IsHardwareBreakpointDetected());
  StopHardwareBreakpointWatchdog();
  MT_CHECK(true);
}

MT_TEST(AntiTamper_AssessFastRisk_ExecutesWithoutThreadCreation) {
  RiskAssessment r = AssessFastEnvironmentRisk();
  MT_CHECK(r.risk_score >= 0 && r.risk_score <= 100);
}

MT_TEST(AntiTamper_DynamicImport_CompileTimeHashValidation) {
  constexpr std::uint32_t h1 = HashApi("IsDebuggerPresent");
  constexpr std::uint32_t h2 = HashApi("CheckRemoteDebuggerPresent");
  MT_CHECK(h1 != 0);
  MT_CHECK(h2 != 0);
  MT_CHECK(h1 != h2);

  // Case insensitive hash matches uppercase / lowercase
  constexpr std::uint32_t mod_lower = HashApiCaseInsensitive("kernel32.dll");
  constexpr std::uint32_t mod_upper = HashApiCaseInsensitive("KERNEL32.DLL");
  MT_CHECK(mod_lower == mod_upper);

  const wchar_t wide_name[] = L"KERNEL32.DLL";
  std::uint32_t mod_wide = HashApiWideCaseInsensitive(wide_name, 12);
  MT_CHECK(mod_wide == mod_lower);
}

MT_TEST(AntiTamper_DynamicImport_ResolveExportByHash) {
#if defined(_WIN32)
  void* k32_base = GetLoadedModuleBaseByHash(kHashKernel32);
  MT_CHECK(k32_base != nullptr);

  auto fnVirtualProtect = ResolveExportByHash(k32_base, kHashVirtualProtect);
  MT_CHECK(fnVirtualProtect != nullptr);

  auto fnIsDbg = ResolveExportByHash(k32_base, kHashIsDebuggerPresent);
  MT_CHECK(fnIsDbg != nullptr);

  // Invalid hash should return nullptr
  auto fnInvalid = ResolveExportByHash(k32_base, 0x12345678);
  MT_CHECK(fnInvalid == nullptr);
#else
  MT_CHECK(true);
#endif
}

MT_TEST(AntiTamper_AntiDump_DetectMemoryDumper_CleanEnvironment) {
  // In normal test execution, no dumper module or dbghelp should be present
  bool dumper = DetectMemoryDumper();
  MT_CHECK(!dumper);
}

MT_TEST(AntiTamper_AntiDump_DetectMemoryProbing_CleanEnvironment) {
  bool probing = DetectMemoryProbing();
  MT_CHECK(!probing);
}

MT_TEST(AntiTamper_AntiDump_EphemeralExecutionGuard_ExecuteAndCleanse) {
  EphemeralExecutionGuard guard;
#if defined(_WIN32)
  // Windows x64: lea rax, [rcx + rcx + 7]; ret -> computes 2*x + 7
  static const std::uint8_t kPayload[] = { 0x48, 0x8d, 0x44, 0x09, 0x07, 0xc3 };
#else
  // SysV x64: lea rax, [rdi + rdi + 7]; ret -> computes 2*x + 7
  static const std::uint8_t kPayload[] = { 0x48, 0x8d, 0x44, 0x3f, 0x07, 0xc3 };
#endif
  std::int64_t result = 0;
  bool ok = guard.ExecuteEphemeral(kPayload, sizeof(kPayload), 5, &result);
  MT_CHECK(ok);
  MT_CHECK(result == 17);  // 2*5 + 7 = 17
  // After execution completes, memory should have been cleansed and freed
  MT_CHECK(!guard.IsAllocated());
}

MT_MAIN()
