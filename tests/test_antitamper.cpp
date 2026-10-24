// tests/test_antitamper.cpp

#include "antitamper/anti_debug.h"
#include "antitamper/anti_dump.h"
#include "antitamper/dynamic_import.h"
#include "antitamper/env_detect.h"
#include "antitamper/risk_policy.h"
#include "antitamper/section_protector.h"
#include "licensing/countermeasure_config.h"
#include "obfuscation/control_flow.h"
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

MT_TEST(AntiTamper_HypervisorAloneKeepsCanonicalCleanKeySalt) {
  RiskAssessment clean;
  RiskAssessment virtualized;
  virtualized.hypervisor_detected = true;
  virtualized.risk_score = 15;
  MT_CHECK(DeriveRiskSalt(clean) == DeriveRiskSalt(virtualized));
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

MT_TEST(AntiTamper_RiskAssessment_WiresAntiDumpChecks) {
  RiskAssessment r_env = AssessEnvironmentRisk();
  RiskAssessment r_fast = AssessFastEnvironmentRisk();

  // Flags must be populated consistently
  MT_CHECK(r_env.memory_dump_detected == DetectMemoryDumper());
  MT_CHECK(r_env.memory_probing_detected == DetectMemoryProbing());
  MT_CHECK(r_fast.memory_dump_detected == DetectMemoryDumper());
  MT_CHECK(r_fast.memory_probing_detected == DetectMemoryProbing());

  // Synthetic validation: memory dump and probing detection poison risk salt
  RiskAssessment clean;
  clean.risk_score = 0;
  auto clean_salt = DeriveRiskSalt(clean);

  RiskAssessment dump_detected = clean;
  dump_detected.memory_dump_detected = true;
  dump_detected.risk_score = 40;
  auto dump_salt = DeriveRiskSalt(dump_detected);
  MT_CHECK(clean_salt != dump_salt);

  RiskAssessment probe_detected = clean;
  probe_detected.memory_probing_detected = true;
  probe_detected.risk_score = 30;
  auto probe_salt = DeriveRiskSalt(probe_detected);
  MT_CHECK(clean_salt != probe_salt);
}

MT_TEST(AntiTamper_ValueEntanglement_CleanVsTampered) {
  RiskAssessment clean;
  clean.risk_score = 0;
  clean.debugger_present = false;
  clean.memory_dump_detected = false;

  // Clean risk assessment produces strictly 0 delta and mask
  MT_CHECK(FoldTamperStateDelta(clean, 0x1111) == 0);
  MT_CHECK(FoldTamperStateMask(clean, 0x2222) == 0);

  // Business computation preserved when clean
  std::int64_t gameplay_health = 100;
  std::int64_t clean_health = gameplay_health - static_cast<std::int64_t>(FoldTamperStateDelta(clean));
  MT_CHECK(clean_health == 100);

  // Tampered assessment produces non-zero perturbation
  RiskAssessment tampered = clean;
  tampered.risk_score = 45;
  tampered.debugger_present = true;

  std::uint64_t delta1 = FoldTamperStateDelta(tampered, 0x1111);
  std::uint64_t delta2 = FoldTamperStateDelta(tampered, 0x3333);
  std::uint64_t mask = FoldTamperStateMask(tampered, 0x2222);

  MT_CHECK(delta1 != 0);
  MT_CHECK(delta2 != 0);
  MT_CHECK(mask != 0);
  MT_CHECK(delta1 != delta2);  // Salt variation produces different deltas

  // Downstream value is perturbed/corrupted without explicit branch
  std::int64_t corrupted_health = gameplay_health - static_cast<std::int64_t>(delta1);
  MT_CHECK(corrupted_health != 100);
}

MT_TEST(AntiTamper_AssessEnvironmentRiskVirtualized_ExecutesBytecode) {
  // Test with multiple seeds to verify permutation invariance and robust bytecode generation
  RiskAssessment r1 = AssessEnvironmentRiskVirtualized(nullptr, 0x12345678);
  MT_CHECK(r1.risk_score >= 0 && r1.risk_score <= 100);

  RiskAssessment r2 = AssessEnvironmentRiskVirtualized(nullptr, 0x9ABCDEF0);
  MT_CHECK(r2.risk_score >= 0 && r2.risk_score <= 100);
}

MT_TEST(AntiTamper_FunctionCrossLink_DepositAndVerify) {
  FunctionCrossLink::ResetForTesting();

  constexpr std::uint64_t kFnA = 0xAA01;
  constexpr std::uint64_t kFnB = 0xBB02;
  constexpr std::uint64_t kTokenA = 0xDEADBEEFCAFEULL;
  constexpr std::uint64_t kTokenB = 0xFEEDFACE1234ULL;

  // Initially unverified
  MT_CHECK(!FunctionCrossLink::VerifyToken(kFnA, kTokenA));
  MT_CHECK(!FunctionCrossLink::VerifyToken(kFnB, kTokenB));

  // Deposit token for function A
  FunctionCrossLink::DepositToken(kFnA, kTokenA);
  MT_CHECK(FunctionCrossLink::VerifyToken(kFnA, kTokenA));
  MT_CHECK(!FunctionCrossLink::VerifyToken(kFnA, 0xBADC0DEULL));
  MT_CHECK(!FunctionCrossLink::VerifyToken(kFnB, kTokenB));

  // Deposit token for function B
  FunctionCrossLink::DepositToken(kFnB, kTokenB);
  MT_CHECK(FunctionCrossLink::VerifyToken(kFnA, kTokenA));
  MT_CHECK(FunctionCrossLink::VerifyToken(kFnB, kTokenB));

  // Reset clears all tokens
  FunctionCrossLink::ResetForTesting();
  MT_CHECK(!FunctionCrossLink::VerifyToken(kFnA, kTokenA));
  MT_CHECK(!FunctionCrossLink::VerifyToken(kFnB, kTokenB));
}

MT_TEST(AntiTamper_DynamicImportMacros_ExecuteCorrectly) {
  // Verify RTPROTECT_CALL_API resolves and executes GetCurrentProcessId directly without IAT entry
  DWORD pid = RTPROTECT_CALL_API("kernel32.dll", GetCurrentProcessId, DWORD(WINAPI*)());
  MT_CHECK(pid == ::GetCurrentProcessId());

  // Verify RTPROTECT_RESOLVE_API resolves VirtualProtect
  auto pVP = RTPROTECT_RESOLVE_API("kernel32.dll", VirtualProtect, BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD));
  MT_CHECK(pVP != nullptr);
}

MT_TEST(AntiTamper_ScopedSectionExecution_RefcountingAndLifecycle) {
  // ScopedSectionExecution with null header is a valid no-op (no encrypted PE section embedded)
  {
    ScopedSectionExecution scope(nullptr);
    MT_CHECK(scope.IsValid());

    // Test move construction
    ScopedSectionExecution scope2(std::move(scope));
    MT_CHECK(scope2.IsValid());
    MT_CHECK(!scope.IsValid()); // Moved-from scope is deactivated

    // Test move assignment
    ScopedSectionExecution scope3;
    scope3 = std::move(scope2);
    MT_CHECK(scope3.IsValid());
    MT_CHECK(!scope2.IsValid());
  }
}

MT_TEST(AntiTamper_Obfuscation_ControlFlowAndMba) {
  using namespace rtprotect::obfuscation;

  // MBA Arithmetic Substitutions
  MT_CHECK(MbaAdd(15, 27) == 42);
  MT_CHECK(MbaAdd(-10, 25) == 15);
  MT_CHECK(MbaSub(100, 37) == 63);
  MT_CHECK(MbaSub(40, 50) == -10);
  MT_CHECK(MbaXor(0x1234, 0x5678) == (0x1234 ^ 0x5678));
  MT_CHECK(MbaEqual(42, 42) == true);
  MT_CHECK(MbaEqual(42, 43) == false);

  // Invariant Opaque Predicates
  MT_CHECK(OpaquePredicateTrue(0) == true);
  MT_CHECK(OpaquePredicateTrue(42) == true);
  MT_CHECK(OpaquePredicateTrue(1337) == true);
  MT_CHECK(OpaquePredicateTrue(-7) == true);

  MT_CHECK(OpaquePredicateFalse(0) == false);
  MT_CHECK(OpaquePredicateFalse(42) == false);
  MT_CHECK(OpaquePredicateFalse(1337) == false);

  MT_CHECK(OpaquePredicateEqual(10, 20) == true);
  MT_CHECK(OpaquePredicateEqual(0, 0) == true);
  MT_CHECK(OpaquePredicateEqual(-5, 15) == true);

  // Control-Flow Flattening State Machine Dispatcher
  int step_accumulator = 0;
  RTPROTECT_FLATTEN_BEGIN(st, 1) {
    RTPROTECT_FLATTEN_CASE(1) {
      step_accumulator += 10;
      RTPROTECT_FLATTEN_TRANSITION(st, 2);
    }
    RTPROTECT_FLATTEN_CASE(2) {
      step_accumulator *= 2;
      RTPROTECT_FLATTEN_TRANSITION(st, 3);
    }
    RTPROTECT_FLATTEN_CASE(3) {
      step_accumulator += 5;
      RTPROTECT_FLATTEN_EXIT();
    }
  } RTPROTECT_FLATTEN_END();

  // (0 + 10) * 2 + 5 = 25
  MT_CHECK(step_accumulator == 25);
}

MT_TEST(AntiTamper_Countermeasures_DynamicUpdatesAndEnforcement) {
  ResetCountermeasuresForTesting();

  // Initial clean policy
  RiskAssessment r;
  r.risk_score = 45;
  // Under default restrict threshold (50), risk 45 is permitted
  MT_CHECK(EnforceRiskPolicy(RiskAction::kRestrict, r));

  // Dynamically lower restriction threshold to 40 via countermeasure update
  std::vector<std::string> procs = { "nonexistent_hacker_tool_xyz.exe" };
  std::vector<std::string> windows = { "Nonexistent_Debug_Window_999" };
  ApplyCountermeasures(procs, windows, /*restrict_thresh=*/40, /*terminate_thresh=*/80);

  // Now risk 45 is restricted because threshold was dynamically tightened to 40
  MT_CHECK(!EnforceRiskPolicy(RiskAction::kRestrict, r));

  // Reset to restore baseline
  ResetCountermeasuresForTesting();
  MT_CHECK(EnforceRiskPolicy(RiskAction::kRestrict, r));
}

MT_MAIN()
