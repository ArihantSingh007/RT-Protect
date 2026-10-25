// antitamper/risk_policy.cpp

#include "antitamper/risk_policy.h"
#include "antitamper/anti_debug.h"
#include "antitamper/anti_dump.h"
#include "antitamper/dynamic_import.h"
#include "antitamper/env_detect.h"
#include "bytecode_vm/builder.h"
#include "bytecode_vm/opcode_map.h"
#include "bytecode_vm/vm.h"
#include "crypto/kdf.h"
#include "integrity/sha256.h"

#include <cctype>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>
#include <windows.h>
#include <tlhelp32.h>

namespace rtprotect::antitamper {

namespace {

std::mutex s_cm_mutex;
std::vector<std::string> s_active_blacklisted_procs;
std::vector<std::string> s_active_blacklisted_windows;
int s_restrict_thresh = 50;
int s_terminate_thresh = 80;
std::uint64_t s_cm_expires_at = 0;

bool CheckBlacklistedProcesses(const std::vector<std::string>& procs) {
  if (procs.empty()) return false;
  auto pCreateToolhelp32Snapshot = ResolveApi<HANDLE(WINAPI*)(DWORD, DWORD)>(kHashKernel32, kHashCreateToolhelp32Snapshot);
  auto pProcess32First = ResolveApi<BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32)>(kHashKernel32, HashApi("Process32First"));
  auto pProcess32Next = ResolveApi<BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32)>(kHashKernel32, HashApi("Process32Next"));
  auto pCloseHandle = ResolveApi<BOOL(WINAPI*)(HANDLE)>(kHashKernel32, kHashCloseHandle);

  if (!pCreateToolhelp32Snapshot || !pProcess32First || !pProcess32Next || !pCloseHandle) return false;

  HANDLE hSnap = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnap == INVALID_HANDLE_VALUE) return false;

  PROCESSENTRY32 pe{};
  pe.dwSize = sizeof(pe);

  bool found = false;
  if (pProcess32First(hSnap, &pe)) {
    do {
      std::string exe = pe.szExeFile;
      for (char& c : exe) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      for (const auto& bl : procs) {
        std::string bl_lower = bl;
        for (char& c : bl_lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (exe == bl_lower || exe.find(bl_lower) != std::string::npos) {
          found = true;
          break;
        }
      }
      if (found) break;
    } while (pProcess32Next(hSnap, &pe));
  }
  pCloseHandle(hSnap);
  return found;
}

bool CheckBlacklistedWindows(const std::vector<std::string>& titles) {
  if (titles.empty()) return false;
  auto pFindWindowA = ResolveApi<HWND(WINAPI*)(LPCSTR, LPCSTR)>(kHashUser32, HashApi("FindWindowA"));
  if (!pFindWindowA) return false;
  for (const auto& title : titles) {
    if (pFindWindowA(nullptr, title.c_str()) != nullptr) {
      return true;
    }
  }
  return false;
}

}  // namespace

void ApplyCountermeasures(const std::vector<std::string>& blacklisted_procs,
                          const std::vector<std::string>& blacklisted_windows,
                          int restrict_thresh,
                          int terminate_thresh,
                          std::uint64_t expires_at) {
  std::lock_guard<std::mutex> lock(s_cm_mutex);
  s_active_blacklisted_procs = blacklisted_procs;
  s_active_blacklisted_windows = blacklisted_windows;
  s_restrict_thresh = restrict_thresh;
  s_terminate_thresh = terminate_thresh;
  s_cm_expires_at = expires_at;
}

void ResetCountermeasuresForTesting() {
  std::lock_guard<std::mutex> lock(s_cm_mutex);
  s_active_blacklisted_procs.clear();
  s_active_blacklisted_windows.clear();
  s_restrict_thresh = 50;
  s_terminate_thresh = 80;
  s_cm_expires_at = 0;
}

RiskAssessment AssessEnvironmentRisk() {
  RiskAssessment r;
  r.debugger_present = CheckDebuggerPresent();
  r.remote_debugger_present = CheckRemoteDebugger();
  r.hardware_breakpoints_detected = CheckHardwareBreakpoints() || IsHardwareBreakpointDetected();
  r.timing_anomaly_detected = CheckExecutionTimingAnomaly();
  r.hypervisor_detected = CheckHypervisorPresent();
  r.memory_tampered = CheckMemoryTampered();
  r.memory_dump_detected = DetectMemoryDumper();
  r.memory_probing_detected = DetectMemoryProbing();
  if (r.hypervisor_detected) {
    r.hypervisor_vendor = GetHypervisorVendor();
  }

  int score = 0;
  if (r.debugger_present || r.remote_debugger_present) {
    score += 40;
    // Small corroboration bump if both distinct indicators hit
    if (r.debugger_present && r.remote_debugger_present) {
      score += 10;
    }
  }
  if (r.hardware_breakpoints_detected) score += 50;
  if (r.timing_anomaly_detected) score += 30;
  if (r.memory_tampered) score += 40;
  if (r.memory_dump_detected) score += 40;
  if (r.memory_probing_detected) score += 30;
  if (r.hypervisor_detected) score += 15; // Low risk by itself to avoid penalizing legitimate VMs

  {
    std::lock_guard<std::mutex> lock(s_cm_mutex);
    std::uint64_t now = static_cast<std::uint64_t>(std::time(nullptr));
    if (s_cm_expires_at != 0 && s_cm_expires_at < now) {
      s_active_blacklisted_procs.clear();
      s_active_blacklisted_windows.clear();
      s_restrict_thresh = 50;
      s_terminate_thresh = 80;
      s_cm_expires_at = 0;
    }
    if (!s_active_blacklisted_procs.empty() && CheckBlacklistedProcesses(s_active_blacklisted_procs)) {
      r.blacklisted_process_detected = true;
      score += 50;
    }
    if (!s_active_blacklisted_windows.empty() && CheckBlacklistedWindows(s_active_blacklisted_windows)) {
      r.blacklisted_window_detected = true;
      score += 50;
    }
  }

  if (score > 100) score = 100;
  r.risk_score = score;
  return r;
}

RiskAssessment AssessFastEnvironmentRisk() {
  RiskAssessment r;
  r.debugger_present = CheckDebuggerPresent();
  r.remote_debugger_present = CheckRemoteDebugger();
  r.hardware_breakpoints_detected = IsHardwareBreakpointDetected();
  r.timing_anomaly_detected = CheckExecutionTimingAnomaly();
  r.hypervisor_detected = CheckHypervisorPresent();
  r.memory_tampered = CheckMemoryTampered();
  r.memory_dump_detected = DetectMemoryDumper();
  r.memory_probing_detected = DetectMemoryProbing();
  if (r.hypervisor_detected) {
    r.hypervisor_vendor = GetHypervisorVendor();
  }

  int score = 0;
  if (r.debugger_present || r.remote_debugger_present) {
    score += 40;
    if (r.debugger_present && r.remote_debugger_present) {
      score += 10;
    }
  }
  if (r.hardware_breakpoints_detected) score += 50;
  if (r.timing_anomaly_detected) score += 30;
  if (r.memory_tampered) score += 40;
  if (r.memory_dump_detected) score += 40;
  if (r.memory_probing_detected) score += 30;
  if (r.hypervisor_detected) score += 15;

  {
    std::lock_guard<std::mutex> lock(s_cm_mutex);
    std::uint64_t now = static_cast<std::uint64_t>(std::time(nullptr));
    if (s_cm_expires_at != 0 && s_cm_expires_at < now) {
      s_active_blacklisted_procs.clear();
      s_active_blacklisted_windows.clear();
      s_restrict_thresh = 50;
      s_terminate_thresh = 80;
      s_cm_expires_at = 0;
    }
    if (!s_active_blacklisted_procs.empty() && CheckBlacklistedProcesses(s_active_blacklisted_procs)) {
      r.blacklisted_process_detected = true;
      score += 50;
    }
    if (!s_active_blacklisted_windows.empty() && CheckBlacklistedWindows(s_active_blacklisted_windows)) {
      r.blacklisted_window_detected = true;
      score += 50;
    }
  }

  if (score > 100) score = 100;
  r.risk_score = score;
  return r;
}

bool EnforceRiskPolicy(RiskAction action, const RiskAssessment& assessment) {
  int restrict_th = 50;
  int terminate_th = 80;
  {
    std::lock_guard<std::mutex> lock(s_cm_mutex);
    restrict_th = s_restrict_thresh;
    terminate_th = s_terminate_thresh;
  }
  switch (action) {
    case RiskAction::kReportOnly:
      return true;

    case RiskAction::kRestrict:
      return assessment.risk_score < restrict_th;

    case RiskAction::kTerminate:
      if (assessment.risk_score >= terminate_th) {
        std::exit(1);
      }
      return true;
  }
  return true;
}

bool IsEnvironmentCleanOrLegitimateHypervisor(const RiskAssessment& risk) {
  const bool no_strong_tamper_signal = !risk.debugger_present &&
      !risk.remote_debugger_present && !risk.hardware_breakpoints_detected &&
      !risk.timing_anomaly_detected && !risk.memory_tampered &&
      !risk.memory_dump_detected && !risk.memory_probing_detected &&
      !risk.blacklisted_process_detected && !risk.blacklisted_window_detected;
  const bool only_low_risk_hypervisor = risk.hypervisor_detected &&
      risk.risk_score == 15 && no_strong_tamper_signal;
  return no_strong_tamper_signal &&
      (risk.risk_score == 0 || only_low_risk_hypervisor);
}

std::vector<std::uint8_t> DeriveRiskSalt(const RiskAssessment& assessment) {
  std::ostringstream ss;
  bool is_clean = IsEnvironmentCleanOrLegitimateHypervisor(assessment);

  if (is_clean) {
    ss << "RTProtect-AntiTamper-Baseline-Clean-Salt-v2";
  } else {
    // Poison the salt deterministically based on risk metrics
    ss << "RTProtect-AntiTamper-Poisoned-Salt-v2:"
       << "score=" << assessment.risk_score
       << ":dbg=" << (assessment.debugger_present ? 1 : 0)
       << ":rdbg=" << (assessment.remote_debugger_present ? 1 : 0)
       << ":hwbp=" << (assessment.hardware_breakpoints_detected ? 1 : 0)
       << ":time=" << (assessment.timing_anomaly_detected ? 1 : 0)
       << ":mem=" << (assessment.memory_tampered ? 1 : 0)
       << ":dump=" << (assessment.memory_dump_detected ? 1 : 0)
       << ":probe=" << (assessment.memory_probing_detected ? 1 : 0)
       << ":blproc=" << (assessment.blacklisted_process_detected ? 1 : 0)
       << ":blwin=" << (assessment.blacklisted_window_detected ? 1 : 0);
  }

  std::string s = ss.str();
  auto digest = integrity::Sha256(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
  if (!digest.has_value()) {
    return std::vector<std::uint8_t>(32, 0xEE);
  }
  return std::vector<std::uint8_t>(digest->begin(), digest->end());
}

crypto::Aes256Key DeriveTamperBoundKey(const crypto::Aes256Key& master_secret,
                                       const RiskAssessment& assessment,
                                       const std::string& context_info) {
  auto salt = DeriveRiskSalt(assessment);
  std::string info = "rtprotect/tamper-bound-key/" + context_info;

  auto derived = crypto::Hkdf::DeriveKey(master_secret.bytes(), salt, info, crypto::kAes256KeyLen);
  if (!derived.has_value()) {
    throw std::runtime_error("DeriveTamperBoundKey: HKDF derivation failed");
  }

  auto key = crypto::Aes256Key::FromBytes(derived->data(), derived->size());
  if (!key.has_value()) {
    throw std::runtime_error("DeriveTamperBoundKey: internal key error");
  }

  return std::move(*key);
}

std::uint64_t DeriveTamperPerturbation(const RiskAssessment& assessment) {
  if (IsEnvironmentCleanOrLegitimateHypervisor(assessment)) {
    return 0;
  }

  auto salt = DeriveRiskSalt(assessment);
  std::uint64_t mask = 0;
  std::memcpy(&mask, salt.data(), sizeof(mask));
  return mask ? mask : 0xDEADBEEFCAFE1234ULL;
}

std::uint64_t FoldTamperStateDelta(const RiskAssessment& risk, std::uint64_t salt) {
  if (IsEnvironmentCleanOrLegitimateHypervisor(risk)) {
    return 0;
  }
  std::uint64_t perturb = DeriveTamperPerturbation(risk);
  std::uint64_t h = (perturb ^ salt) * 0x9E3779B97F4A7C15ULL + 0x123456789ABCDEF1ULL;
  return h ? h : 0x42ULL;
}

std::uint64_t FoldTamperStateMask(const RiskAssessment& risk, std::uint64_t salt) {
  if (IsEnvironmentCleanOrLegitimateHypervisor(risk)) {
    return 0;
  }
  std::uint64_t perturb = DeriveTamperPerturbation(risk);
  std::uint64_t m = (perturb ^ (salt * 0x517cc1b727220a95ULL));
  return m ? m : 0x0F0F0F0F0F0F0F0FULL;
}

namespace {

std::int64_t NativeProbePebFn(std::int64_t, void*) {
  return CheckDebuggerPresent() ? 1 : 0;
}
std::int64_t NativeProbeDebugPortFn(std::int64_t, void*) {
  return CheckRemoteDebugger() ? 1 : 0;
}
std::int64_t NativeProbeHwBreakpointsFn(std::int64_t, void*) {
  return IsHardwareBreakpointDetected() ? 1 : 0;
}
std::int64_t NativeProbeTimingFn(std::int64_t, void*) {
  return CheckExecutionTimingAnomaly() ? 1 : 0;
}
std::int64_t NativeProbeMemoryHooksFn(std::int64_t, void*) {
  return CheckMemoryTampered() ? 1 : 0;
}
std::int64_t NativeProbeAntiDumpFn(std::int64_t, void*) {
  return (DetectMemoryDumper() || DetectMemoryProbing()) ? 1 : 0;
}

const vm::NativeFunctionTable* GetGlobalAntiTamperNativeTable() {
  static const auto table = []() {
    auto t = std::make_unique<vm::NativeFunctionTable>();
    t->Register(kNativeProbePeb, NativeProbePebFn);
    t->Register(kNativeProbeDebugPort, NativeProbeDebugPortFn);
    t->Register(kNativeProbeHwBreakpoints, NativeProbeHwBreakpointsFn);
    t->Register(kNativeProbeTiming, NativeProbeTimingFn);
    t->Register(kNativeProbeMemoryHooks, NativeProbeMemoryHooksFn);
    t->Register(kNativeProbeAntiDump, NativeProbeAntiDumpFn);
    return t;
  }();
  return table.get();
}

vm::Program BuildVirtualizedRiskAssessor(std::uint32_t seed) {
  // Generates randomized check sequencing to defeat signature matching
  vm::ProgramBuilder b(1);

  struct ProbeSpec {
    std::uint16_t id;
    std::int64_t weight;
  };
  std::vector<ProbeSpec> probes = {
    {kNativeProbePeb, 35},
    {kNativeProbeDebugPort, 35},
    {kNativeProbeHwBreakpoints, 25},
    {kNativeProbeTiming, 15},
    {kNativeProbeMemoryHooks, 30},
    {kNativeProbeAntiDump, 25}
  };

  // Fisher-Yates permutation based on build seed
  std::uint32_t rng = seed;
  for (std::size_t i = probes.size() - 1; i > 0; --i) {
    rng = rng * 1664525u + 1013904223u;
    std::size_t j = rng % (i + 1);
    std::swap(probes[i], probes[j]);
  }

  // Local 0 = cumulative risk score
  b.PushConst(0);
  b.StoreLocal(0);

  for (const auto& probe : probes) {
    b.PushConst(0); // argument
    b.CallNative(probe.id);
    b.PushConst(probe.weight);
    b.Mul();
    b.PushLocal(0);
    b.Add();
    b.StoreLocal(0);
  }

  b.PushLocal(0);
  b.Ret();
  return b.Build();
}

}  // namespace

const void* GetAntiTamperNativeTableVoid() {
  return GetGlobalAntiTamperNativeTable();
}

RiskAssessment AssessEnvironmentRiskVirtualized(const void* opcode_map, std::uint32_t seed) {
  RiskAssessment assessment;

  // Build and execute virtualized detection program
  auto prog = BuildVirtualizedRiskAssessor(seed);
  const auto* map = static_cast<const vm::OpcodeMap*>(opcode_map);
  const auto* native_table = GetGlobalAntiTamperNativeTable();

  // Pick one of the four engines dynamically based on seed
  auto flavor = static_cast<vm::VmEngineFlavor>(seed % 4);
  auto res = vm::Run(prog, {0}, map, nullptr, flavor, 0, native_table);

  if (res.error == vm::VmError::kNone) {
    int score = static_cast<int>(res.value);
    if (score > 100) score = 100;
    if (score < 0) score = 0;
    assessment.risk_score = score;
  } else {
    // If virtualized evaluation itself was faulted or tampered, fail-closed
    assessment.risk_score = 100;
  }

  assessment.debugger_present = CheckDebuggerPresent();
  assessment.remote_debugger_present = CheckRemoteDebugger();
  assessment.hardware_breakpoints_detected = IsHardwareBreakpointDetected();
  assessment.timing_anomaly_detected = CheckExecutionTimingAnomaly();
  assessment.memory_tampered = CheckMemoryTampered();
  assessment.memory_dump_detected = DetectMemoryDumper();
  assessment.memory_probing_detected = DetectMemoryProbing();

  return assessment;
}

namespace {
std::mutex g_cross_link_mu;
std::unordered_map<std::uint64_t, std::uint64_t> g_cross_link_tokens;
}

void FunctionCrossLink::DepositToken(std::uint64_t function_id, std::uint64_t token) {
  std::lock_guard<std::mutex> lock(g_cross_link_mu);
  g_cross_link_tokens[function_id] = token;
}

bool FunctionCrossLink::VerifyToken(std::uint64_t function_id, std::uint64_t expected_token) {
  std::lock_guard<std::mutex> lock(g_cross_link_mu);
  auto it = g_cross_link_tokens.find(function_id);
  if (it == g_cross_link_tokens.end()) return false;
  return it->second == expected_token;
}

void FunctionCrossLink::ResetForTesting() {
  std::lock_guard<std::mutex> lock(g_cross_link_mu);
  g_cross_link_tokens.clear();
}

void ScatterTamperCheck(const char* checkpoint_name, std::uint64_t* inout_state_accumulator) {
  if (!inout_state_accumulator) return;

  // Run lightweight low-overhead checks (sub-microsecond, zero thread spawning)
  bool dbg = CheckDebuggerPresent();
  bool mem = CheckMemoryTampered();
  bool timing = CheckExecutionTimingAnomaly();
  bool hw_bp = IsHardwareBreakpointDetected();
  bool dumper = DetectMemoryDumper();
  bool probing = DetectMemoryProbing();

  if (dbg || mem || timing || hw_bp || dumper || probing) {
    // Fold non-zero poison into accumulator
    std::uint64_t poison = 0x9E3779B97F4A7C15ULL;
    if (checkpoint_name) {
      for (const char* p = checkpoint_name; *p; ++p) {
        poison = (poison ^ static_cast<std::uint64_t>(*p)) * 1099511628211ULL;
      }
    }
    *inout_state_accumulator ^= poison;
  }
}

}  // namespace rtprotect::antitamper
