// antitamper/risk_policy.cpp

#include "antitamper/risk_policy.h"
#include "antitamper/anti_debug.h"
#include "antitamper/anti_dump.h"
#include "antitamper/env_detect.h"
#include "crypto/kdf.h"
#include "integrity/sha256.h"

#include <cstdlib>
#include <cstring>
#include <sstream>
#include <stdexcept>

namespace rtprotect::antitamper {

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

std::vector<std::uint8_t> DeriveRiskSalt(const RiskAssessment& assessment) {
  std::ostringstream ss;
  bool is_clean = (assessment.risk_score == 0 &&
                   !assessment.debugger_present &&
                   !assessment.remote_debugger_present &&
                   !assessment.hardware_breakpoints_detected &&
                   !assessment.timing_anomaly_detected &&
                   !assessment.memory_tampered &&
                   !assessment.memory_dump_detected &&
                   !assessment.memory_probing_detected);

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
       << ":probe=" << (assessment.memory_probing_detected ? 1 : 0);
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
  if (assessment.risk_score == 0 &&
      !assessment.debugger_present &&
      !assessment.remote_debugger_present &&
      !assessment.hardware_breakpoints_detected &&
      !assessment.timing_anomaly_detected &&
      !assessment.memory_tampered &&
      !assessment.memory_dump_detected &&
      !assessment.memory_probing_detected) {
    return 0;
  }

  auto salt = DeriveRiskSalt(assessment);
  std::uint64_t mask = 0;
  std::memcpy(&mask, salt.data(), sizeof(mask));
  return mask ? mask : 0xDEADBEEFCAFE1234ULL;
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
