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
//
// In addition to boolean enforcement, this module provides cryptographic tamper-bound
// key derivation (DeriveTamperBoundKey) and state perturbation (DeriveTamperPerturbation)
// to eliminate single-point-of-failure patchable branches.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "crypto/aead.h"

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

// Fast, zero-thread environment risk assessment designed for per-invocation checks in hot paths.
// Evaluates PEB/NtQuery debugger flags, memory tampering, timing anomaly, and cached
// hardware breakpoint signals without spawning helper threads.
RiskAssessment AssessFastEnvironmentRisk();

// Applies the configured risk action based on assessment results.
// If action is kTerminate and risk exceeds threshold, cleanly exits with code 1.
// Returns true if execution is permitted to proceed, false if restricted.
bool EnforceRiskPolicy(RiskAction action, const RiskAssessment& assessment);

// Derives a cryptographic salt bound to the risk assessment state.
// When assessment is clean (risk_score == 0), outputs a canonical clean baseline salt.
// When tampering or debugging is present, outputs a mutated/poisoned salt.
std::vector<std::uint8_t> DeriveRiskSalt(const RiskAssessment& assessment);

// Cryptographically binds key derivation to anti-tamper state (RTP-SEC Finding 2).
// Instead of a single patchable boolean gate (std::exit), sensitive operations (such as
// decrypting virtualized bytecode, verifying integrity tags, or decrypting strings)
// derive their cryptographic key through HKDF using the risk salt.
// If an attacker attaches a debugger or patches code, the derived key is poisoned,
// causing AEAD authentication to fail or bytecode to desynchronize silently.
crypto::Aes256Key DeriveTamperBoundKey(const crypto::Aes256Key& master_secret,
                                       const RiskAssessment& assessment,
                                       const std::string& context_info);

// Returns 0 if execution environment is clean; returns a non-zero pseudorandom perturbation
// mask if tampering/debugging is detected. Used to silently desynchronize VM states without exits.
std::uint64_t DeriveTamperPerturbation(const RiskAssessment& assessment);

// Performs a lightweight scattered check and folds the risk into an inout accumulator.
// Designed to be scattered across multiple generated functions/stubs.
void ScatterTamperCheck(const char* checkpoint_name, std::uint64_t* inout_state_accumulator);

}  // namespace rtprotect::antitamper
