// licensing/hardware_id.h
//
// Machine fingerprinting and hardware-bound licensing.
//
// Extracts stable hardware characteristics (CPU characteristics, system
// storage volume ID, operating system machine GUID, and hostname) and computes
// a weighted composite fingerprint.
//
// Designed to support tolerance for legitimate hardware drift (e.g. peripheral
// swaps or OS minor updates) while detecting attempts to share license files
// across distinct machines.

#pragma once

#include <string>

namespace rtprotect::licensing {

struct HardwareFingerprint {
  std::string cpu_component;       // Hashed CPU model & features
  std::string storage_component;   // Hashed volume GUID / serial
  std::string system_component;    // Hashed OS install / machine GUID
  std::string host_component;      // Hashed computer name
  std::string composite_id;        // 64-character hex digest
  bool cpu_probed_successfully = false;
  bool storage_probed_successfully = false;
  bool system_probed_successfully = false;
  bool host_probed_successfully = false;

  bool is_degraded() const {
    return !cpu_probed_successfully || !storage_probed_successfully ||
           !system_probed_successfully || !host_probed_successfully;
  }
};

struct HardwareSimilarityWeights {
  double cpu_weight = 0.25;
  double storage_weight = 0.25;
  double system_weight = 0.35;
  double host_weight = 0.15;
  double min_match_score = 0.75;
};

// Generates the hardware fingerprint for the local machine.
HardwareFingerprint GetLocalHardwareFingerprint();

// Convenience function returning the 64-char composite hex hardware ID.
std::string GetLocalHardwareId();

// Calculates similarity between two hardware ID strings (0.0 to 1.0).
// If exact string match, returns 1.0. If component breakdown matches
// a subset of metrics, returns proportional score using specified weights.
double ComputeHardwareSimilarity(const std::string& id_a,
                                 const std::string& id_b,
                                 const HardwareSimilarityWeights* weights = nullptr);

// Evaluates whether current hardware matches registered hardware under
// specified tolerance threshold (defaults to 0.75 or configured in weights).
bool VerifyHardwareMatch(const std::string& registered_hwid,
                         const std::string& current_hwid,
                         double min_score = 0.75,
                         const HardwareSimilarityWeights* weights = nullptr);

}  // namespace rtprotect::licensing
