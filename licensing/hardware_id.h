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
};

// Generates the hardware fingerprint for the local machine.
HardwareFingerprint GetLocalHardwareFingerprint();

// Convenience function returning the 64-char composite hex hardware ID.
std::string GetLocalHardwareId();

// Calculates similarity between two hardware ID strings (0.0 to 1.0).
// If exact string match, returns 1.0. If component breakdown matches
// a subset of metrics, returns proportional score.
double ComputeHardwareSimilarity(const std::string& id_a, const std::string& id_b);

// Evaluates whether current hardware matches registered hardware under
// specified tolerance threshold (defaults to 0.75).
bool VerifyHardwareMatch(const std::string& registered_hwid,
                         const std::string& current_hwid,
                         double min_score = 0.75);

}  // namespace rtprotect::licensing
