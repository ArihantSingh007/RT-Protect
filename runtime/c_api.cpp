#include "runtime/c_api.h"
#include "antitamper/risk_policy.h"
#include "integrity/verifier.h"
#include "integrity/manifest.h"
#include "licensing/hardware_id.h"
#include "licensing/license.h"
#include "licensing/license_verifier.h"
#include "tooling/file_io.h"

#include <atomic>
#include <cstring>
#include <ctime>
#include <stdexcept>
#include <string>

namespace {
std::atomic<int> g_fault_injection_mode{0};
}

extern "C" {

RTPROTECT_API void rtprotect_set_fault_injection_for_testing(int fault_mode) {
  g_fault_injection_mode.store(fault_mode, std::memory_order_relaxed);
}

RTPROTECT_API int rtprotect_get_hardware_id(char* buffer, int buffer_len) {
  try {
    if (g_fault_injection_mode.load(std::memory_order_relaxed) == 2) {
      throw std::runtime_error("Simulated hardware ID query fault");
    }
    if (!buffer || buffer_len <= 0) return -1;
    std::string hwid = rtprotect::licensing::GetLocalHardwareId();
    if (hwid.empty()) return -1;
    if (static_cast<int>(hwid.length()) >= buffer_len) {
      std::memcpy(buffer, hwid.data(), buffer_len - 1);
      buffer[buffer_len - 1] = '\0';
      return buffer_len - 1;
    }
    std::memcpy(buffer, hwid.data(), hwid.length());
    buffer[hwid.length()] = '\0';
    return static_cast<int>(hwid.length());
  } catch (...) {
    if (buffer && buffer_len > 0) {
      buffer[0] = '\0';
    }
    return -1;
  }
}

RTPROTECT_API double rtprotect_assess_environment_risk(void) {
  try {
    if (g_fault_injection_mode.load(std::memory_order_relaxed) == 1) {
      throw std::runtime_error("Simulated HKDF/CSPRNG failure during risk evaluation");
    }
    auto assessment = rtprotect::antitamper::AssessEnvironmentRisk();
    double normalized = static_cast<double>(assessment.risk_score) / 100.0;
    if (normalized < 0.0) normalized = 0.0;
    if (normalized > 1.0) normalized = 1.0;
    return normalized;
  } catch (...) {
    return -1.0;
  }
}

RTPROTECT_API int rtprotect_verify_manifest(const char* manifest_path, const uint8_t* pub_key) {
  try {
    if (g_fault_injection_mode.load(std::memory_order_relaxed) == 3) {
      throw std::runtime_error("Simulated cryptographic failure during manifest verification");
    }
    if (!manifest_path || !pub_key) return 0;
    std::string mpath(manifest_path);
    std::string spath = mpath + ".sig";
    auto mbytes = rtprotect::tooling::ReadFile(mpath);
    auto sbytes = rtprotect::tooling::ReadFile(spath);
    if (!mbytes.has_value() || !sbytes.has_value() || sbytes->size() != rtprotect::integrity::kEd25519SignatureLen) {
      return 0;
    }
    rtprotect::integrity::Ed25519Signature sig{};
    std::memcpy(sig.data(), sbytes->data(), rtprotect::integrity::kEd25519SignatureLen);
    rtprotect::integrity::Ed25519PublicKey pk{};
    std::memcpy(pk.data(), pub_key, rtprotect::integrity::kEd25519PublicKeyLen);
    return rtprotect::integrity::VerifyManifestSignature(*mbytes, sig, pk) ? 1 : 0;
  } catch (...) {
    return 0;
  }
}

RTPROTECT_API int rtprotect_verify_license(const char* license_path, const uint8_t* pub_key, const char* expected_product_id) {
  try {
    if (g_fault_injection_mode.load(std::memory_order_relaxed) == 4) {
      throw std::runtime_error("Simulated parser/crypto failure during license validation");
    }
    if (!license_path || !pub_key || !expected_product_id) return 0;
    auto lbytes = rtprotect::tooling::ReadFile(license_path);
    if (!lbytes.has_value()) return 0;

    rtprotect::licensing::LicenseVerificationContext ctx;
    ctx.current_time = static_cast<std::uint64_t>(std::time(nullptr));
    ctx.expected_product_id = expected_product_id;
    ctx.current_hardware_id = rtprotect::licensing::GetLocalHardwareId();
    ctx.reject_degraded_hardware = false;

    rtprotect::integrity::Ed25519PublicKey pk{};
    std::memcpy(pk.data(), pub_key, rtprotect::integrity::kEd25519PublicKeyLen);

    rtprotect::licensing::License lic;
    auto status = rtprotect::licensing::VerifyLicenseBytes(lbytes->data(), lbytes->size(), pk, ctx, &lic);
    return (status == rtprotect::licensing::LicenseStatus::kValid) ? 1 : 0;
  } catch (...) {
    return 0;
  }
}

}
