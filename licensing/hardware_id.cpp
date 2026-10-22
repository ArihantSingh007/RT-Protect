// licensing/hardware_id.cpp

#include "licensing/hardware_id.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>

#include <windows.h>
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif

#include <openssl/rand.h>

#include "integrity/sha256.h"
#include "tooling/file_io.h"

namespace rtprotect::licensing {

namespace {

std::string DigestToHex(const integrity::Sha256Digest& d) {
  char buf[65];
  for (std::size_t i = 0; i < 32; ++i) {
    std::snprintf(buf + i * 2, 3, "%02x", d[i]);
  }
  buf[64] = '\0';
  return std::string(buf);
}

std::string GetDeviceSeedPath() {
  namespace fs = std::filesystem;
  const char* local_app_data = std::getenv("LOCALAPPDATA");
  if (local_app_data && *local_app_data) {
    fs::path dir = fs::path(local_app_data) / "RTProtect";
    std::error_code ec;
    fs::create_directories(dir, ec);
    return (dir / "device.seed").string();
  }
  const char* app_data = std::getenv("APPDATA");
  if (app_data && *app_data) {
    fs::path dir = fs::path(app_data) / "RTProtect";
    std::error_code ec;
    fs::create_directories(dir, ec);
    return (dir / "device.seed").string();
  }
  return (fs::temp_directory_path() / ".rtprotect_device.seed").string();
}

std::vector<std::uint8_t> GetOrCreateDeviceSeed() {
  std::string seed_path = GetDeviceSeedPath();
  auto existing = rtprotect::tooling::ReadFile(seed_path);
  if (existing.has_value() && existing->size() >= 32) {
    return *existing;
  }
  std::vector<std::uint8_t> new_seed(32);
  if (RAND_bytes(new_seed.data(), 32) != 1) {
    auto t = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    std::memcpy(new_seed.data(), &t, sizeof(t));
  }
  if (!rtprotect::tooling::WriteSecretFile(seed_path, new_seed.data(), new_seed.size())) {
    // Write failed: re-read in case another process just created it in a race
    auto race_read = rtprotect::tooling::ReadFile(seed_path);
    if (race_read.has_value() && race_read->size() >= 32) {
      return *race_read;
    }
    // If unwritable and unreadable (e.g. read-only filesystem), derive a stable
    // deterministic seed from non-volatile OS identity so the fallback does not drift
    std::string stable_info = "RTProtect-StaticSeed:";
    const char* comp = std::getenv("COMPUTERNAME");
    const char* user = std::getenv("USERNAME");
    const char* sysroot = std::getenv("SystemRoot");
    stable_info += (comp ? comp : "Comp") + std::string(":") +
                   (user ? user : "User") + std::string(":") +
                   (sysroot ? sysroot : "C:\\Windows");
    auto digest = integrity::Sha256(reinterpret_cast<const std::uint8_t*>(stable_info.data()), stable_info.size());
    if (digest.has_value()) {
      return std::vector<std::uint8_t>(digest->begin(), digest->end());
    }
  }
  return new_seed;
}

std::string GenerateProbeFallbackEntropy(const std::string& probe_name) {
  auto seed = GetOrCreateDeviceSeed();
  std::string data = "RTProtect-ProbeFallback:" + probe_name + ":" +
                     std::string(reinterpret_cast<const char*>(seed.data()), seed.size());
  auto d = integrity::Sha256(reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
  if (d.has_value()) {
    return "MachineSeed:" + DigestToHex(*d).substr(0, 16);
  }
  return "MachineSeed:LocalEntropy";
}

std::string HashString(const std::string& input) {
  auto d = integrity::Sha256(reinterpret_cast<const std::uint8_t*>(input.data()), input.size());
  if (!d.has_value()) {
    // Avoid deterministic zeros on hash error (RTP-SEC Finding 1b)
    auto seed = GetOrCreateDeviceSeed();
    std::string fallback = input + ":" + std::string(reinterpret_cast<const char*>(seed.data()), seed.size());
    auto d2 = integrity::Sha256(reinterpret_cast<const std::uint8_t*>(fallback.data()), fallback.size());
    if (d2.has_value()) return DigestToHex(*d2);
    return DigestToHex(integrity::Sha256Digest{});
  }
  return DigestToHex(*d);
}

std::string GetCpuInfo(bool* out_success) {
  std::ostringstream ss;
  bool success = false;
  int cpu_info[4] = {0};
#if defined(_MSC_VER)
  __cpuid(cpu_info, 0);
#else
  __cpuid(0, cpu_info[0], cpu_info[1], cpu_info[2], cpu_info[3]);
#endif
  char vendor[13] = {0};
  std::memcpy(vendor, &cpu_info[1], 4);
  std::memcpy(vendor + 4, &cpu_info[3], 4);
  std::memcpy(vendor + 8, &cpu_info[2], 4);
  ss << vendor;

#if defined(_MSC_VER)
  __cpuid(cpu_info, 1);
#else
  __cpuid(1, cpu_info[0], cpu_info[1], cpu_info[2], cpu_info[3]);
#endif
  ss << ":" << cpu_info[0] << ":" << cpu_info[3];
  success = true;

  if (out_success) *out_success = success;
  if (!success) {
    return GenerateProbeFallbackEntropy("CPU");
  }
  return ss.str();
}

std::string GetStorageInfo(bool* out_success) {
  std::ostringstream ss;
  bool success = false;
  DWORD serial = 0;
  if (GetVolumeInformationA("C:\\", nullptr, 0, &serial, nullptr, nullptr, nullptr, 0) && serial != 0) {
    ss << "VolSerial:" << serial;
    success = true;
  }

  if (out_success) *out_success = success;
  if (!success) {
    return GenerateProbeFallbackEntropy("Storage");
  }
  return ss.str();
}

std::string GetSystemInfo(bool* out_success) {
  std::ostringstream ss;
  bool success = false;
  HKEY hKey = nullptr;
  if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
    char guid[128] = {0};
    DWORD len = sizeof(guid) - 1;
    if (RegQueryValueExA(hKey, "MachineGuid", nullptr, nullptr, reinterpret_cast<LPBYTE>(guid), &len) == ERROR_SUCCESS && len > 0) {
      ss << guid;
      success = true;
    }
    RegCloseKey(hKey);
  }

  if (out_success) *out_success = success;
  if (!success) {
    return GenerateProbeFallbackEntropy("System");
  }
  return ss.str();
}

std::string GetHostInfo(bool* out_success) {
  char name[256] = {0};
  DWORD len = sizeof(name) - 1;
  if (GetComputerNameA(name, &len) && len > 0) {
    if (out_success) *out_success = true;
    return std::string(name);
  }

  if (out_success) *out_success = false;
  return GenerateProbeFallbackEntropy("Host");
}

}  // namespace

HardwareFingerprint GetLocalHardwareFingerprint() {
  HardwareFingerprint fp;
  fp.cpu_component = HashString(GetCpuInfo(&fp.cpu_probed_successfully)).substr(0, 16);
  fp.storage_component = HashString(GetStorageInfo(&fp.storage_probed_successfully)).substr(0, 16);
  fp.system_component = HashString(GetSystemInfo(&fp.system_probed_successfully)).substr(0, 16);
  fp.host_component = HashString(GetHostInfo(&fp.host_probed_successfully)).substr(0, 16);

  std::string composite_raw = fp.cpu_component + "-" +
                              fp.storage_component + "-" +
                              fp.system_component + "-" +
                              fp.host_component;
  fp.composite_id = HashString(composite_raw);
  return fp;
}

std::string GetLocalHardwareId() {
  auto fp = GetLocalHardwareFingerprint();
  // Formatted as composite string: CPU:STORAGE:SYSTEM:HOST-HASH16
  return fp.cpu_component + ":" + fp.storage_component + ":" + fp.system_component + ":" + fp.host_component + "-" + fp.composite_id.substr(0, 16);
}

double ComputeHardwareSimilarity(const std::string& id_a,
                                 const std::string& id_b,
                                 const HardwareSimilarityWeights* weights) {
  if (id_a.empty() || id_b.empty()) return 0.0;
  if (id_a == id_b) return 1.0;

  HardwareSimilarityWeights w;
  if (weights) w = *weights;

  // Split into components separated by ':' or '-'
  auto split_components = [](const std::string& s) -> std::vector<std::string> {
    std::vector<std::string> parts;
    std::string token;
    for (char c : s) {
      if (c == ':' || c == '-') {
        if (!token.empty()) {
          parts.push_back(token);
          token.clear();
        }
      } else {
        token.push_back(c);
      }
    }
    if (!token.empty()) parts.push_back(token);
    return parts;
  };

  auto parts_a = split_components(id_a);
  auto parts_b = split_components(id_b);

  if (parts_a.size() < 4 || parts_b.size() < 4) {
    return id_a == id_b ? 1.0 : 0.0;
  }

  double total_weight = w.cpu_weight + w.storage_weight + w.system_weight + w.host_weight;
  if (total_weight <= 0.0) total_weight = 1.0;

  double score = 0.0;
  if (parts_a[0] == parts_b[0]) score += w.cpu_weight;
  if (parts_a[1] == parts_b[1]) score += w.storage_weight;
  if (parts_a[2] == parts_b[2]) score += w.system_weight;
  if (parts_a[3] == parts_b[3]) score += w.host_weight;

  return score / total_weight;
}

bool VerifyHardwareMatch(const std::string& registered_hwid,
                         const std::string& current_hwid,
                         double min_score,
                         const HardwareSimilarityWeights* weights) {
  if (registered_hwid.empty()) return true;  // License is not machine-bound
  double sim = ComputeHardwareSimilarity(registered_hwid, current_hwid, weights);
  double effective_min = weights ? weights->min_match_score : min_score;
  return sim >= effective_min;
}

}  // namespace rtprotect::licensing
