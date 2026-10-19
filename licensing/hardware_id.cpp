// licensing/hardware_id.cpp

#include "licensing/hardware_id.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <vector>

#include "integrity/sha256.h"

#if defined(_WIN32)
#include <windows.h>
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif
#else
#include <unistd.h>
#include <fstream>
#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#endif
#endif

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

std::string HashString(const std::string& input) {
  auto d = integrity::Sha256(reinterpret_cast<const std::uint8_t*>(input.data()), input.size());
  if (!d.has_value()) return std::string(64, '0');
  return DigestToHex(*d);
}

std::string GetCpuInfo() {
  std::ostringstream ss;
#if defined(_WIN32)
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
#elif defined(__x86_64__) || defined(__i386__)
  unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
  if (__get_cpuid(0, &eax, &ebx, &ecx, &edx)) {
    char vendor[13] = {0};
    std::memcpy(vendor, &ebx, 4);
    std::memcpy(vendor + 4, &edx, 4);
    std::memcpy(vendor + 8, &ecx, 4);
    ss << vendor;
  }
  if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
    ss << ":" << eax << ":" << edx;
  }
#else
  ss << "Generic-CPU-Architecture";
#endif
  return ss.str();
}

std::string GetStorageInfo() {
  std::ostringstream ss;
#if defined(_WIN32)
  DWORD serial = 0;
  if (GetVolumeInformationA("C:\\", nullptr, 0, &serial, nullptr, nullptr, nullptr, 0)) {
    ss << "VolSerial:" << serial;
  } else {
    ss << "VolSerial:DefaultVolume";
  }
#else
  std::ifstream f("/etc/fstab");
  std::string line;
  if (f && std::getline(f, line)) {
    ss << line;
  } else {
    ss << "POSIX-Root-Filesystem";
  }
#endif
  return ss.str();
}

std::string GetSystemInfo() {
  std::ostringstream ss;
#if defined(_WIN32)
  HKEY hKey = nullptr;
  if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
    char guid[128] = {0};
    DWORD len = sizeof(guid) - 1;
    if (RegQueryValueExA(hKey, "MachineGuid", nullptr, nullptr, reinterpret_cast<LPBYTE>(guid), &len) == ERROR_SUCCESS) {
      ss << guid;
    }
    RegCloseKey(hKey);
  }
  if (ss.str().empty()) {
    ss << "Windows-Fallback-System-ID";
  }
#else
  std::ifstream f("/etc/machine-id");
  std::string mid;
  if (f && std::getline(f, mid) && !mid.empty()) {
    ss << mid;
  } else {
    std::ifstream f2("/var/lib/dbus/machine-id");
    if (f2 && std::getline(f2, mid) && !mid.empty()) {
      ss << mid;
    } else {
      ss << "Linux-Fallback-Machine-ID";
    }
  }
#endif
  return ss.str();
}

std::string GetHostInfo() {
  char name[256] = {0};
#if defined(_WIN32)
  DWORD len = sizeof(name) - 1;
  if (GetComputerNameA(name, &len)) {
    return std::string(name);
  }
#else
  if (gethostname(name, sizeof(name) - 1) == 0) {
    return std::string(name);
  }
#endif
  return "DefaultHostname";
}

}  // namespace

HardwareFingerprint GetLocalHardwareFingerprint() {
  HardwareFingerprint fp;
  fp.cpu_component = HashString(GetCpuInfo()).substr(0, 16);
  fp.storage_component = HashString(GetStorageInfo()).substr(0, 16);
  fp.system_component = HashString(GetSystemInfo()).substr(0, 16);
  fp.host_component = HashString(GetHostInfo()).substr(0, 16);

  std::string composite_raw = fp.cpu_component + "-" +
                              fp.storage_component + "-" +
                              fp.system_component + "-" +
                              fp.host_component;
  fp.composite_id = HashString(composite_raw);
  return fp;
}

std::string GetLocalHardwareId() {
  auto fp = GetLocalHardwareFingerprint();
  // Formatted as composite string: CPU:STORAGE:SYSTEM:HOST-HASH64
  return fp.cpu_component + ":" + fp.storage_component + ":" + fp.system_component + ":" + fp.host_component + "-" + fp.composite_id.substr(0, 16);
}

double ComputeHardwareSimilarity(const std::string& id_a, const std::string& id_b) {
  if (id_a.empty() || id_b.empty()) return 0.0;
  if (id_a == id_b) return 1.0;

  // Split into components separated by ':'
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

  // Weightings:
  // CPU: 0.25, Storage: 0.25, System install GUID: 0.35, Hostname: 0.15
  double score = 0.0;
  if (parts_a[0] == parts_b[0]) score += 0.25;  // CPU
  if (parts_a[1] == parts_b[1]) score += 0.25;  // Storage
  if (parts_a[2] == parts_b[2]) score += 0.35;  // System GUID
  if (parts_a[3] == parts_b[3]) score += 0.15;  // Hostname

  return score;
}

bool VerifyHardwareMatch(const std::string& registered_hwid,
                         const std::string& current_hwid,
                         double min_score) {
  if (registered_hwid.empty()) return true;  // License is not machine-bound
  double sim = ComputeHardwareSimilarity(registered_hwid, current_hwid);
  return sim >= min_score;
}

}  // namespace rtprotect::licensing
