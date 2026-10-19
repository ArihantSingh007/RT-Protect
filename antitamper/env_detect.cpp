// antitamper/env_detect.cpp

#include "antitamper/env_detect.h"

#include <cstring>

#if defined(_WIN32)
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif
#elif defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#endif

namespace rtprotect::antitamper {

bool CheckHypervisorPresent() {
#if defined(_WIN32)
  int cpu_info[4] = {0};
#if defined(_MSC_VER)
  __cpuid(cpu_info, 1);
#else
  __cpuid(1, cpu_info[0], cpu_info[1], cpu_info[2], cpu_info[3]);
#endif
  // Leaf 1, ECX bit 31 is the hypervisor present bit
  return (cpu_info[2] & (1 << 31)) != 0;
#elif defined(__x86_64__) || defined(__i386__)
  unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
  if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
    return (ecx & (1 << 31)) != 0;
  }
  return false;
#else
  return false;
#endif
}

std::string GetHypervisorVendor() {
  if (!CheckHypervisorPresent()) return "";

#if defined(_WIN32)
  int cpu_info[4] = {0};
#if defined(_MSC_VER)
  __cpuid(cpu_info, 0x40000000);
#else
  __cpuid(0x40000000, cpu_info[0], cpu_info[1], cpu_info[2], cpu_info[3]);
#endif
  char sig[13] = {0};
  std::memcpy(sig, &cpu_info[1], 4);
  std::memcpy(sig + 4, &cpu_info[2], 4);
  std::memcpy(sig + 8, &cpu_info[3], 4);
  return std::string(sig);
#elif defined(__x86_64__) || defined(__i386__)
  unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
  if (__get_cpuid(0x40000000, &eax, &ebx, &ecx, &edx)) {
    char sig[13] = {0};
    std::memcpy(sig, &ebx, 4);
    std::memcpy(sig + 4, &ecx, 4);
    std::memcpy(sig + 8, &edx, 4);
    return std::string(sig);
  }
  return "";
#else
  return "";
#endif
}

}  // namespace rtprotect::antitamper
