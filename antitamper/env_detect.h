// antitamper/env_detect.h
//
// Virtualization and hypervisor detection.
//
// Identifies virtualized environments via CPUID hypervisor flags and signature
// queries. In accordance with policy, virtualization is treated as an environmental
// risk indicator, not immediate proof of tampering (supporting legitimate cloud/VM use).

#pragma once

#include <string>

namespace rtprotect::antitamper {

// Queries CPUID leaf 1 (ECX bit 31) to detect presence of a hypervisor.
bool CheckHypervisorPresent();

// Queries CPUID leaf 0x40000000 to identify the hypervisor vendor signature
// (e.g. "Microsoft Hv", "VMwareVMware", "KVMKVMKVM", "prl hyperv", "VBoxVBoxVBox", "XenVMMXenVMM").
// Returns empty string if no hypervisor signature is present.
std::string GetHypervisorVendor();

}  // namespace rtprotect::antitamper
