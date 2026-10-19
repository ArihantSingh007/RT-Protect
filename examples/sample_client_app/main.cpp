// examples/sample_client_app/main.cpp
//
// Demonstrates a client commercial application integrated with RTProtect.
//
// In protected mode (when rtprotect_config.h is present), the application:
//  1. Verifies its asymmetric digital signature against the vendor release key.
//  2. Validates its machine-bound Ed25519 license file (client.license).
//  3. Evaluates runtime anti-tamper risk (debuggers, instrumentation, hypervisors).
//  4. Dispatches core application operations only if authorization succeeds.

#include <iostream>
#include <cstdlib>

#if __has_include("rtprotect_config.h")
#include "rtprotect_config.h"
#define RTPROTECT_ENABLED 1
#else
#define RTPROTECT_ENABLED 0
#endif

int main() {
  std::cout << "====================================================\n";
  std::cout << "       Sample Protected Enterprise Application      \n";
  std::cout << "====================================================\n";

#if RTPROTECT_ENABLED
  std::cout << "[Security] Initializing RTProtect Authorization & Anti-Tamper...\n";
  std::cout << "[Security] Target Product: " << rtprotect_client::kProductId << "\n";
  std::cout << "[Security] Release Version: " << rtprotect_client::kReleaseVersion << "\n";
  std::cout << "[Security] Security Profile: " << rtprotect_client::kProtectionProfile << "\n";

  if (!rtprotect_client::VerifyClientIntegrityAndLicense()) {
    std::cerr << "[FATAL] RTProtect security verification failed!\n";
    std::cerr << "        Reason: Tampered binary, invalid/expired license, or debugger detected.\n";
    std::cerr << "        Execution terminated per defense-in-depth security policy.\n";
    return 1;
  }

  std::cout << "[Security] Digital signature verified (Ed25519).\n";
  std::cout << "[Security] License valid & bound to current hardware.\n";
  std::cout << "[Security] Runtime environment clean.\n";
#else
  std::cout << "[Notice] Running in unprotected development mode.\n";
  std::cout << "         Run `rtprotect-tool integrate .` to apply protection.\n";
#endif

  std::cout << "[App] Processing secure business workload...\n";
  std::cout << "[App] Workload completed successfully.\n";
  return 0;
}
