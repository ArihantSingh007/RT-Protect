#include "runtime/c_api.h"

#include <cassert>
#include <cstring>
#include <iostream>

int main() {
  std::cout << "[Test] C ABI: get_hardware_id...\n";
  char hwid[128]{};
  int len = rtprotect_get_hardware_id(hwid, sizeof(hwid));
  assert(len > 0);
  assert(std::strlen(hwid) == static_cast<std::size_t>(len));
  std::cout << "[OK] Hardware ID: " << hwid << " (len=" << len << ")\n";

  std::cout << "[Test] C ABI: assess_environment_risk...\n";
  double risk = rtprotect_assess_environment_risk();
  assert(risk >= 0.0 && risk <= 1.0);
  std::cout << "[OK] Environment risk score: " << risk << "\n";

  std::cout << "[Test] C ABI: verify_manifest with nonexistent file...\n";
  std::uint8_t dummy_key[32]{};
  int res = rtprotect_verify_manifest("nonexistent.manifest", dummy_key);
  if (res != 0) {
    std::cerr << "Expected verify_manifest to fail for nonexistent file\n";
    return 1;
  }
  std::cout << "[OK] Nonexistent manifest rejected as expected.\n";

  std::cout << "[Test] C ABI: verify_license with nonexistent file...\n";
  int lic_res = rtprotect_verify_license("nonexistent.license", dummy_key, "com.test.product");
  if (lic_res != 0) {
    std::cerr << "Expected verify_license to fail for nonexistent file\n";
    return 1;
  }
  std::cout << "[OK] Nonexistent license rejected as expected.\n";

  std::cout << "All C-ABI runtime tests passed!\n";
  return 0;
}
