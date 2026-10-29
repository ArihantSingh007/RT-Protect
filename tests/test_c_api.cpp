#include "runtime/c_api.h"

#include <cstring>
#include <iostream>

#define C_API_CHECK(cond, msg) \
  do { \
    if (!(cond)) { \
      std::cerr << "[FAIL] Line " << __LINE__ << ": " << (msg) << "\n"; \
      return 1; \
    } \
  } while (0)

int main() {
  std::cout << "[Test] C ABI: get_hardware_id normal...\n";
  char hwid[128]{};
  int len = rtprotect_get_hardware_id(hwid, sizeof(hwid));
  C_API_CHECK(len > 0, "get_hardware_id returned non-positive length");
  C_API_CHECK(std::strlen(hwid) == static_cast<std::size_t>(len), "Hardware ID length mismatch");
  std::cout << "[OK] Hardware ID: " << hwid << " (len=" << len << ")\n";

  std::cout << "[Test] C ABI: get_hardware_id null/bounds...\n";
  C_API_CHECK(rtprotect_get_hardware_id(nullptr, 128) == -1, "Expected -1 for nullptr buffer");
  C_API_CHECK(rtprotect_get_hardware_id(hwid, 0) == -1, "Expected -1 for buffer_len == 0");
  C_API_CHECK(rtprotect_get_hardware_id(hwid, -5) == -1, "Expected -1 for negative buffer_len");

  // Truncation test: buffer smaller than hwid length
  char small_buf[16]{};
  int trunc_len = rtprotect_get_hardware_id(small_buf, sizeof(small_buf));
  C_API_CHECK(trunc_len == sizeof(small_buf) - 1, "Expected truncation to buffer_len - 1");
  C_API_CHECK(std::strlen(small_buf) == static_cast<std::size_t>(trunc_len), "Truncated string length mismatch");
  std::cout << "[OK] Hardware ID truncation handled correctly.\n";

  std::cout << "[Test] C ABI: assess_environment_risk normal...\n";
  double risk = rtprotect_assess_environment_risk();
  C_API_CHECK(risk >= 0.0 && risk <= 1.0, "Risk score outside [0.0, 1.0]");
  std::cout << "[OK] Environment risk score: " << risk << "\n";

  std::cout << "[Test] C ABI: verify_manifest invalid/null checks...\n";
  std::uint8_t dummy_key[32]{};
  C_API_CHECK(rtprotect_verify_manifest(nullptr, dummy_key) == 0, "Expected 0 for nullptr manifest_path");
  C_API_CHECK(rtprotect_verify_manifest("nonexistent.manifest", nullptr) == 0, "Expected 0 for nullptr pub_key");
  C_API_CHECK(rtprotect_verify_manifest("nonexistent.manifest", dummy_key) == 0, "Expected 0 for nonexistent manifest");
  std::cout << "[OK] verify_manifest null and nonexistent inputs rejected.\n";

  std::cout << "[Test] C ABI: verify_license invalid/null checks...\n";
  C_API_CHECK(rtprotect_verify_license(nullptr, dummy_key, "com.test.product") == 0, "Expected 0 for nullptr license_path");
  C_API_CHECK(rtprotect_verify_license("nonexistent.license", nullptr, "com.test.product") == 0, "Expected 0 for nullptr pub_key");
  C_API_CHECK(rtprotect_verify_license("nonexistent.license", dummy_key, nullptr) == 0, "Expected 0 for nullptr expected_product_id");
  C_API_CHECK(rtprotect_verify_license("nonexistent.license", dummy_key, "com.test.product") == 0, "Expected 0 for nonexistent license");
  std::cout << "[OK] verify_license null and nonexistent inputs rejected.\n";

  // Exception fault injection boundary tests
  std::cout << "[Test] C ABI: fault injection exception safety...\n";

  // Fault mode 1: assess_environment_risk throws exception -> returns -1.0
  rtprotect_set_fault_injection_for_testing(1);
  double faulted_risk = rtprotect_assess_environment_risk();
  C_API_CHECK(faulted_risk == -1.0, "Expected -1.0 sentinel on assess_environment_risk fault");
  std::cout << "[OK] assess_environment_risk exception caught, returned sentinel -1.0\n";

  // Fault mode 2: get_hardware_id throws exception -> returns -1
  rtprotect_set_fault_injection_for_testing(2);
  char fault_hwid[128] = "pre_existing_data";
  int faulted_hwid_len = rtprotect_get_hardware_id(fault_hwid, sizeof(fault_hwid));
  C_API_CHECK(faulted_hwid_len == -1, "Expected -1 sentinel on get_hardware_id fault");
  C_API_CHECK(fault_hwid[0] == '\0', "Expected zeroed/empty buffer on get_hardware_id fault");
  std::cout << "[OK] get_hardware_id exception caught, returned sentinel -1\n";

  // Fault mode 3: verify_manifest throws exception -> returns 0
  rtprotect_set_fault_injection_for_testing(3);
  int faulted_manifest_res = rtprotect_verify_manifest("some.manifest", dummy_key);
  C_API_CHECK(faulted_manifest_res == 0, "Expected 0 sentinel on verify_manifest fault");
  std::cout << "[OK] verify_manifest exception caught, returned sentinel 0\n";

  // Fault mode 4: verify_license throws exception -> returns 0
  rtprotect_set_fault_injection_for_testing(4);
  int faulted_license_res = rtprotect_verify_license("some.license", dummy_key, "com.test");
  C_API_CHECK(faulted_license_res == 0, "Expected 0 sentinel on verify_license fault");
  std::cout << "[OK] verify_license exception caught, returned sentinel 0\n";

  // Reset fault injection
  rtprotect_set_fault_injection_for_testing(0);
  C_API_CHECK(rtprotect_assess_environment_risk() >= 0.0, "Expected valid risk after fault injection reset");
  std::cout << "[OK] Fault injection reset successfully.\n";

  std::cout << "All C-ABI runtime tests passed!\n";
  return 0;
}
