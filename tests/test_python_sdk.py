#!/usr/bin/env python3
"""
tests/test_python_sdk.py

End-to-end unit and boundary verification for the RTProtect Python SDK.
Verifies native C-ABI binding, fallback modes, and exception-safety sentinels.
"""

import os
import sys

# Add sdk/python to module search path
HERE = os.path.dirname(os.path.abspath(__file__))
SDK_DIR = os.path.abspath(os.path.join(HERE, "..", "sdk", "python"))
sys.path.insert(0, SDK_DIR)

from rtprotect import RTProtectClient  # noqa: E402


def test_native_client():
    print("[Test] Initializing RTProtectClient with auto-discovery...")
    client = RTProtectClient()
    if not client.is_native_loaded():
        raise RuntimeError("Expected native rtprotect_runtime to be loaded, but it was not found.")
    print("[OK] Native rtprotect_runtime loaded successfully.")

    # 1. Hardware ID
    print("[Test] Querying hardware fingerprint via native C-ABI...")
    hwid = client.get_hardware_fingerprint()
    print(f"[OK] Hardware ID: {hwid} (len={len(hwid)})")
    if len(hwid) < 32:
        raise AssertionError(f"Hardware ID unexpectedly short: {hwid}")

    # 2. Risk assessment
    print("[Test] Assessing environment risk via native C-ABI...")
    risk = client.assess_environment_risk()
    print(f"[OK] Environment risk: {risk:.4f}")
    if not (0.0 <= risk <= 1.0):
        raise AssertionError(f"Risk score outside bounds [0.0, 1.0]: {risk}")

    # 3. Manifest verification with invalid/missing inputs
    print("[Test] Verifying manifest handling with missing files...")
    dummy_key = b"\x00" * 32
    if client.verify_manifest("nonexistent.manifest", dummy_key):
        raise AssertionError("Expected nonexistent manifest to be rejected.")
    print("[OK] Nonexistent manifest rejected as expected.")

    # 4. License verification with invalid/missing inputs
    print("[Test] Verifying license handling with missing files...")
    if client.verify_license("nonexistent.license", dummy_key, "com.test.app"):
        raise AssertionError("Expected nonexistent license to be rejected.")
    print("[OK] Nonexistent license rejected as expected.")

    # 5. Fault injection and C-ABI boundary exception safety
    print("[Test] Testing C-ABI boundary exception safety under fault injection...")

    # Fault 1: assess_environment_risk throws C++ exception
    client.set_fault_injection_for_testing(1)
    fault_risk = client.assess_environment_risk()
    print(f"[OK] Fault mode 1 survived: risk={fault_risk}")
    if not (0.0 <= fault_risk <= 1.0):
        raise AssertionError(f"Expected safe risk fallback, got {fault_risk}")

    # Fault 2: get_hardware_id throws C++ exception
    client.set_fault_injection_for_testing(2)
    fault_hwid = client.get_hardware_fingerprint()
    print(f"[OK] Fault mode 2 survived: fallback hwid={fault_hwid} (len={len(fault_hwid)})")
    if len(fault_hwid) != 64:  # SHA256 fallback hex is 64 chars
        raise AssertionError(f"Expected 64-char SHA256 fallback on fault, got len={len(fault_hwid)}")

    # Fault 3: verify_manifest throws C++ exception
    client.set_fault_injection_for_testing(3)
    if client.verify_manifest("nonexistent.manifest", dummy_key):
        raise AssertionError("Expected fault mode 3 to return False safely.")
    print("[OK] Fault mode 3 survived: verify_manifest returned False")

    # Fault 4: verify_license throws C++ exception
    client.set_fault_injection_for_testing(4)
    if client.verify_license("nonexistent.license", dummy_key, "com.test.app"):
        raise AssertionError("Expected fault mode 4 to return False safely.")
    print("[OK] Fault mode 4 survived: verify_license returned False")

    # Reset fault injection
    client.set_fault_injection_for_testing(0)
    normal_risk = client.assess_environment_risk()
    if not (0.0 <= normal_risk <= 1.0):
        raise AssertionError("Expected valid risk score after fault reset.")
    print("[OK] Fault injection reset successfully.")


def test_managed_fallback():
    print("[Test] Testing pure-Python managed fallback...")
    client = RTProtectClient(lib_path="nonexistent_library_12345.dll")
    if client.is_native_loaded():
        raise AssertionError("Expected client not to load nonexistent native library.")

    hwid = client.get_hardware_fingerprint()
    print(f"[OK] Managed fallback hardware ID: {hwid} (len={len(hwid)})")
    if len(hwid) != 64:
        raise AssertionError(f"Expected 64-char SHA256 fallback fingerprint, got len={len(hwid)}")

    risk = client.assess_environment_risk()
    print(f"[OK] Managed fallback risk: {risk:.4f}")
    if not (0.0 <= risk <= 1.0):
        raise AssertionError(f"Managed fallback risk out of range: {risk}")


def main():
    test_native_client()
    test_managed_fallback()
    print("\nAll Python SDK tests passed successfully!")


if __name__ == "__main__":
    main()
