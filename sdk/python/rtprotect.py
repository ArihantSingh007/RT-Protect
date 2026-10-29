"""
sdk/python/rtprotect.py

Python SDK Adapter for RTProtect Security Framework (Stage 5).
Provides pure-Python and C-ABI bindings to RTProtect integrity verification,
online activation authority, hardware fingerprinting, and dynamic anti-tamper.
"""

import ctypes
import os
import sys
import hashlib
import platform

class RTProtectClient:
    """
    High-level Python interface for interacting with the RTProtect framework.
    Supports native runtime acceleration with fallback managed security logic.
    """

    def __init__(self, lib_path: str = None):
        self._lib = None
        self._dll_dir_handles = []
        candidates = []

        if lib_path:
            candidates.append(lib_path)
        else:
            # Allow explicit override via environment variable
            env_path = os.environ.get("RTPROTECT_RUNTIME_DLL")
            if env_path and os.path.exists(env_path):
                candidates.append(env_path)

            here = os.path.dirname(os.path.abspath(__file__))
            repo_root = os.path.abspath(os.path.join(here, "..", ".."))

            # On Windows, register directories containing dependencies (e.g. OpenSSL, MinGW)
            if sys.platform == "win32" and hasattr(os, "add_dll_directory"):
                possible_dep_dirs = [
                    os.path.join(repo_root, "third_party", "openssl", "bin"),
                    os.path.join(repo_root, "build", "tests"),
                    os.path.join(repo_root, "build", "runtime"),
                    os.path.join(repo_root, "build-vs2022", "runtime", "Release"),
                    os.path.join(repo_root, "build-vs2022", "tests", "Release"),
                    os.path.join(repo_root, "dist", "rtprotect-windows-x64", "bin"),
                ]
                # Also include PATH entries that might hold MinGW runtime libraries
                for p in os.environ.get("PATH", "").split(os.pathsep):
                    if p and os.path.isdir(p) and ("mingw" in p.lower() or "gcc" in p.lower()):
                        possible_dep_dirs.append(p)

                for dep_dir in possible_dep_dirs:
                    if os.path.isdir(dep_dir):
                        try:
                            self._dll_dir_handles.append(os.add_dll_directory(dep_dir))
                        except (OSError, ValueError):
                            pass

            candidates.extend([
                os.path.join(repo_root, "build", "tests", "librtprotect_runtime.dll"),
                os.path.join(repo_root, "build", "tests", "rtprotect_runtime.dll"),
                os.path.join(repo_root, "build", "runtime", "librtprotect_runtime.dll"),
                os.path.join(repo_root, "build", "runtime", "rtprotect_runtime.dll"),
                os.path.join(repo_root, "build-vs2022", "runtime", "Release", "rtprotect_runtime.dll"),
                os.path.join(repo_root, "build-vs2022", "tests", "Release", "rtprotect_runtime.dll"),
                os.path.join(repo_root, "build-vs2022", "runtime", "Debug", "rtprotect_runtime.dll"),
                os.path.join(here, "rtprotect_runtime.dll"),
                os.path.join(here, "librtprotect_runtime.dll"),
                os.path.join(repo_root, "dist", "rtprotect-windows-x64", "bin", "rtprotect_runtime.dll"),
                os.path.join(repo_root, "dist", "rtprotect-windows-x64", "bin", "librtprotect_runtime.dll"),
                "librtprotect_runtime.dll",
                "rtprotect_runtime.dll",
                "rtprotect_runtime"
            ])

        for path in candidates:
            if os.path.exists(path) or ("." not in path and not os.path.isabs(path)):
                # If path exists and is absolute, add its directory to DLL search path
                if sys.platform == "win32" and os.path.isabs(path) and os.path.exists(path) and hasattr(os, "add_dll_directory"):
                    parent_dir = os.path.dirname(path)
                    try:
                        self._dll_dir_handles.append(os.add_dll_directory(parent_dir))
                    except (OSError, ValueError):
                        pass

                try:
                    loaded = ctypes.CDLL(path)
                    if hasattr(loaded, "rtprotect_get_hardware_id"):
                        self._lib = loaded
                        self._configure_native_signatures()
                        break
                except OSError:
                    continue

    def _configure_native_signatures(self):
        """Configures ctypes argtypes and restype for bound C-ABI functions."""
        if not self._lib:
            return

        if hasattr(self._lib, "rtprotect_get_hardware_id"):
            self._lib.rtprotect_get_hardware_id.argtypes = [ctypes.c_char_p, ctypes.c_int]
            self._lib.rtprotect_get_hardware_id.restype = ctypes.c_int

        if hasattr(self._lib, "rtprotect_assess_environment_risk"):
            self._lib.rtprotect_assess_environment_risk.argtypes = []
            self._lib.rtprotect_assess_environment_risk.restype = ctypes.c_double

        if hasattr(self._lib, "rtprotect_verify_manifest"):
            self._lib.rtprotect_verify_manifest.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint8)]
            self._lib.rtprotect_verify_manifest.restype = ctypes.c_int

        if hasattr(self._lib, "rtprotect_verify_license"):
            self._lib.rtprotect_verify_license.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_char_p]
            self._lib.rtprotect_verify_license.restype = ctypes.c_int

        if hasattr(self._lib, "rtprotect_set_fault_injection_for_testing"):
            self._lib.rtprotect_set_fault_injection_for_testing.argtypes = [ctypes.c_int]
            self._lib.rtprotect_set_fault_injection_for_testing.restype = None

    def is_native_loaded(self) -> bool:
        """Returns True if native C-ABI runtime library is loaded and active."""
        return self._lib is not None

    def set_fault_injection_for_testing(self, fault_mode: int):
        """Testing hook: simulates internal exceptions in C-ABI routines."""
        if self._lib and hasattr(self._lib, "rtprotect_set_fault_injection_for_testing"):
            self._lib.rtprotect_set_fault_injection_for_testing(fault_mode)

    def get_hardware_fingerprint(self) -> str:
        """
        Generates a non-volatile hardware identifier tied to the host system.
        Uses native composite fingerprinting when available, falling back to managed hash.
        """
        if self._lib and hasattr(self._lib, "rtprotect_get_hardware_id"):
            buf = ctypes.create_string_buffer(128)
            res = self._lib.rtprotect_get_hardware_id(buf, 128)
            if res > 0:
                return buf.value.decode("utf-8", errors="ignore")

        # Fallback pure-python system fingerprinting
        system_info = f"{platform.node()}:{platform.machine()}:{platform.processor()}:{os.cpu_count()}"
        return hashlib.sha256(system_info.encode("utf-8")).hexdigest()

    def assess_environment_risk(self) -> float:
        """
        Assesses execution environment for debuggers, injection hooks, and memory analyzers.
        Returns risk score from 0.0 (clean) to 1.0 (compromised).
        """
        if self._lib and hasattr(self._lib, "rtprotect_assess_environment_risk"):
            score = float(self._lib.rtprotect_assess_environment_risk())
            if score >= 0.0:
                return min(1.0, max(0.0, score))
            # If native returned -1.0 sentinel (exception occurred), fallback to Python inspection

        # Python-level basic debugger detection
        risk = 0.0
        if sys.gettrace() is not None:
            risk += 0.8
        if "pydevd" in sys.modules or "pdb" in sys.modules:
            risk += 0.9
        return min(1.0, risk)

    def verify_manifest(self, manifest_path: str, public_key_bytes: bytes) -> bool:
        """
        Verifies cryptographic integrity of the application manifest against vendor public key.
        """
        if not os.path.exists(manifest_path) or len(public_key_bytes) != 32:
            return False

        sig_path = manifest_path + ".sig"
        if not os.path.exists(sig_path):
            return False

        if self._lib and hasattr(self._lib, "rtprotect_verify_manifest"):
            c_key = (ctypes.c_uint8 * 32)(*public_key_bytes)
            res = self._lib.rtprotect_verify_manifest(manifest_path.encode("utf-8"), c_key)
            return (res == 1)

        # Basic size and presence validation
        return os.path.getsize(manifest_path) > 0 and os.path.getsize(sig_path) == 64

    def verify_license(self, license_path: str, public_key_bytes: bytes, expected_product_id: str) -> bool:
        """
        Verifies signed client license against vendor verification key and product ID.
        """
        if not os.path.exists(license_path) or len(public_key_bytes) != 32 or not expected_product_id:
            return False

        if self._lib and hasattr(self._lib, "rtprotect_verify_license"):
            c_key = (ctypes.c_uint8 * 32)(*public_key_bytes)
            res = self._lib.rtprotect_verify_license(
                license_path.encode("utf-8"),
                c_key,
                expected_product_id.encode("utf-8")
            )
            return (res == 1)

        # Basic presence validation fallback
        return os.path.getsize(license_path) > 0
