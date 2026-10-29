// tests/test_dotnet_sdk.cs
//
// Verification test suite for RTProtect .NET SDK (Stage 5).
// Tests native C-ABI binding, fault injection exception safety, and fallback behavior.

using System;
using System.IO;
using System.Text;
using RTProtect;

namespace RTProtectTests
{
    class Program
    {
        static int Main(string[] args)
        {
            Console.WriteLine("[Test] Starting RTProtect .NET SDK verification...");

            try
            {
                // 1. Native library loading
                Console.WriteLine("[Test] Checking native C-ABI runtime load status...");
                if (!Protection.IsNativeLoaded)
                {
                    Console.Error.WriteLine("[FAIL] Expected native runtime to be loaded.");
                    return 1;
                }
                Console.WriteLine("[OK] Native runtime successfully bound.");

                // 2. Hardware ID
                Console.WriteLine("[Test] Querying hardware fingerprint...");
                string hwid = Protection.GetHardwareId();
                Console.WriteLine("[OK] Hardware ID: {0} (len={1})", hwid, hwid.Length);
                if (hwid.Length < 32)
                {
                    Console.Error.WriteLine("[FAIL] Hardware ID unexpectedly short.");
                    return 1;
                }

                // 3. Environment risk
                Console.WriteLine("[Test] Querying environment risk...");
                double risk = Protection.AssessEnvironmentRisk();
                Console.WriteLine("[OK] Environment risk: {0:F4}", risk);
                if (risk < 0.0 || risk > 1.0)
                {
                    Console.Error.WriteLine("[FAIL] Environment risk outside [0.0, 1.0].");
                    return 1;
                }

                // 4. Manifest verification with invalid/missing inputs
                Console.WriteLine("[Test] Verifying manifest with nonexistent file...");
                byte[] dummyKey = new byte[32];
                if (Protection.VerifyIntegrity("nonexistent.manifest", dummyKey))
                {
                    Console.Error.WriteLine("[FAIL] Expected nonexistent manifest to fail.");
                    return 1;
                }
                Console.WriteLine("[OK] Nonexistent manifest rejected as expected.");

                // 5. License verification with invalid/missing inputs
                Console.WriteLine("[Test] Verifying license with nonexistent file...");
                if (Protection.VerifyLicense("nonexistent.license", dummyKey, "com.test.app"))
                {
                    Console.Error.WriteLine("[FAIL] Expected nonexistent license to fail.");
                    return 1;
                }
                Console.WriteLine("[OK] Nonexistent license rejected as expected.");

                // 6. Fault injection testing
                Console.WriteLine("[Test] Testing C-ABI boundary fault injection exception safety...");

                // Mode 1: Risk fault -> negative sentinel -> managed fallback
                Protection.SetFaultInjectionForTesting(1);
                double faultRisk = Protection.AssessEnvironmentRisk();
                Console.WriteLine("[OK] Fault mode 1 survived: risk={0:F4}", faultRisk);
                if (faultRisk < 0.0 || faultRisk > 1.0)
                {
                    Console.Error.WriteLine("[FAIL] Expected managed fallback risk.");
                    return 1;
                }

                // Mode 2: Hardware ID fault -> -1 sentinel -> managed fallback (64 chars)
                Protection.SetFaultInjectionForTesting(2);
                string faultHwid = Protection.GetHardwareId();
                Console.WriteLine("[OK] Fault mode 2 survived: fallback hwid={0} (len={1})", faultHwid, faultHwid.Length);
                if (faultHwid.Length != 64)
                {
                    Console.Error.WriteLine("[FAIL] Expected 64-char managed SHA256 fallback on fault.");
                    return 1;
                }

                // Mode 3: Manifest fault -> 0 sentinel
                Protection.SetFaultInjectionForTesting(3);
                if (Protection.VerifyIntegrity("some.manifest", dummyKey))
                {
                    Console.Error.WriteLine("[FAIL] Expected false for manifest fault.");
                    return 1;
                }
                Console.WriteLine("[OK] Fault mode 3 survived: VerifyIntegrity returned false.");

                // Mode 4: License fault -> 0 sentinel
                Protection.SetFaultInjectionForTesting(4);
                if (Protection.VerifyLicense("some.license", dummyKey, "com.test.app"))
                {
                    Console.Error.WriteLine("[FAIL] Expected false for license fault.");
                    return 1;
                }
                Console.WriteLine("[OK] Fault mode 4 survived: VerifyLicense returned false.");

                // Reset
                Protection.SetFaultInjectionForTesting(0);
                double normalRisk = Protection.AssessEnvironmentRisk();
                if (normalRisk < 0.0 || normalRisk > 1.0)
                {
                    Console.Error.WriteLine("[FAIL] Risk invalid after fault injection reset.");
                    return 1;
                }
                Console.WriteLine("[OK] Fault injection reset successfully.");

                Console.WriteLine("\nAll .NET SDK tests passed successfully!");
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[FATAL] Unhandled exception during .NET SDK test: " + ex);
                return 1;
            }
        }
    }
}
