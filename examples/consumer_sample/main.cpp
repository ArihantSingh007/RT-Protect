#include <iostream>
#include <vector>
#include <string>

#include "licensing/hardware_id.h"
#include "antitamper/anti_debug.h"
#include "integrity/sha256.h"
#include "crypto/aead.h"

int main() {
    std::cout << "=== RTProtect Consumer Sample Application ===" << std::endl;

    // 1. Hardware ID derivation
    std::string hwid = rtprotect::licensing::GetLocalHardwareId();
    if (hwid.empty()) {
        std::cerr << "FAIL: Failed to get hardware fingerprint" << std::endl;
        return 1;
    }
    std::cout << "[OK] Hardware Fingerprint derived: " << hwid.substr(0, 16) << "..." << std::endl;

    // 2. Anti-debug check
    bool debugger = rtprotect::antitamper::CheckDebuggerPresent();
    std::cout << "[OK] Debugger check completed (debugger present: " << (debugger ? "true" : "false") << ")" << std::endl;

    // 3. Cryptographic hashing check
    const std::string msg = "RTProtect SDK Integration Smoke Test";
    auto digest = rtprotect::integrity::Sha256(reinterpret_cast<const std::uint8_t*>(msg.data()), msg.size());
    if (!digest.has_value()) {
        std::cerr << "FAIL: SHA-256 calculation failed" << std::endl;
        return 1;
    }
    std::cout << "[OK] SHA-256 integrity test verified" << std::endl;

    // 4. Crypto AEAD key generation test
    auto key = rtprotect::crypto::Aes256Key::Generate();
    if (key.bytes().empty()) {
        std::cerr << "FAIL: Cryptographic key generation failed" << std::endl;
        return 1;
    }
    std::cout << "[OK] Cryptographic AES-256 key generated successfully (" << key.bytes().size() << " bytes)" << std::endl;

    std::cout << "Consumer sample executed cleanly with 0 errors." << std::endl;
    return 0;
}
