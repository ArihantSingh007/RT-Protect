// tooling/pe_protector.h
//
// Binary-Level PE64 Executable Protection Engine for RTProtect.
// Provides post-build PE section encryption and import-table obfuscation for compiled
// x64 Windows executables and DLLs, complementing source-level function virtualization.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace rtprotect::tooling {

#pragma pack(push, 1)
// Embedded metadata descriptor located in protected PE binary
struct PeProtectedSectionHeader {
  std::uint32_t magic;               // 0x52545053 ("RTPS" - RTProtect Section)
  std::uint32_t version;             // 1
  std::uint32_t section_rva;         // VirtualAddress of protected code section
  std::uint32_t section_size;        // SizeOfRawData in bytes
  std::uint8_t key[32];              // AES-256 key for CTR decryption
  std::uint8_t iv[16];               // AES-256 CTR IV/nonce
  std::uint32_t original_protect;    // Original section characteristics
  std::uint32_t checksum;            // FNV-1a checksum of encrypted section data
  std::uint32_t obfuscated_imports;  // Number of IAT import entries obfuscated
};
#pragma pack(pop)

inline constexpr std::uint32_t kPeProtectorMagic = 0x52545053; // "RTPS"

struct PeProtectionOptions {
  std::string target_section = ".text"; // Section name to encrypt (typically .text)
  bool encrypt_section = true;          // Enable AES-256-CTR section encryption
  bool obfuscate_imports = true;        // Enable IAT import name obfuscation
  std::string custom_key_hex;           // Optional 64-hex-character AES key (auto-generated if empty)
};

struct PeProtectionResult {
  bool success = false;
  std::string error;
  std::string target_section;
  std::size_t section_bytes_encrypted = 0;
  std::size_t imports_obfuscated = 0;
  std::array<std::uint8_t, 32> encryption_key{};
  std::array<std::uint8_t, 16> iv{};
  std::uint32_t checksum = 0;
};

class PeProtector {
 public:
  // Protects a PE x64 file on disk, writing output to output_path
  static bool ProtectFile(const std::string& input_path,
                          const std::string& output_path,
                          const PeProtectionOptions& options,
                          PeProtectionResult* result_out = nullptr);

  // Protects an in-memory PE x64 image buffer
  static bool ProtectMemory(std::vector<std::uint8_t>& pe_image,
                            const PeProtectionOptions& options,
                            PeProtectionResult* result_out = nullptr);

  // Validates whether a file is a valid 64-bit PE binary
  static bool IsValidPe64(const std::vector<std::uint8_t>& pe_image);
};

}  // namespace rtprotect::tooling
