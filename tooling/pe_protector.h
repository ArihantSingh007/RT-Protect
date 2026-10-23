// tooling/pe_protector.h
//
// [EXPERIMENTAL - NON-PRODUCTION]
// Binary-Level PE64 Executable Protection Engine for RTProtect.
// Provides experimental post-build PE section encryption and import-table obfuscation for compiled
// x64 Windows executables and DLLs.
//
// DESIGN & SECURITY NOTICE:
// 1. This module is EXPERIMENTAL and NOT ready for production deployments.
// 2. Client-side embedded AES keys provide static string obfuscation only; they do not provide
//    confidentiality against an adversary with memory access or debugging tools on the host.
// 3. Modifying PE files on disk without a complete runtime bootstrap loader will interfere with
//    normal Windows loader import binding and Authenticode code signatures.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <windows.h>

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
  std::uint32_t original_protect;    // Original memory protection (PAGE_* constant, e.g. PAGE_EXECUTE_READ)
  std::uint32_t checksum;            // FNV-1a checksum of encrypted section data
  std::uint32_t obfuscated_imports;  // Number of IAT import entries obfuscated
};
#pragma pack(pop)

inline constexpr std::uint32_t kPeProtectorMagic = 0x52545053; // "RTPS"

// Converts PE IMAGE_SECTION_HEADER::Characteristics flags into Windows VirtualProtect PAGE_* constants
inline DWORD SectionCharacteristicsToPageProtection(DWORD characteristics) {
  bool r = (characteristics & IMAGE_SCN_MEM_READ) != 0;
  bool w = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
  bool x = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
  if (x) {
    if (w) return PAGE_EXECUTE_READWRITE;
    if (r) return PAGE_EXECUTE_READ;
    return PAGE_EXECUTE;
  }
  if (w) return PAGE_READWRITE;
  if (r) return PAGE_READONLY;
  return PAGE_NOACCESS;
}

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
  // Protects a PE x64 file on disk, writing output to output_path [EXPERIMENTAL]
  static bool ProtectFile(const std::string& input_path,
                          const std::string& output_path,
                          const PeProtectionOptions& options,
                          PeProtectionResult* result_out = nullptr);

  // Protects an in-memory PE x64 image buffer [EXPERIMENTAL]
  static bool ProtectMemory(std::vector<std::uint8_t>& pe_image,
                            const PeProtectionOptions& options,
                            PeProtectionResult* result_out = nullptr);

  // Validates whether a file is a valid 64-bit PE binary with strict bounds checking
  static bool IsValidPe64(const std::vector<std::uint8_t>& pe_image);
};

}  // namespace rtprotect::tooling
