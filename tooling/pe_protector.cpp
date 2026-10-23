// tooling/pe_protector.cpp
//
// [EXPERIMENTAL - NON-PRODUCTION]
// Binary-Level PE64 Executable Protection Engine implementation.

#include "tooling/pe_protector.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <windows.h>
#include "tooling/file_io.h"

namespace rtprotect::tooling {

namespace {

std::uint32_t ComputeFnv1a(const std::uint8_t* data, std::size_t len) {
  std::uint32_t hash = 2166136261u;
  for (std::size_t i = 0; i < len; ++i) {
    hash ^= data[i];
    hash *= 16777619u;
  }
  return hash;
}

bool HexToBytes(const std::string& hex, std::uint8_t* out, std::size_t len) {
  if (hex.size() != len * 2) return false;
  for (std::size_t i = 0; i < len; ++i) {
    char h[3] = { hex[i * 2], hex[i * 2 + 1], '\0' };
    char* end = nullptr;
    long v = std::strtol(h, &end, 16);
    if (end != h + 2 || v < 0 || v > 255) return false;
    out[i] = static_cast<std::uint8_t>(v);
  }
  return true;
}

std::size_t RvaToFileOffset(const IMAGE_NT_HEADERS64* nt,
                            const IMAGE_SECTION_HEADER* sections,
                            std::uint32_t rva,
                            std::size_t required_bytes,
                            std::size_t image_size) {
  if (required_bytes == 0 || required_bytes > image_size) return 0;
  for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
    const auto& sec = sections[i];
    std::uint32_t sec_rva = sec.VirtualAddress;
    std::uint32_t sec_vsize = sec.Misc.VirtualSize ? sec.Misc.VirtualSize : sec.SizeOfRawData;
    if (rva >= sec_rva && static_cast<std::uint64_t>(rva) < static_cast<std::uint64_t>(sec_rva) + sec_vsize) {
      std::uint32_t offset_in_sec = rva - sec_rva;
      if (static_cast<std::size_t>(offset_in_sec) + required_bytes > sec_vsize) return 0;
      if (sec.PointerToRawData > image_size) return 0;
      if (static_cast<std::size_t>(sec.PointerToRawData) + offset_in_sec > image_size - required_bytes) return 0;
      return static_cast<std::size_t>(sec.PointerToRawData) + offset_in_sec;
    }
  }
  return 0;
}

bool Aes256CtrTransform(const std::uint8_t* key,
                        const std::uint8_t* iv,
                        const std::uint8_t* input,
                        std::size_t len,
                        std::uint8_t* output) {
  if (len > static_cast<std::size_t>(std::numeric_limits<int>::max())) return false;
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return false;

  bool ok = false;
  do {
    if (EVP_CipherInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key, iv, 1) != 1) break;
    int out_len = 0;
    if (EVP_CipherUpdate(ctx, output, &out_len, input, static_cast<int>(len)) != 1) break;
    int final_len = 0;
    if (EVP_CipherFinal_ex(ctx, output + out_len, &final_len) != 1) break;
    ok = true;
  } while (false);

  EVP_CIPHER_CTX_free(ctx);
  return ok;
}

}  // namespace

bool PeProtector::IsValidPe64(const std::vector<std::uint8_t>& pe_image) {
  if (pe_image.size() < sizeof(IMAGE_DOS_HEADER)) return false;

  const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(pe_image.data());
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

  if (dos->e_lfanew < static_cast<LONG>(sizeof(IMAGE_DOS_HEADER))) return false;
  if (pe_image.size() < sizeof(IMAGE_NT_HEADERS64) ||
      static_cast<std::size_t>(dos->e_lfanew) > pe_image.size() - sizeof(IMAGE_NT_HEADERS64)) {
    return false;
  }

  const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(pe_image.data() + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
  if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return false;
  if (nt->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) return false;
  if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return false;

  // Validate entire section table fits in the file image
  std::size_t sec_table_offset = static_cast<std::size_t>(dos->e_lfanew) +
                                 offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
                                 nt->FileHeader.SizeOfOptionalHeader;
  std::size_t sec_table_size = static_cast<std::size_t>(nt->FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
  if (sec_table_offset > pe_image.size() || sec_table_size > pe_image.size() - sec_table_offset) {
    return false;
  }

  return true;
}

bool PeProtector::ProtectMemory(std::vector<std::uint8_t>& pe_image,
                               const PeProtectionOptions& options,
                               PeProtectionResult* result_out) {
  if (result_out) {
    result_out->success = false;
    result_out->target_section = options.target_section;
  }

  if (!IsValidPe64(pe_image)) {
    if (result_out) result_out->error = "Invalid PE64 executable format or truncated image bounds";
    return false;
  }

  auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(pe_image.data());
  auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(pe_image.data() + dos->e_lfanew);
  auto* sections = IMAGE_FIRST_SECTION(nt);

  IMAGE_SECTION_HEADER* target_sec = nullptr;
  for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
    char sec_name[9] = {0};
    std::memcpy(sec_name, sections[i].Name, 8);
    if (options.target_section == sec_name) {
      target_sec = &sections[i];
      break;
    }
  }

  if (!target_sec && options.encrypt_section) {
    if (result_out) result_out->error = "Target section '" + options.target_section + "' not found in binary";
    return false;
  }

  // Ensure sufficient DOS stub space exists before e_lfanew to store the header
  if (dos->e_lfanew < static_cast<LONG>(0x40 + sizeof(PeProtectedSectionHeader))) {
    if (result_out) {
      result_out->error = "Insufficient DOS stub padding in executable header to embed protection descriptor";
    }
    return false;
  }

  PeProtectedSectionHeader header{};
  header.magic = kPeProtectorMagic;
  header.version = 1;

  if (options.encrypt_section && target_sec) {
    // Checked arithmetic for section bounds
    if (target_sec->PointerToRawData > pe_image.size() ||
        target_sec->SizeOfRawData > pe_image.size() - target_sec->PointerToRawData) {
      if (result_out) result_out->error = "Section raw data extends beyond PE file bounds";
      return false;
    }

    if (target_sec->SizeOfRawData == 0) {
      if (result_out) result_out->error = "Target section has zero SizeOfRawData";
      return false;
    }

    // Key generation / loading
    if (!options.custom_key_hex.empty()) {
      if (!HexToBytes(options.custom_key_hex, header.key, 32)) {
        if (result_out) result_out->error = "Invalid custom AES-256 key hex string (must be 64 hex characters)";
        return false;
      }
    } else {
      if (RAND_bytes(header.key, sizeof(header.key)) != 1) {
        if (result_out) result_out->error = "OpenSSL RNG failure generating section encryption key";
        return false;
      }
    }

    if (RAND_bytes(header.iv, sizeof(header.iv)) != 1) {
      if (result_out) result_out->error = "OpenSSL RNG failure generating IV";
      return false;
    }

    header.section_rva = target_sec->VirtualAddress;
    header.section_size = target_sec->SizeOfRawData;
    // Map section characteristics to actual Win32 VirtualProtect PAGE_* constants
    header.original_protect = SectionCharacteristicsToPageProtection(target_sec->Characteristics);

    // Encrypt section in-place
    std::uint8_t* sec_data = pe_image.data() + target_sec->PointerToRawData;
    std::vector<std::uint8_t> encrypted(target_sec->SizeOfRawData);
    if (!Aes256CtrTransform(header.key, header.iv, sec_data, target_sec->SizeOfRawData, encrypted.data())) {
      if (result_out) result_out->error = "AES-256-CTR section encryption failed";
      return false;
    }
    std::memcpy(sec_data, encrypted.data(), target_sec->SizeOfRawData);

    header.checksum = ComputeFnv1a(sec_data, target_sec->SizeOfRawData);

    // Ensure section has read, write, execute in header characteristics
    target_sec->Characteristics |= IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;

    if (result_out) {
      result_out->section_bytes_encrypted = target_sec->SizeOfRawData;
      std::memcpy(result_out->encryption_key.data(), header.key, 32);
      std::memcpy(result_out->iv.data(), header.iv, 16);
      result_out->checksum = header.checksum;
    }
  }

  // Import table obfuscation with full bounds validation
  std::size_t obfuscated_count = 0;
  if (options.obfuscate_imports) {
    const auto& import_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.VirtualAddress != 0 && import_dir.Size >= sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
      std::size_t import_file_offset = RvaToFileOffset(nt, sections, import_dir.VirtualAddress, import_dir.Size, pe_image.size());
      if (import_file_offset != 0) {
        std::size_t max_descriptors = import_dir.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
        auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pe_image.data() + import_file_offset);
        for (std::size_t d = 0; d < max_descriptors && (desc->Name != 0 || desc->FirstThunk != 0); ++d, ++desc) {
          std::uint32_t thunk_rva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
          if (thunk_rva == 0) continue;
          std::size_t thunk_offset = RvaToFileOffset(nt, sections, thunk_rva, sizeof(IMAGE_THUNK_DATA64), pe_image.size());
          if (thunk_offset == 0) continue;

          auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA64*>(pe_image.data() + thunk_offset);
          std::size_t max_thunks = (pe_image.size() - thunk_offset) / sizeof(IMAGE_THUNK_DATA64);
          for (std::size_t t = 0; t < max_thunks && thunk->u1.AddressOfData != 0; ++t, ++thunk) {
            if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
              std::uint32_t name_rva = static_cast<std::uint32_t>(thunk->u1.AddressOfData);
              std::size_t name_offset = RvaToFileOffset(nt, sections, name_rva, sizeof(IMAGE_IMPORT_BY_NAME) + 1, pe_image.size());
              if (name_offset != 0) {
                auto* import_by_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pe_image.data() + name_offset);
                char* func_name = import_by_name->Name;
                std::size_t max_name_len = pe_image.size() - (name_offset + offsetof(IMAGE_IMPORT_BY_NAME, Name));
                std::size_t fn_len = 0;
                bool found_null = false;
                while (fn_len < max_name_len && fn_len < 256) {
                  if (func_name[fn_len] == '\0') {
                    found_null = true;
                    break;
                  }
                  fn_len++;
                }
                if (found_null && fn_len > 0) {
                  for (std::size_t k = 0; k < fn_len; ++k) {
                    func_name[k] = static_cast<char>(func_name[k] ^ (0x5A + (k % 7)));
                    if (func_name[k] == '\0') func_name[k] = '_';
                  }
                  obfuscated_count++;
                }
              }
            }
          }
        }
      }
    }
  }

  header.obfuscated_imports = static_cast<std::uint32_t>(obfuscated_count);
  if (result_out) {
    result_out->imports_obfuscated = obfuscated_count;
  }

  // Embed the PeProtectedSectionHeader into the validated DOS stub padding
  std::memcpy(pe_image.data() + 0x40, &header, sizeof(header));

  if (result_out) {
    result_out->success = true;
  }
  return true;
}

bool PeProtector::ProtectFile(const std::string& input_path,
                              const std::string& output_path,
                              const PeProtectionOptions& options,
                              PeProtectionResult* result_out) {
  auto pe_bytes = tooling::ReadFile(input_path);
  if (!pe_bytes.has_value()) {
    if (result_out) result_out->error = "Failed to read input file: " + input_path;
    return false;
  }

  if (!ProtectMemory(*pe_bytes, options, result_out)) {
    return false;
  }

  if (!tooling::WriteFile(output_path, *pe_bytes)) {
    if (result_out) result_out->error = "Failed to write protected binary to: " + output_path;
    return false;
  }

  return true;
}

}  // namespace rtprotect::tooling
