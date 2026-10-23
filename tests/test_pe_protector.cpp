// tests/test_pe_protector.cpp
//
// Comprehensive unit tests for Binary-Level PE Protector & Runtime Decryption.

#include <cstring>
#include <vector>

#include <windows.h>

#include "antitamper/section_protector.h"
#include "tests/micro_test.h"
#include "tooling/pe_protector.h"

using namespace rtprotect::tooling;
using namespace rtprotect::antitamper;

namespace {

std::vector<std::uint8_t> CreateSyntheticPe64() {
  // Allocate synthetic PE image with headers and .text section
  std::vector<std::uint8_t> pe(4096, 0);

  // 1. DOS Header
  auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(pe.data());
  dos->e_magic = IMAGE_DOS_SIGNATURE; // 0x5A4D
  dos->e_lfanew = 0x100; // 256 bytes offset to NT header

  // 2. NT Headers (x64)
  auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(pe.data() + dos->e_lfanew);
  nt->Signature = IMAGE_NT_SIGNATURE; // 0x4550
  nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64; // 0x8664
  nt->FileHeader.NumberOfSections = 1;
  nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
  nt->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;

  nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC; // 0x020B
  nt->OptionalHeader.AddressOfEntryPoint = 0x1000;
  nt->OptionalHeader.ImageBase = 0x140000000;
  nt->OptionalHeader.SectionAlignment = 0x1000;
  nt->OptionalHeader.FileAlignment = 0x200;
  nt->OptionalHeader.SizeOfImage = 0x2000;
  nt->OptionalHeader.SizeOfHeaders = 0x400;

  // 3. Section Header for .text
  auto* sec = IMAGE_FIRST_SECTION(nt);
  std::memcpy(sec->Name, ".text\0\0\0", 8);
  sec->VirtualAddress = 0x1000;
  sec->Misc.VirtualSize = 0x200;
  sec->PointerToRawData = 0x400;
  sec->SizeOfRawData = 0x200;
  sec->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

  // 4. Populate .text section with recognizable code bytes (x64 NOPs and instructions)
  std::uint8_t* code = pe.data() + sec->PointerToRawData;
  for (std::size_t i = 0; i < sec->SizeOfRawData; ++i) {
    code[i] = static_cast<std::uint8_t>((0x90 + (i % 31)) & 0xFF);
  }

  return pe;
}

}  // namespace

MT_TEST(PeProtector_RejectsInvalidPeHeaders) {
  std::vector<std::uint8_t> invalid_data = {0x00, 0x11, 0x22, 0x33};
  MT_CHECK(!PeProtector::IsValidPe64(invalid_data));

  PeProtectionOptions opts;
  PeProtectionResult res;
  MT_CHECK(!PeProtector::ProtectMemory(invalid_data, opts, &res));
  MT_CHECK(!res.success);

  // Security Audit Regression: Test buffers in the 64..263 byte window (and up to e_lfanew + sizeof(NT_HEADERS))
  // where pe_image.size() < sizeof(IMAGE_NT_HEADERS64) would cause integer underflow in bounds checks
  for (std::size_t sz : {64, 65, 100, 128, 200, 263, 264, 300, 327}) {
    std::vector<std::uint8_t> small_pe(sz, 0);
    auto* dos_small = reinterpret_cast<IMAGE_DOS_HEADER*>(small_pe.data());
    dos_small->e_magic = IMAGE_DOS_SIGNATURE;
    dos_small->e_lfanew = static_cast<LONG>(sizeof(IMAGE_DOS_HEADER)); // 64 bytes
    // Must be rejected safely without out-of-bounds reads or underflow
    MT_CHECK(!PeProtector::IsValidPe64(small_pe));

    PeProtectionResult small_res;
    MT_CHECK(!PeProtector::ProtectMemory(small_pe, opts, &small_res));
    MT_CHECK(!small_res.success);
  }

  // Test truncated NT headers
  auto pe_trunc = CreateSyntheticPe64();
  auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(pe_trunc.data());
  dos->e_lfanew = static_cast<LONG>(pe_trunc.size() - 10); // Not enough space for IMAGE_NT_HEADERS64
  MT_CHECK(!PeProtector::IsValidPe64(pe_trunc));

  // Test section table extending beyond file bounds
  auto pe_sec_overflow = CreateSyntheticPe64();
  auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(pe_sec_overflow.data() + 0x100);
  nt->FileHeader.NumberOfSections = 100; // 100 * 40 bytes = 4000 bytes, exceeds file size
  MT_CHECK(!PeProtector::IsValidPe64(pe_sec_overflow));

  // Test section raw data extending beyond file bounds
  auto pe_raw_overflow = CreateSyntheticPe64();
  auto* sec = IMAGE_FIRST_SECTION(reinterpret_cast<IMAGE_NT_HEADERS64*>(pe_raw_overflow.data() + 0x100));
  sec->PointerToRawData = 0x800;
  sec->SizeOfRawData = 0xFFFFFFFF; // Integer overflow attempt
  PeProtectionResult res2;
  MT_CHECK(!PeProtector::ProtectMemory(pe_raw_overflow, opts, &res2));
  MT_CHECK(!res2.success);
}

MT_TEST(PeProtector_ValidatesSyntheticPe64) {
  auto pe = CreateSyntheticPe64();
  MT_CHECK(PeProtector::IsValidPe64(pe));
}

MT_TEST(PeProtector_EncryptsCodeSectionAndEmbedsHeader) {
  auto pe = CreateSyntheticPe64();
  auto* sec = IMAGE_FIRST_SECTION(reinterpret_cast<IMAGE_NT_HEADERS64*>(pe.data() + 0x100));
  std::vector<std::uint8_t> original_code(pe.data() + sec->PointerToRawData,
                                          pe.data() + sec->PointerToRawData + sec->SizeOfRawData);

  PeProtectionOptions opts;
  opts.target_section = ".text";
  opts.encrypt_section = true;
  opts.obfuscate_imports = false;

  PeProtectionResult res;
  MT_CHECK(PeProtector::ProtectMemory(pe, opts, &res));
  MT_CHECK(res.success);
  MT_CHECK(res.section_bytes_encrypted == sec->SizeOfRawData);

  // Check that code section has been encrypted and is NOT identical to original
  std::vector<std::uint8_t> encrypted_code(pe.data() + sec->PointerToRawData,
                                           pe.data() + sec->PointerToRawData + sec->SizeOfRawData);
  MT_CHECK(encrypted_code != original_code);

  // Verify that the PeProtectedSectionHeader was embedded in the DOS stub area (offset 0x40)
  const auto* hdr = FindProtectedSectionHeader(pe.data());
  MT_CHECK(hdr != nullptr);
  MT_CHECK(hdr->magic == kPeProtectorMagic);
  MT_CHECK(hdr->version == 1);
  MT_CHECK(hdr->section_rva == sec->VirtualAddress);
  MT_CHECK(hdr->section_size == sec->SizeOfRawData);
}

MT_TEST(PeProtector_DecryptionRestoresOriginalCode) {
  auto pe = CreateSyntheticPe64();
  auto* sec = IMAGE_FIRST_SECTION(reinterpret_cast<IMAGE_NT_HEADERS64*>(pe.data() + 0x100));
  std::vector<std::uint8_t> original_code(pe.data() + sec->PointerToRawData,
                                          pe.data() + sec->PointerToRawData + sec->SizeOfRawData);

  PeProtectionOptions opts;
  opts.target_section = ".text";
  opts.encrypt_section = true;
  opts.obfuscate_imports = false;

  PeProtectionResult res;
  MT_CHECK(PeProtector::ProtectMemory(pe, opts, &res));
  MT_CHECK(res.success);

  // In our synthetic buffer, map VirtualAddress to PointerToRawData for the test environment
  // Windows VirtualProtect requires VirtualAlloc-backed page-aligned memory
  void* loaded_image = VirtualAlloc(nullptr, 0x3000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  MT_CHECK(loaded_image != nullptr);

  std::memcpy(loaded_image, pe.data(), 0x400); // Headers
  std::memcpy(static_cast<std::uint8_t*>(loaded_image) + sec->VirtualAddress,
              pe.data() + sec->PointerToRawData, sec->SizeOfRawData);

  const auto* hdr = FindProtectedSectionHeader(loaded_image);
  MT_CHECK(hdr != nullptr);

  // Decrypt section in the simulated loaded image
  bool decrypt_ok = DecryptProtectedSectionInMemory(*hdr, loaded_image);
  MT_CHECK(decrypt_ok);

  // Verify decrypted bytes match original plaintext code 100%
  const std::uint8_t* decrypted_code = static_cast<const std::uint8_t*>(loaded_image) + sec->VirtualAddress;
  MT_CHECK(std::memcmp(decrypted_code, original_code.data(), original_code.size()) == 0);

  VirtualFree(loaded_image, 0, MEM_RELEASE);
}

MT_MAIN()
