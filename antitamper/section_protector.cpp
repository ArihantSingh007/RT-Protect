// antitamper/section_protector.cpp
//
// Runtime Binary-Level In-Memory Section Decryption & Initialization Engine implementation.

#include "antitamper/section_protector.h"

#include <cstring>
#include <windows.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "antitamper/dynamic_import.h"

namespace rtprotect::antitamper {

namespace {

using VirtualProtectFn = BOOL (WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);
using GetModuleHandleAFn = HMODULE (WINAPI*)(LPCSTR);
using FlushInstructionCacheFn = BOOL (WINAPI*)(HANDLE, LPCVOID, SIZE_T);

std::uint32_t ComputeFnv1a(const std::uint8_t* data, std::size_t len) {
  std::uint32_t hash = 2166136261u;
  for (std::size_t i = 0; i < len; ++i) {
    hash ^= data[i];
    hash *= 16777619u;
  }
  return hash;
}

bool Aes256CtrDecrypt(const std::uint8_t* key,
                      const std::uint8_t* iv,
                      const std::uint8_t* input,
                      std::size_t len,
                      std::uint8_t* output) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return false;

  bool ok = false;
  do {
    if (EVP_CipherInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key, iv, 0) != 1) break;
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

const tooling::PeProtectedSectionHeader* FindProtectedSectionHeader(const void* module_base) {
  if (!module_base) {
    auto pGetModuleHandle = ResolveApi<GetModuleHandleAFn>(kHashKernel32, kHashGetModuleHandleA);
    if (!pGetModuleHandle) return nullptr;
    module_base = reinterpret_cast<const void*>(pGetModuleHandle(nullptr));
    if (!module_base) return nullptr;
  }

  const auto* base_bytes = reinterpret_cast<const std::uint8_t*>(module_base);
  const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base_bytes);
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

  // Check offset 0x40 in DOS stub padding
  const auto* candidate = reinterpret_cast<const tooling::PeProtectedSectionHeader*>(base_bytes + 0x40);
  if (candidate->magic == tooling::kPeProtectorMagic && candidate->version == 1) {
    return candidate;
  }

  return nullptr;
}

bool DecryptProtectedSectionInMemory(const tooling::PeProtectedSectionHeader& header, void* module_base) {
  if (!module_base) {
    auto pGetModuleHandle = ResolveApi<GetModuleHandleAFn>(kHashKernel32, kHashGetModuleHandleA);
    if (!pGetModuleHandle) return false;
    module_base = reinterpret_cast<void*>(pGetModuleHandle(nullptr));
    if (!module_base) return false;
  }

  auto pVirtualProtect = ResolveApi<VirtualProtectFn>(kHashKernel32, kHashVirtualProtect);
  if (!pVirtualProtect) return false;

  auto* base_bytes = reinterpret_cast<std::uint8_t*>(module_base);
  std::uint8_t* sec_addr = base_bytes + header.section_rva;

  // Make memory page writable
  DWORD old_protect = 0;
  if (!pVirtualProtect(sec_addr, header.section_size, PAGE_EXECUTE_READWRITE, &old_protect)) {
    return false;
  }

  // Validate ciphertext integrity before proceeding
  if (header.checksum != 0 && ComputeFnv1a(sec_addr, header.section_size) != header.checksum) {
    DWORD temp = 0;
    pVirtualProtect(sec_addr, header.section_size, old_protect, &temp);
    return false;
  }

  // Decrypt section in memory
  std::vector<std::uint8_t> decrypted(header.section_size);
  bool decrypt_ok = Aes256CtrDecrypt(header.key, header.iv, sec_addr, header.section_size, decrypted.data());
  if (!decrypt_ok) {
    DWORD temp = 0;
    pVirtualProtect(sec_addr, header.section_size, old_protect, &temp);
    return false;
  }

  // Copy decrypted code into execution location
  std::memcpy(sec_addr, decrypted.data(), header.section_size);

  // Cleanse sensitive decrypted buffer
  OPENSSL_cleanse(decrypted.data(), decrypted.size());

  // Restore memory page protection using the verified PAGE_* constant
  DWORD final_protect = header.original_protect ? header.original_protect : PAGE_EXECUTE_READ;
  DWORD temp = 0;
  if (!pVirtualProtect(sec_addr, header.section_size, final_protect, &temp)) {
    // Attempt fallback to PAGE_EXECUTE_READ
    pVirtualProtect(sec_addr, header.section_size, PAGE_EXECUTE_READ, &temp);
    return false;
  }

  // Flush instruction cache for the modified executable code range
  auto pFlushInstructionCache = ResolveApi<FlushInstructionCacheFn>(kHashKernel32, HashApi("FlushInstructionCache"));
  if (pFlushInstructionCache) {
    pFlushInstructionCache(GetCurrentProcess(), sec_addr, header.section_size);
  }

  return true;
}

bool InitializeProtectedBinary(void* module_base) {
  const auto* header = FindProtectedSectionHeader(module_base);
  if (!header) {
    // Binary does not contain an encrypted section
    return true;
  }

  return DecryptProtectedSectionInMemory(*header, module_base);
}

}  // namespace rtprotect::antitamper
