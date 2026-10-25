// antitamper/section_protector.cpp
//
// Runtime Binary-Level In-Memory Section Decryption & Initialization Engine implementation.

#include "antitamper/section_protector.h"

#include <atomic>
#include <cstring>
#include <limits>
#include <mutex>
#include <utility>
#include <vector>
#include <windows.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "antitamper/dynamic_import.h"

namespace rtprotect::antitamper {

namespace {

using VirtualProtectFn = BOOL (WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);
using GetModuleHandleAFn = HMODULE (WINAPI*)(LPCSTR);
using FlushInstructionCacheFn = BOOL (WINAPI*)(HANDLE, LPCVOID, SIZE_T);

bool Aes256GcmEncrypt(const std::uint8_t* key,
                      const std::uint8_t* iv,
                      const std::uint8_t* input,
                      std::size_t len,
                      std::uint8_t* output,
                      std::uint8_t* tag) {
  if (len > static_cast<std::size_t>(std::numeric_limits<int>::max())) return false;
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return false;

  bool ok = false;
  do {
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1) break;
    int out_len = 0;
    if (EVP_EncryptUpdate(ctx, output, &out_len, input, static_cast<int>(len)) != 1) break;
    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, output + out_len, &final_len) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) break;
    ok = true;
  } while (false);

  EVP_CIPHER_CTX_free(ctx);
  return ok;
}

bool Aes256GcmDecrypt(const std::uint8_t* key,
                      const std::uint8_t* iv,
                      const std::uint8_t* input,
                      std::size_t len,
                      std::uint8_t* output,
                      const std::uint8_t* tag) {
  if (len > static_cast<std::size_t>(std::numeric_limits<int>::max())) return false;
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return false;

  bool ok = false;
  do {
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1) break;
    int out_len = 0;
    if (EVP_DecryptUpdate(ctx, output, &out_len, input, static_cast<int>(len)) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<std::uint8_t*>(tag)) != 1) break;
    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx, output + out_len, &final_len) != 1) break;
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
  if (dos->e_lfanew < static_cast<LONG>(0x40 + sizeof(tooling::PeProtectedSectionHeader))) {
    return nullptr;
  }

  // Check offset 0x40 in DOS stub padding
  const auto* candidate = reinterpret_cast<const tooling::PeProtectedSectionHeader*>(base_bytes + 0x40);
  if (candidate->magic == tooling::kPeProtectorMagic && candidate->version == 2) {
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
  const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base_bytes);
  if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < static_cast<LONG>(sizeof(IMAGE_DOS_HEADER))) return false;
  const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base_bytes + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
      header.section_size == 0 ||
      static_cast<std::uint64_t>(header.section_rva) + header.section_size > nt->OptionalHeader.SizeOfImage ||
      header.section_size > static_cast<std::uint32_t>(std::numeric_limits<int>::max())) return false;
  std::uint8_t* sec_addr = base_bytes + header.section_rva;

  // Make memory page writable
  DWORD old_protect = 0;
  if (!pVirtualProtect(sec_addr, header.section_size, PAGE_EXECUTE_READWRITE, &old_protect)) {
    return false;
  }

  // Authenticate and decrypt into a temporary buffer before modifying code.
  std::vector<std::uint8_t> decrypted(header.section_size);
  bool decrypt_ok = Aes256GcmDecrypt(header.key, header.iv, sec_addr, header.section_size, decrypted.data(), header.tag);
  if (!decrypt_ok) {
    OPENSSL_cleanse(decrypted.data(), decrypted.size());
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

bool EncryptProtectedSectionInMemory(const tooling::PeProtectedSectionHeader& header, void* module_base) {
  if (!module_base) {
    auto pGetModuleHandle = ResolveApi<GetModuleHandleAFn>(kHashKernel32, kHashGetModuleHandleA);
    if (!pGetModuleHandle) return false;
    module_base = reinterpret_cast<void*>(pGetModuleHandle(nullptr));
    if (!module_base) return false;
  }

  auto pVirtualProtect = ResolveApi<VirtualProtectFn>(kHashKernel32, kHashVirtualProtect);
  if (!pVirtualProtect) return false;

  auto* base_bytes = reinterpret_cast<std::uint8_t*>(module_base);
  const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base_bytes);
  if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < static_cast<LONG>(sizeof(IMAGE_DOS_HEADER))) return false;
  const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base_bytes + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
      header.section_size == 0 ||
      static_cast<std::uint64_t>(header.section_rva) + header.section_size > nt->OptionalHeader.SizeOfImage ||
      header.section_size > static_cast<std::uint32_t>(std::numeric_limits<int>::max())) return false;
  std::uint8_t* sec_addr = base_bytes + header.section_rva;

  DWORD old_protect = 0;
  if (!pVirtualProtect(sec_addr, header.section_size, PAGE_READWRITE, &old_protect)) {
    return false;
  }

  std::vector<std::uint8_t> encrypted(header.section_size);
  std::uint8_t new_tag[16]{};
  bool enc_ok = Aes256GcmEncrypt(header.key, header.iv, sec_addr, header.section_size, encrypted.data(), new_tag);
  if (enc_ok) {
    std::memcpy(sec_addr, encrypted.data(), header.section_size);
  } else {
    OPENSSL_cleanse(encrypted.data(), encrypted.size());
    DWORD temp = 0;
    pVirtualProtect(sec_addr, header.section_size, old_protect, &temp);
    return false;
  }
  OPENSSL_cleanse(encrypted.data(), encrypted.size());

  // Revoke read/write/execute permissions to defeat in-memory dumpers
  DWORD temp = 0;
  pVirtualProtect(sec_addr, header.section_size, PAGE_NOACCESS, &temp);

  auto pFlushInstructionCache = ResolveApi<FlushInstructionCacheFn>(kHashKernel32, HashApi("FlushInstructionCache"));
  if (pFlushInstructionCache) {
    pFlushInstructionCache(GetCurrentProcess(), sec_addr, header.section_size);
  }

  return true;
}

namespace {
std::atomic<int> s_scoped_section_refcount{0};
std::mutex s_scoped_section_mutex;
}  // namespace

ScopedSectionExecution::ScopedSectionExecution(const tooling::PeProtectedSectionHeader* header, void* module_base)
    : header_(header), module_base_(module_base) {
  if (!header_) {
    header_ = FindProtectedSectionHeader(module_base_);
  }
  if (!header_) {
    // If no protected section exists, scope is implicitly valid
    active_ = true;
    return;
  }

  std::lock_guard<std::mutex> lock(s_scoped_section_mutex);
  if (s_scoped_section_refcount == 0) {
    active_ = DecryptProtectedSectionInMemory(*header_, module_base_);
    if (active_) {
      ++s_scoped_section_refcount;
    }
  } else {
    ++s_scoped_section_refcount;
    active_ = true;
  }
}

ScopedSectionExecution::~ScopedSectionExecution() {
  if (!header_ || !active_) return;

  std::lock_guard<std::mutex> lock(s_scoped_section_mutex);
  if (s_scoped_section_refcount > 0 && --s_scoped_section_refcount == 0) {
    EncryptProtectedSectionInMemory(*header_, module_base_);
  }
}

ScopedSectionExecution::ScopedSectionExecution(ScopedSectionExecution&& other) noexcept
    : header_(other.header_), module_base_(other.module_base_), active_(other.active_) {
  other.header_ = nullptr;
  other.active_ = false;
}

ScopedSectionExecution& ScopedSectionExecution::operator=(ScopedSectionExecution&& other) noexcept {
  if (this != &other) {
    if (header_ && active_) {
      std::lock_guard<std::mutex> lock(s_scoped_section_mutex);
      if (s_scoped_section_refcount > 0 && --s_scoped_section_refcount == 0) {
        EncryptProtectedSectionInMemory(*header_, module_base_);
      }
    }
    header_ = other.header_;
    module_base_ = other.module_base_;
    active_ = other.active_;
    other.header_ = nullptr;
    other.active_ = false;
  }
  return *this;
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
