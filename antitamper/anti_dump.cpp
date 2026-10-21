// antitamper/anti_dump.cpp

#include "antitamper/anti_dump.h"
#include "antitamper/dynamic_import.h"

#include <algorithm>
#include <cstring>
#include <vector>

#include <openssl/crypto.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <fstream>
#include <string>
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace rtprotect::antitamper {

bool DetectMemoryDumper() {
#if defined(_WIN32)
  // 1. Detect dbghelp.dll which is required for MiniDumpWriteDump
  void* dbghelp_base = GetLoadedModuleBaseByHash(kHashDbgHelp);
  if (dbghelp_base != nullptr) {
    return true;
  }

  // 2. Scan loaded modules for signature hashes of prominent dumping tools
  static const std::uint32_t kDumperHashes[] = {
      HashApiCaseInsensitive("scylla.dll"),
      HashApiCaseInsensitive("scyllahide.dll"),
      HashApiCaseInsensitive("procdump.dll"),
      HashApiCaseInsensitive("cheatengine.dll"),
      HashApiCaseInsensitive("titanengine.dll")
  };

  for (std::uint32_t hash : kDumperHashes) {
    if (GetLoadedModuleBaseByHash(hash) != nullptr) {
      return true;
    }
  }

  return false;
#else
  // Linux: inspect /proc/self/maps for dumper frameworks
  std::ifstream maps("/proc/self/maps");
  std::string line;
  while (maps && std::getline(maps, line)) {
    static const char* const kDumperKeywords[] = {
        "scylla", "procdump", "gcore", "cheatengine"
    };
    for (const char* kw : kDumperKeywords) {
      if (line.find(kw) != std::string::npos) {
        return true;
      }
    }
  }
  return false;
#endif
}

bool DetectMemoryProbing() {
#if defined(_WIN32)
  // Resolve VirtualQuery export via dynamic hashed lookup to inspect hook status
  auto pVirtualQuery = ResolveApi<const unsigned char*>(kHashKernel32, kHashVirtualQuery);
  if (!pVirtualQuery) {
    pVirtualQuery = ResolveApi<const unsigned char*>(kHashKernelBase, kHashVirtualQuery);
  }

  if (pVirtualQuery) {
    // Check for INT 3 software breakpoint (0xCC)
    if (pVirtualQuery[0] == 0xCC) return true;
    // Check for 32-bit relative JMP (0xE9)
    if (pVirtualQuery[0] == 0xE9) return true;
    // Check for 64-bit indirect JMP [rip + disp32] (0xFF 0x25)
    if (pVirtualQuery[0] == 0xFF && pVirtualQuery[1] == 0x25) return true;
    // Check for MOV RAX, imm64; JMP RAX (0x48 0xB8 ... 0xFF 0xE0)
    if (pVirtualQuery[0] == 0x48 && pVirtualQuery[1] == 0xB8) {
      if (pVirtualQuery[10] == 0xFF && pVirtualQuery[11] == 0xE0) return true;
    }
  }

  return false;
#else
  return false;
#endif
}

bool EraseProcessHeaders() {
#if defined(_WIN32)
  auto* base = reinterpret_cast<std::uint8_t*>(::GetModuleHandleA(nullptr));
  if (!base) return false;

  auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
    return false;
  }

  DWORD old_prot = 0;
  // Dynamic API resolution for VirtualProtect to avoid static IAT entry
  typedef BOOL (WINAPI *pfnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
  auto fnVirtualProtect = ResolveApi<pfnVirtualProtect>(kHashKernel32, kHashVirtualProtect);
  if (!fnVirtualProtect) {
    fnVirtualProtect = ResolveApi<pfnVirtualProtect>(kHashKernelBase, kHashVirtualProtect);
  }
  if (!fnVirtualProtect) {
    return false;
  }

  // PE Header page size is 4096 bytes
  constexpr std::size_t kHeaderPageSize = 4096;
  if (!fnVirtualProtect(base, kHeaderPageSize, PAGE_READWRITE, &old_prot)) {
    return false;
  }

  // Cleanse DOS header and NT headers
  OPENSSL_cleanse(base, kHeaderPageSize);

  // Set to PAGE_READONLY or PAGE_NOACCESS to prevent dumping
  fnVirtualProtect(base, kHeaderPageSize, PAGE_READONLY, &old_prot);
  return true;
#else
  return true;
#endif
}

EphemeralExecutionGuard::EphemeralExecutionGuard() = default;

EphemeralExecutionGuard::~EphemeralExecutionGuard() {
  Cleanup();
}

EphemeralExecutionGuard::EphemeralExecutionGuard(EphemeralExecutionGuard&& other) noexcept
    : memory_(other.memory_), allocated_size_(other.allocated_size_) {
  other.memory_ = nullptr;
  other.allocated_size_ = 0;
}

EphemeralExecutionGuard& EphemeralExecutionGuard::operator=(EphemeralExecutionGuard&& other) noexcept {
  if (this != &other) {
    Cleanup();
    memory_ = other.memory_;
    allocated_size_ = other.allocated_size_;
    other.memory_ = nullptr;
    other.allocated_size_ = 0;
  }
  return *this;
}

void EphemeralExecutionGuard::Cleanup() {
  if (memory_ && allocated_size_ > 0) {
#if defined(_WIN32)
    DWORD old_prot = 0;
    typedef BOOL (WINAPI *pfnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
    typedef BOOL (WINAPI *pfnVirtualFree)(LPVOID, SIZE_T, DWORD);

    auto fnVirtualProtect = ResolveApi<pfnVirtualProtect>(kHashKernel32, kHashVirtualProtect);
    auto fnVirtualFree = ResolveApi<pfnVirtualFree>(kHashKernel32, HashApi("VirtualFree"));

    if (fnVirtualProtect) {
      fnVirtualProtect(memory_, allocated_size_, PAGE_READWRITE, &old_prot);
    }
    OPENSSL_cleanse(memory_, allocated_size_);
    if (fnVirtualFree) {
      fnVirtualFree(memory_, 0, MEM_RELEASE);
    } else {
      ::VirtualFree(memory_, 0, MEM_RELEASE);
    }
#else
    mprotect(memory_, allocated_size_, PROT_READ | PROT_WRITE);
    OPENSSL_cleanse(memory_, allocated_size_);
    munmap(memory_, allocated_size_);
#endif
    memory_ = nullptr;
    allocated_size_ = 0;
  }
}

bool EphemeralExecutionGuard::ExecuteEphemeral(const std::uint8_t* code_bytes,
                                              std::size_t code_size,
                                              std::int64_t arg,
                                              std::int64_t* out_result) {
  if (!code_bytes || code_size == 0 || !out_result) {
    return false;
  }

  Cleanup();

#if defined(_WIN32)
  typedef LPVOID (WINAPI *pfnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
  typedef BOOL (WINAPI *pfnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
  typedef BOOL (WINAPI *pfnFlushInstructionCache)(HANDLE, LPCVOID, SIZE_T);

  auto fnVirtualAlloc = ResolveApi<pfnVirtualAlloc>(kHashKernel32, kHashVirtualAlloc);
  auto fnVirtualProtect = ResolveApi<pfnVirtualProtect>(kHashKernel32, kHashVirtualProtect);
  auto fnFlushCache = ResolveApi<pfnFlushInstructionCache>(kHashKernel32, HashApi("FlushInstructionCache"));

  if (!fnVirtualAlloc || !fnVirtualProtect) {
    return false;
  }

  // Allocate page-aligned memory
  std::size_t page_size = 4096;
  std::size_t alloc_size = (code_size + page_size - 1) & ~(page_size - 1);
  void* mem = fnVirtualAlloc(nullptr, alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!mem) {
    return false;
  }

  memory_ = mem;
  allocated_size_ = alloc_size;

  std::memcpy(memory_, code_bytes, code_size);

  DWORD old_prot = 0;
  if (!fnVirtualProtect(memory_, allocated_size_, PAGE_EXECUTE_READ, &old_prot)) {
    Cleanup();
    return false;
  }

  if (fnFlushCache) {
    fnFlushCache(::GetCurrentProcess(), memory_, allocated_size_);
  }

  typedef std::int64_t (*PayloadFunc)(std::int64_t);
  auto func = reinterpret_cast<PayloadFunc>(memory_);
  *out_result = func(arg);

  // Immediately wipe and release ephemeral memory upon completion
  Cleanup();
  return true;

#else
  std::size_t page_size = static_cast<std::size_t>(sysconf(_SC_PAGESIZE));
  std::size_t alloc_size = (code_size + page_size - 1) & ~(page_size - 1);

  void* mem = mmap(nullptr, alloc_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mem == MAP_FAILED) {
    return false;
  }

  memory_ = mem;
  allocated_size_ = alloc_size;

  std::memcpy(memory_, code_bytes, code_size);

  if (mprotect(memory_, allocated_size_, PROT_READ | PROT_EXEC) != 0) {
    Cleanup();
    return false;
  }

  typedef std::int64_t (*PayloadFunc)(std::int64_t);
  auto func = reinterpret_cast<PayloadFunc>(memory_);
  *out_result = func(arg);

  Cleanup();
  return true;
#endif
}

}  // namespace rtprotect::antitamper
