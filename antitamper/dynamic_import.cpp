// antitamper/dynamic_import.cpp

#include "antitamper/dynamic_import.h"

#include <algorithm>
#include <cstring>
#include <string>

#include <windows.h>
#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace rtprotect::antitamper {

namespace {

struct UNICODE_STR {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
};

struct LDR_DATA_ENTRY {
  LIST_ENTRY InLoadOrderLinks;
  LIST_ENTRY InMemoryOrderLinks;
  LIST_ENTRY InInitializationOrderLinks;
  PVOID DllBase;
  PVOID EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STR FullDllName;
  UNICODE_STR BaseDllName;
};

struct PEB_LDR {
  ULONG Length;
  BOOLEAN Initialized;
  PVOID SsHandle;
  LIST_ENTRY InLoadOrderModuleList;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
};

const unsigned char* GetProcessEnvironmentBlock() {
#if defined(_M_X64) || defined(__x86_64__)
  const unsigned char* peb = nullptr;
  #if defined(__GNUC__) || defined(__clang__)
  __asm__("movq %%gs:0x60, %0" : "=r"(peb));
  #elif defined(_MSC_VER)
  peb = reinterpret_cast<const unsigned char*>(__readgsqword(0x60));
  #endif
  return peb;
#elif defined(_M_IX86) || defined(__i386__)
  const unsigned char* peb = nullptr;
  #if defined(__GNUC__) || defined(__clang__)
  __asm__("movl %%fs:0x30, %0" : "=r"(peb));
  #elif defined(_MSC_VER)
  peb = reinterpret_cast<const unsigned char*>(__readfsdword(0x30));
  #endif
  return peb;
#else
  return nullptr;
#endif
}

}  // namespace

void* GetLoadedModuleBaseByHash(std::uint32_t module_hash) {
  const unsigned char* peb = GetProcessEnvironmentBlock();
  if (!peb) {
    return nullptr;
  }

#if defined(_M_X64) || defined(__x86_64__)
  // PEB.Ldr offset is 0x18 on x64
  const auto* ldr = *reinterpret_cast<const PEB_LDR* const*>(peb + 0x18);
#else
  // PEB.Ldr offset is 0x0C on x86
  const auto* ldr = *reinterpret_cast<const PEB_LDR* const*>(peb + 0x0C);
#endif

  if (!ldr) {
    return nullptr;
  }

  const LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
  const LIST_ENTRY* curr = head->Flink;

  while (curr && curr != head) {
    const auto* entry = reinterpret_cast<const LDR_DATA_ENTRY*>(curr);
    if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0) {
      std::size_t char_count = entry->BaseDllName.Length / sizeof(wchar_t);
      std::uint32_t hash = HashApiWideCaseInsensitive(entry->BaseDllName.Buffer, char_count);
      if (hash == module_hash) {
        return entry->DllBase;
      }
    }
    curr = curr->Flink;
  }

  return nullptr;
}

void* ResolveExportByHash(void* module_base, std::uint32_t function_hash) {
  if (!module_base) {
    return nullptr;
  }

  const auto* base = reinterpret_cast<const std::uint8_t*>(module_base);
  const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
    return nullptr;
  }

  const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE) {
    return nullptr;
  }

  const auto& export_dir_entry = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if (export_dir_entry.VirtualAddress == 0 || export_dir_entry.Size == 0) {
    return nullptr;
  }

  const auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
      base + export_dir_entry.VirtualAddress);

  const auto* name_rvas = reinterpret_cast<const std::uint32_t*>(
      base + exports->AddressOfNames);
  const auto* ordinals = reinterpret_cast<const std::uint16_t*>(
      base + exports->AddressOfNameOrdinals);
  const auto* func_rvas = reinterpret_cast<const std::uint32_t*>(
      base + exports->AddressOfFunctions);

  for (DWORD i = 0; i < exports->NumberOfNames; ++i) {
    const char* func_name = reinterpret_cast<const char*>(base + name_rvas[i]);
    if (HashApi(func_name) == function_hash) {
      std::uint16_t ordinal = ordinals[i];
      std::uint32_t func_rva = func_rvas[ordinal];

      // Check for forwarded export (falls inside export directory bounds)
      if (func_rva >= export_dir_entry.VirtualAddress &&
          static_cast<std::uint64_t>(func_rva) < static_cast<std::uint64_t>(export_dir_entry.VirtualAddress) + export_dir_entry.Size) {
        const char* forwarder = reinterpret_cast<const char*>(base + func_rva);
        std::string forward_str(forwarder);
        auto dot_pos = forward_str.find('.');
        if (dot_pos != std::string::npos) {
          std::string mod_name = forward_str.substr(0, dot_pos) + ".dll";
          std::string fn_name = forward_str.substr(dot_pos + 1);
          std::uint32_t mod_h = HashApiCaseInsensitive(mod_name.c_str());
          std::uint32_t fn_h = HashApi(fn_name.c_str());
          return ResolveExportByHash(mod_h, fn_h);
        }
        return nullptr;
      }

      return const_cast<std::uint8_t*>(base + func_rva);
    }
  }

  return nullptr;
}

void* ResolveExportByHash(std::uint32_t module_hash, std::uint32_t function_hash) {
  void* mod_base = GetLoadedModuleBaseByHash(module_hash);
  if (!mod_base) {
    // If not found in PEB (e.g. kernel32 vs kernelbase differences), try known fallback modules
    if (module_hash == kHashKernel32) {
      mod_base = GetLoadedModuleBaseByHash(kHashKernelBase);
    } else if (module_hash == kHashKernelBase) {
      mod_base = GetLoadedModuleBaseByHash(kHashKernel32);
    }
  }
  if (!mod_base) {
    return nullptr;
  }
  return ResolveExportByHash(mod_base, function_hash);
}

}  // namespace rtprotect::antitamper
