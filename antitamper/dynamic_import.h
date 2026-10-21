// antitamper/dynamic_import.h
//
// Dynamic hashed API import resolution.
//
// Resolves Windows/POSIX system APIs at runtime by computing compile-time hashes
// of module and export names and walking the process's loaded module list and
// Export Address Table (EAT) directly.
//
// This eliminates sensitive security/anti-debug API names (e.g., IsDebuggerPresent,
// CheckRemoteDebuggerPresent, NtQueryInformationProcess, VirtualProtect) from
// the PE Import Address Table (IAT) and static string tables, preventing automated
// static analysis tools from locating anti-tamper checkpoints.

#pragma once

#include <cstddef>
#include <cstdint>

namespace rtprotect::antitamper {

// Compile-time FNV-1a 32-bit hash for ASCII strings
constexpr std::uint32_t HashApi(const char* str) {
  std::uint32_t hash = 2166136261u;
  while (*str) {
    hash ^= static_cast<std::uint8_t>(*str++);
    hash *= 16777619u;
  }
  return hash;
}

// Compile-time case-insensitive FNV-1a 32-bit hash for module names
constexpr std::uint32_t HashApiCaseInsensitive(const char* str) {
  std::uint32_t hash = 2166136261u;
  while (*str) {
    char c = *str++;
    if (c >= 'A' && c <= 'Z') {
      c = static_cast<char>(c + ('a' - 'A'));
    }
    hash ^= static_cast<std::uint8_t>(c);
    hash *= 16777619u;
  }
  return hash;
}

// Wide-character case-insensitive FNV-1a 32-bit hash for PEB UNICODE_STRING
constexpr std::uint32_t HashApiWideCaseInsensitive(const wchar_t* str, std::size_t len) {
  std::uint32_t hash = 2166136261u;
  for (std::size_t i = 0; i < len; ++i) {
    wchar_t c = str[i];
    if (c >= L'A' && c <= L'Z') {
      c = static_cast<wchar_t>(c + (L'a' - L'A'));
    }
    hash ^= static_cast<std::uint8_t>(c & 0xFF);
    hash *= 16777619u;
  }
  return hash;
}

// Pre-computed module hashes (case-insensitive)
inline constexpr std::uint32_t kHashKernel32   = HashApiCaseInsensitive("kernel32.dll");
inline constexpr std::uint32_t kHashNtdll      = HashApiCaseInsensitive("ntdll.dll");
inline constexpr std::uint32_t kHashKernelBase = HashApiCaseInsensitive("kernelbase.dll");
inline constexpr std::uint32_t kHashDbgHelp    = HashApiCaseInsensitive("dbghelp.dll");
inline constexpr std::uint32_t kHashUser32     = HashApiCaseInsensitive("user32.dll");

// Pre-computed function export hashes (case-sensitive)
inline constexpr std::uint32_t kHashIsDebuggerPresent          = HashApi("IsDebuggerPresent");
inline constexpr std::uint32_t kHashCheckRemoteDebuggerPresent = HashApi("CheckRemoteDebuggerPresent");
inline constexpr std::uint32_t kHashNtQueryInformationProcess  = HashApi("NtQueryInformationProcess");
inline constexpr std::uint32_t kHashVirtualProtect             = HashApi("VirtualProtect");
inline constexpr std::uint32_t kHashVirtualAlloc               = HashApi("VirtualAlloc");
inline constexpr std::uint32_t kHashVirtualQuery               = HashApi("VirtualQuery");
inline constexpr std::uint32_t kHashGetProcAddress             = HashApi("GetProcAddress");
inline constexpr std::uint32_t kHashGetModuleHandleA           = HashApi("GetModuleHandleA");
inline constexpr std::uint32_t kHashLoadLibraryA               = HashApi("LoadLibraryA");
inline constexpr std::uint32_t kHashMiniDumpWriteDump          = HashApi("MiniDumpWriteDump");
inline constexpr std::uint32_t kHashCreateToolhelp32Snapshot   = HashApi("CreateToolhelp32Snapshot");
inline constexpr std::uint32_t kHashThread32First              = HashApi("Thread32First");
inline constexpr std::uint32_t kHashThread32Next               = HashApi("Thread32Next");
inline constexpr std::uint32_t kHashOpenThread                 = HashApi("OpenThread");
inline constexpr std::uint32_t kHashGetThreadContext           = HashApi("GetThreadContext");
inline constexpr std::uint32_t kHashCloseHandle                = HashApi("CloseHandle");
inline constexpr std::uint32_t kHashGetCurrentProcess          = HashApi("GetCurrentProcess");
inline constexpr std::uint32_t kHashGetCurrentProcessId        = HashApi("GetCurrentProcessId");
inline constexpr std::uint32_t kHashGetCurrentThreadId         = HashApi("GetCurrentThreadId");

// Obtains the base address of a loaded module by walking the PEB LDR table
void* GetLoadedModuleBaseByHash(std::uint32_t module_hash);

// Resolves a function export address from the given module base by walking its EAT
void* ResolveExportByHash(void* module_base, std::uint32_t function_hash);

// Resolves a function export address by module hash and function hash
void* ResolveExportByHash(std::uint32_t module_hash, std::uint32_t function_hash);

// Type-safe dynamic resolution template helper
template <typename FuncPtr>
inline FuncPtr ResolveApi(std::uint32_t module_hash, std::uint32_t func_hash) {
  return reinterpret_cast<FuncPtr>(ResolveExportByHash(module_hash, func_hash));
}

}  // namespace rtprotect::antitamper
