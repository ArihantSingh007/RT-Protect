// tooling/clang_ast_scanner.cpp

#include "tooling/clang_ast_scanner.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

#include "tooling/file_io.h"
#include "tooling/simple_json.h"

#include <windows.h>

namespace fs = std::filesystem;

namespace rtprotect::tooling {

namespace {

std::string NormalizePath(const std::string& p) {
  std::string s = p;
  std::replace(s.begin(), s.end(), '\\', '/');
#if defined(_WIN32)
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
#endif
  return s;
}

// Executes a subprocess directly via argv array without any shell interpreter (popen/cmd.exe/sh).
// Completely immune to shell command injection attacks.
bool RunProcessCaptureOutput(const std::string& exe,
                             const std::vector<std::string>& args,
                             std::string* out_stdout) {
  // Build properly MSVC-escaped command line using standard backslash/quote rules
  std::string cmd_line = "\"" + exe + "\"";
  for (const auto& a : args) {
    cmd_line += " ";
    if (a.empty()) {
      cmd_line += "\"\"";
      continue;
    }
    bool need_quote = false;
    for (char c : a) {
      if (std::isspace(static_cast<unsigned char>(c)) || c == '"') {
        need_quote = true;
        break;
      }
    }
    if (!need_quote) {
      cmd_line += a;
    } else {
      cmd_line += "\"";
      for (std::size_t i = 0; i < a.size(); ++i) {
        std::size_t backslashes = 0;
        while (i < a.size() && a[i] == '\\') {
          backslashes++;
          i++;
        }
        if (i == a.size()) {
          cmd_line.append(backslashes * 2, '\\');
          break;
        } else if (a[i] == '"') {
          cmd_line.append(backslashes * 2 + 1, '\\');
          cmd_line += '"';
        } else {
          cmd_line.append(backslashes, '\\');
          cmd_line += a[i];
        }
      }
      cmd_line += "\"";
    }
  }

  SECURITY_ATTRIBUTES sa{};
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;

  HANDLE hReadPipe = nullptr;
  HANDLE hWritePipe = nullptr;
  if (!::CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
    return false;
  }
  ::SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

  STARTUPINFOA si{};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  si.hStdOutput = hWritePipe;

  // Separate stderr from stdout: redirect stderr to NUL to prevent compiler diagnostics from corrupting JSON AST
  HANDLE hNul = ::CreateFileA("NUL", GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ, &sa, OPEN_EXISTING, 0, nullptr);
  si.hStdError = (hNul != INVALID_HANDLE_VALUE) ? hNul : hWritePipe;

  PROCESS_INFORMATION pi{};
  std::vector<char> cmd_buf(cmd_line.begin(), cmd_line.end());
  cmd_buf.push_back('\0');

  // Direct CreateProcessA invocation: NO cmd.exe shell wrapper
  BOOL ok = ::CreateProcessA(
      nullptr,
      cmd_buf.data(),
      nullptr,
      nullptr,
      TRUE,
      0,
      nullptr,
      nullptr,
      &si,
      &pi);

  ::CloseHandle(hWritePipe);
  if (hNul != INVALID_HANDLE_VALUE && hNul != hWritePipe) {
    ::CloseHandle(hNul);
  }

  if (!ok) {
    ::CloseHandle(hReadPipe);
    return false;
  }

  constexpr std::size_t kMaxCaptureBytes = 64 * 1024 * 1024; // 64 MB maximum output capture
  constexpr DWORD kTimeoutMs = 30000;                        // 30 seconds maximum process execution

  std::string output;
  char buf[4096];
  DWORD start_time = ::GetTickCount();
  bool timed_out = false;
  bool exceeded_cap = false;

  while (true) {
    DWORD elapsed = ::GetTickCount() - start_time;
    if (elapsed > kTimeoutMs) {
      timed_out = true;
      break;
    }

    DWORD bytes_avail = 0;
    if (!::PeekNamedPipe(hReadPipe, nullptr, 0, nullptr, &bytes_avail, nullptr)) {
      break; // Pipe broken / closed by child
    }

    if (bytes_avail > 0) {
      DWORD to_read = (bytes_avail > sizeof(buf)) ? sizeof(buf) : bytes_avail;
      DWORD bytes_read = 0;
      if (::ReadFile(hReadPipe, buf, to_read, &bytes_read, nullptr) && bytes_read > 0) {
        output.append(buf, bytes_read);
        if (output.size() > kMaxCaptureBytes) {
          exceeded_cap = true;
          break;
        }
      }
    } else {
      DWORD wait_res = ::WaitForSingleObject(pi.hProcess, 10);
      if (wait_res == WAIT_OBJECT_0) {
        DWORD final_avail = 0;
        if (::PeekNamedPipe(hReadPipe, nullptr, 0, nullptr, &final_avail, nullptr) && final_avail > 0) {
          DWORD bytes_read = 0;
          while (::ReadFile(hReadPipe, buf, sizeof(buf), &bytes_read, nullptr) && bytes_read > 0) {
            output.append(buf, bytes_read);
            if (output.size() > kMaxCaptureBytes) {
              exceeded_cap = true;
              break;
            }
          }
        }
        break;
      }
    }
  }

  ::CloseHandle(hReadPipe);

  if (timed_out || exceeded_cap) {
    ::TerminateProcess(pi.hProcess, 1);
    ::WaitForSingleObject(pi.hProcess, 2000);
    ::CloseHandle(pi.hThread);
    ::CloseHandle(pi.hProcess);
    return false;
  }

  ::WaitForSingleObject(pi.hProcess, 2000);
  DWORD exit_code = 1;
  ::GetExitCodeProcess(pi.hProcess, &exit_code);
  ::CloseHandle(pi.hThread);
  ::CloseHandle(pi.hProcess);

  if (out_stdout) *out_stdout = std::move(output);
  return (exit_code == 0);
}

}  // namespace

std::optional<CompilationDatabase> CompilationDatabase::LoadFromFile(const std::string& json_path) {
  auto content = ReadTextFile(json_path);
  if (!content.has_value() || content->empty()) return std::nullopt;

  auto parsed = JsonValue::Parse(*content);
  if (!parsed.has_value() || !parsed->is_array()) return std::nullopt;

  CompilationDatabase db;
  for (const auto& item : parsed->as_array()) {
    if (!item.is_object()) continue;

    CompileCommandEntry entry;
    entry.file = item["file"].as_string();
    entry.directory = item["directory"].as_string();
    entry.command = item["command"].as_string();

    if (item.contains("arguments") && item["arguments"].is_array()) {
      for (const auto& arg : item["arguments"].as_array()) {
        entry.arguments.push_back(arg.as_string());
      }
    }

    if (!entry.file.empty()) {
      db.entries_[NormalizePath(entry.file)] = entry;
    }
  }

  return db;
}

std::optional<CompilationDatabase> CompilationDatabase::LoadFromDirectory(const std::string& build_dir) {
  fs::path p = fs::path(build_dir) / "compile_commands.json";
  if (fs::exists(p)) {
    return LoadFromFile(p.string());
  }
  return std::nullopt;
}

std::vector<std::string> CompilationDatabase::GetFlagsForFile(const std::string& file_path) const {
  std::string norm = NormalizePath(file_path);
  auto it = entries_.find(norm);
  if (it == entries_.end()) {
    return { "-std=c++20", "-I." };
  }

  if (!it->second.arguments.empty()) {
    std::vector<std::string> flags;
    bool skip_next = false;
    for (std::size_t i = 1; i < it->second.arguments.size(); ++i) {
      const auto& arg = it->second.arguments[i];
      if (skip_next) {
        skip_next = false;
        continue;
      }
      if (arg == "-c") continue;
      if (arg == "-o") {
        skip_next = true;
        continue;
      }
      if (arg == it->second.file || NormalizePath(arg) == norm) continue;
      flags.push_back(arg);
    }
    return flags;
  }

  std::vector<std::string> flags;
  std::istringstream iss(it->second.command);
  std::string token;
  bool skip_next = false;
  bool is_first = true;

  while (iss >> token) {
    if (is_first) {
      is_first = false;
      continue;
    }
    if (skip_next) {
      skip_next = false;
      continue;
    }
    if (token == "-c") continue;
    if (token == "-o") {
      skip_next = true;
      continue;
    }
    if (token == it->second.file || NormalizePath(token) == norm) continue;
    flags.push_back(token);
  }

  return flags;
}

bool ClangAstScanner::IsAvailable() {
  std::string bin = GetClangBinaryPath();
  return !bin.empty();
}

std::string ClangAstScanner::GetClangBinaryPath() {
  static const char* const kKnownPaths[] = {
      "C:\\Program Files\\LLVM\\bin\\clang.exe",
      "C:\\msys64\\mingw64\\bin\\clang.exe",
      "C:\\msys64\\ucrt64\\bin\\clang.exe"
  };

  std::error_code ec;
  for (const char* path : kKnownPaths) {
    if (fs::exists(path, ec) && !fs::is_directory(path, ec)) return path;
  }

  // Search system PATH environment variable
  const char* env_path = std::getenv("PATH");
  if (env_path) {
    std::string path_str(env_path);
    char delimiter = ';';
    std::string binary_name = "clang.exe";
    std::size_t start = 0;
    while (start < path_str.size()) {
      auto end = path_str.find(delimiter, start);
      if (end == std::string::npos) end = path_str.size();
      std::string dir = path_str.substr(start, end - start);
      if (!dir.empty()) {
        fs::path candidate = fs::path(dir) / binary_name;
        if (fs::exists(candidate, ec) && !fs::is_directory(candidate, ec)) {
          return candidate.string();
        }
      }
      start = end + 1;
    }
  }

  // Win32 where.exe fallback without shell interpolation
  std::string out;
  if (RunProcessCaptureOutput("where.exe", { "clang.exe" }, &out) && !out.empty()) {
    auto nl = out.find('\n');
    if (nl != std::string::npos) out = out.substr(0, nl);
    while (!out.empty() && (out.back() == '\r' || out.back() == ' ')) out.pop_back();
    if (fs::exists(out, ec) && !fs::is_directory(out, ec)) return out;
  }

  return "";
}

namespace {

bool IsValidVmType(const std::string& type_str, bool allow_void) {
  std::string s = type_str;
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();

  if (s.rfind("const ", 0) == 0) s = s.substr(6);
  if (s.rfind("volatile ", 0) == 0) s = s.substr(9);
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();

  if (s.size() > 6 && s.substr(s.size() - 6) == " const") s = s.substr(0, s.size() - 6);

  // Strictly disallow pointers (*), references (&), arrays ([]), templates (<>), ellipses (...)
  if (s.find('*') != std::string::npos) return false;
  if (s.find('&') != std::string::npos) return false;
  if (s.find('[') != std::string::npos) return false;
  if (s.find('<') != std::string::npos) return false;
  if (s.find("...") != std::string::npos) return false;

  if (allow_void && s == "void") return true;

  static const char* const kExactPrimitives[] = {
      "int", "signed int", "unsigned int",
      "short", "signed short", "unsigned short", "short int", "unsigned short int",
      "long", "signed long", "unsigned long", "long int", "unsigned long int",
      "long long", "signed long long", "unsigned long long", "long long int", "unsigned long long int",
      "char", "signed char", "unsigned char",
      "bool", "_Bool",
      "int8_t", "int16_t", "int32_t", "int64_t",
      "uint8_t", "uint16_t", "uint32_t", "uint64_t",
      "std::int8_t", "std::int16_t", "std::int32_t", "std::int64_t",
      "std::uint8_t", "std::uint16_t", "std::uint32_t", "std::uint64_t",
      "size_t", "std::size_t",
      "float", "double"
  };

  for (const char* prim : kExactPrimitives) {
    if (s == prim) return true;
  }
  return false;
}

}  // namespace

bool ClangAstScanner::ValidateVirtualizationEligibility(const ClangFunctionDecl& fn, std::string* out_reason) {
  if (fn.has_unsupported_constructs) {
    if (out_reason) *out_reason = fn.unsupported_reason;
    return false;
  }

  if (fn.param_types.size() > 4) {
    if (out_reason) *out_reason = "Function parameter count exceeds VM argument capacity (max 4)";
    return false;
  }

  if (!IsValidVmType(fn.return_type, /*allow_void=*/true)) {
    if (out_reason) *out_reason = "Unsupported return type for bytecode VM (pointers, references, structs are prohibited): " + fn.return_type;
    return false;
  }

  for (std::size_t i = 0; i < fn.param_types.size(); ++i) {
    const auto& pt = fn.param_types[i];
    if (!IsValidVmType(pt, /*allow_void=*/false)) {
      if (out_reason) *out_reason = "Unsupported parameter " + std::to_string(i + 1) + " type for bytecode VM (must be primitive scalar/float): " + pt;
      return false;
    }
  }

  return true;
}

std::vector<ClangFunctionDecl> ClangAstScanner::AnalyzeTranslationUnit(
    const std::string& source_path,
    const std::vector<std::string>& compiler_flags) {
  std::vector<ClangFunctionDecl> results;
  std::string clang_bin = GetClangBinaryPath();
  if (clang_bin.empty()) return results;

  // Build argv array: NO shell string concatenation, NO popen
  std::vector<std::string> args = {
      "-fsyntax-only",
      "-Xclang",
      "-ast-dump=json"
  };
  for (const auto& flag : compiler_flags) {
    if (!flag.empty()) {
      args.push_back(flag);
    }
  }
  args.push_back(source_path);

  std::string json_output;
  if (!RunProcessCaptureOutput(clang_bin, args, &json_output) || json_output.empty()) {
    return results;
  }

  auto src_text = ReadTextFile(source_path);
  if (!src_text.has_value()) return results;

  auto ast_root = JsonValue::Parse(json_output);
  if (!ast_root.has_value() || !ast_root->is_object()) {
    return results;
  }

  // Robustly traverse AST using simple_json
  std::vector<const JsonValue*> nodes_to_visit = { &(*ast_root) };
  while (!nodes_to_visit.empty()) {
    const JsonValue* node = nodes_to_visit.back();
    nodes_to_visit.pop_back();

    if (node->contains("kind") && (*node)["kind"].as_string() == "FunctionDecl") {
      std::string fn_name = (*node)["name"].as_string();
      if (!fn_name.empty()) {
        std::size_t src_fn_pos = std::string::npos;
        if (node->contains("loc") && (*node)["loc"].contains("offset")) {
          src_fn_pos = static_cast<std::size_t>((*node)["loc"]["offset"].as_int());
        }
        if (src_fn_pos == std::string::npos || src_fn_pos > src_text->size()) {
          src_fn_pos = src_text->find(fn_name);
        }

        if (src_fn_pos != std::string::npos) {
          std::size_t lookback = (src_fn_pos >= 250) ? 250 : src_fn_pos;
          std::string prefix = src_text->substr(src_fn_pos - lookback, lookback);

          bool is_tagged = (prefix.find("RTPROTECT_VIRTUALIZE") != std::string::npos ||
                            prefix.find("[[rtprotect::virtualize]]") != std::string::npos);

          // Also check AST attributes in inner nodes
          if (!is_tagged && node->contains("inner") && (*node)["inner"].is_array()) {
            for (const auto& in_node : (*node)["inner"].as_array()) {
              if (in_node.contains("kind") && in_node["kind"].as_string() == "AnnotateAttr") {
                std::string ann = in_node.contains("annotation") ? in_node["annotation"].as_string() : "";
                if (ann.find("virtualize") != std::string::npos) {
                  is_tagged = true;
                  break;
                }
              }
            }
          }

          if (is_tagged) {
            ClangFunctionDecl decl;
            decl.name = fn_name;
            decl.start_offset = src_fn_pos;
            decl.is_virtualized_annotated = true;

            if (node->contains("type") && (*node)["type"].contains("qualType")) {
              std::string full_type = (*node)["type"]["qualType"].as_string();
              auto paren = full_type.find('(');
              decl.return_type = (paren != std::string::npos) ? full_type.substr(0, paren) : full_type;
              while (!decl.return_type.empty() && decl.return_type.back() == ' ') {
                decl.return_type.pop_back();
              }
            }

            if (node->contains("inner") && (*node)["inner"].is_array()) {
              for (const auto& inner : (*node)["inner"].as_array()) {
                std::string inner_kind = inner["kind"].as_string();
                if (inner_kind == "ParmVarDecl") {
                  decl.param_names.push_back(inner["name"].as_string());
                  if (inner.contains("type") && inner["type"].contains("qualType")) {
                    decl.param_types.push_back(inner["type"]["qualType"].as_string());
                  }
                } else if (inner_kind == "CXXThrowExpr" || inner_kind == "CXXTryStmt") {
                  decl.has_unsupported_constructs = true;
                  decl.unsupported_reason = "C++ exceptions are not supported in virtualized routines";
                }
              }
            }

            // Build unique overload signature: name(type1, type2)
            decl.signature = decl.name + "(";
            for (std::size_t p = 0; p < decl.param_types.size(); ++p) {
              if (p > 0) decl.signature += ", ";
              decl.signature += decl.param_types[p];
            }
            decl.signature += ")";

            results.push_back(decl);
          }
        }
      }
    }

    if (node->contains("inner") && (*node)["inner"].is_array()) {
      for (const auto& child : (*node)["inner"].as_array()) {
        if (child.is_object()) {
          nodes_to_visit.push_back(&child);
        }
      }
    }
  }

  return results;
}

}  // namespace rtprotect::tooling
