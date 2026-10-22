// tooling/clang_ast_scanner.cpp

#include "tooling/clang_ast_scanner.h"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

#include "tooling/file_io.h"

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/wait.h>
#include <unistd.h>
#endif

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

// Executes a subprocess and captures standard output
bool RunSubprocessCaptureOutput(const std::string& cmd_line, std::string* out_stdout) {
#if defined(_WIN32)
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
  si.hStdError = hWritePipe;

  PROCESS_INFORMATION pi{};
  std::string mutable_cmd = cmd_line;

  BOOL ok = ::CreateProcessA(
      nullptr,
      mutable_cmd.data(),
      nullptr,
      nullptr,
      TRUE,
      0,
      nullptr,
      nullptr,
      &si,
      &pi);

  ::CloseHandle(hWritePipe);

  if (!ok) {
    ::CloseHandle(hReadPipe);
    return false;
  }

  std::string output;
  char buf[4096];
  DWORD bytes_read = 0;
  while (::ReadFile(hReadPipe, buf, sizeof(buf), &bytes_read, nullptr) && bytes_read > 0) {
    output.append(buf, bytes_read);
  }

  ::CloseHandle(hReadPipe);
  ::WaitForSingleObject(pi.hProcess, 10000);

  DWORD exit_code = 0;
  ::GetExitCodeProcess(pi.hProcess, &exit_code);
  ::CloseHandle(pi.hThread);
  ::CloseHandle(pi.hProcess);

  if (out_stdout) *out_stdout = std::move(output);
  return (exit_code == 0);
#else
  FILE* pipe = popen(cmd_line.c_str(), "r");
  if (!pipe) return false;

  char buf[4096];
  std::string output;
  while (fgets(buf, sizeof(buf), pipe)) {
    output.append(buf);
  }
  int status = pclose(pipe);
  if (out_stdout) *out_stdout = std::move(output);
  return (status == 0);
#endif
}

}  // namespace

std::optional<CompilationDatabase> CompilationDatabase::LoadFromFile(const std::string& json_path) {
  auto content = ReadTextFile(json_path);
  if (!content.has_value() || content->empty()) return std::nullopt;

  CompilationDatabase db;
  // Parse compile_commands.json entries
  // Standard format: [ { "directory": "...", "command": "...", "file": "..." }, ... ]
  std::string str = *content;
  std::size_t pos = 0;

  while ((pos = str.find('{', pos)) != std::string::npos) {
    auto end_obj = str.find('}', pos);
    if (end_obj == std::string::npos) break;

    std::string obj = str.substr(pos, end_obj - pos + 1);
    CompileCommandEntry entry;

    auto extract_field = [&](const std::string& field_name) -> std::string {
      std::string pattern = "\"" + field_name + "\"";
      auto fpos = obj.find(pattern);
      if (fpos == std::string::npos) return "";
      auto colon = obj.find(':', fpos);
      if (colon == std::string::npos) return "";
      auto quote1 = obj.find('"', colon);
      if (quote1 == std::string::npos) return "";
      auto quote2 = obj.find('"', quote1 + 1);
      if (quote2 == std::string::npos) return "";
      return obj.substr(quote1 + 1, quote2 - quote1 - 1);
    };

    entry.file = extract_field("file");
    entry.directory = extract_field("directory");
    entry.command = extract_field("command");

    if (!entry.file.empty()) {
      db.entries_[NormalizePath(entry.file)] = entry;
    }

    pos = end_obj + 1;
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
    // Default standard flags
    return { "-std=c++20", "-I." };
  }

  std::vector<std::string> flags;
  std::istringstream iss(it->second.command);
  std::string token;
  bool skip_next = false;
  bool is_first = true;

  while (iss >> token) {
    if (is_first) {
      is_first = false;
      continue; // Skip compiler executable
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
#if defined(_WIN32)
  static const char* const kKnownPaths[] = {
      "C:\\Program Files\\LLVM\\bin\\clang.exe",
      "C:\\msys64\\mingw64\\bin\\clang.exe",
      "clang.exe"
  };
#else
  static const char* const kKnownPaths[] = {
      "/usr/bin/clang",
      "/usr/local/bin/clang",
      "clang"
  };
#endif

  for (const char* path : kKnownPaths) {
    if (fs::exists(path)) return path;
  }

  // Check PATH
#if defined(_WIN32)
  std::string out;
  if (RunSubprocessCaptureOutput("where.exe clang.exe", &out) && !out.empty()) {
    auto nl = out.find('\n');
    if (nl != std::string::npos) out = out.substr(0, nl);
    while (!out.empty() && (out.back() == '\r' || out.back() == ' ')) out.pop_back();
    if (fs::exists(out)) return out;
  }
#endif

  return "";
}

bool ClangAstScanner::ValidateVirtualizationEligibility(const ClangFunctionDecl& fn, std::string* out_reason) {
  if (fn.has_unsupported_constructs) {
    if (out_reason) *out_reason = fn.unsupported_reason;
    return false;
  }

  if (fn.param_types.size() > 4) {
    if (out_reason) *out_reason = "Function parameter count exceeds VM argument capacity (max 4)";
    return false;
  }

  // Reject unsupported return types (e.g. non-primitive structs, classes)
  static const char* const kSupportedPrimitives[] = {
      "int", "long", "long long", "int64_t", "int32_t", "uint64_t", "uint32_t",
      "short", "char", "bool", "void", "unsigned int", "unsigned long"
  };

  bool ret_ok = false;
  for (const char* prim : kSupportedPrimitives) {
    if (fn.return_type.find(prim) != std::string::npos) {
      ret_ok = true;
      break;
    }
  }

  if (!ret_ok) {
    if (out_reason) *out_reason = "Unsupported return type for bytecode VM: " + fn.return_type;
    return false;
  }

  return true;
}

std::vector<ClangFunctionDecl> ClangAstScanner::AnalyzeTranslationUnit(
    const std::string& source_path,
    const std::vector<std::string>& compiler_flags) {
  std::vector<ClangFunctionDecl> results;
  std::string clang_bin = GetClangBinaryPath();
  if (clang_bin.empty()) return results;

  std::ostringstream cmd;
  cmd << "\"" << clang_bin << "\" -fsyntax-only -Xclang -ast-dump=json ";
  for (const auto& flag : compiler_flags) {
    cmd << flag << " ";
  }
  cmd << "\"" << source_path << "\"";

  std::string json_output;
  RunSubprocessCaptureOutput(cmd.str(), &json_output);
  if (json_output.empty()) return results;

  // Read source text to verify annotations and line bounds
  auto src_text = ReadTextFile(source_path);
  if (!src_text.has_value()) return results;

  // Parse JSON AST FunctionDecl elements
  std::size_t pos = 0;
  while ((pos = json_output.find("\"kind\": \"FunctionDecl\"", pos)) != std::string::npos) {
    // Find enclosing object start
    std::size_t obj_start = json_output.rfind('{', pos);
    if (obj_start == std::string::npos) {
      pos += 22;
      continue;
    }

    // Extract function name
    auto name_pos = json_output.find("\"name\": \"", pos);
    if (name_pos != std::string::npos && name_pos - pos < 500) {
      auto name_end = json_output.find('"', name_pos + 9);
      std::string fn_name = json_output.substr(name_pos + 9, name_end - name_pos - 9);

      // Check if this function is tagged with RTPROTECT_VIRTUALIZE in source text
      std::string tag_pattern = "RTPROTECT_VIRTUALIZE";
      std::string attr_pattern = "[[rtprotect::virtualize]]";

      std::size_t src_fn_pos = src_text->find(fn_name);
      if (src_fn_pos != std::string::npos) {
        std::size_t lookback = (src_fn_pos >= 200) ? 200 : src_fn_pos;
        std::string prefix = src_text->substr(src_fn_pos - lookback, lookback);

        bool is_tagged = (prefix.find(tag_pattern) != std::string::npos ||
                          prefix.find(attr_pattern) != std::string::npos);

        if (is_tagged) {
          ClangFunctionDecl decl;
          decl.name = fn_name;
          decl.is_virtualized_annotated = true;

          // Extract return type from AST JSON
          auto type_pos = json_output.find("\"qualType\": \"", pos);
          if (type_pos != std::string::npos && type_pos - pos < 400) {
            auto type_end = json_output.find('"', type_pos + 13);
            std::string full_type = json_output.substr(type_pos + 13, type_end - type_pos - 13);
            auto paren = full_type.find('(');
            decl.return_type = (paren != std::string::npos) ? full_type.substr(0, paren) : full_type;
            // Trim whitespace
            while (!decl.return_type.empty() && decl.return_type.back() == ' ') decl.return_type.pop_back();
          }

          // Check for unsupported constructs
          if (src_text->find("throw ", src_fn_pos) != std::string::npos ||
              src_text->find("try {", src_fn_pos) != std::string::npos) {
            decl.has_unsupported_constructs = true;
            decl.unsupported_reason = "C++ exceptions are not supported in virtualized routines";
          }

          results.push_back(decl);
        }
      }
    }

    pos += 22;
  }

  return results;
}

}  // namespace rtprotect::tooling
