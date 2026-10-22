// tooling/clang_ast_scanner.h
//
// Clang AST Compiler Tooling Frontend for RTProtect.
// Consumes compilation database (compile_commands.json), invokes Clang AST
// dump, and semantically analyzes translation unit functions and attributes.
// Fulfills Stage 3 compiler tooling migration requirements.

#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace rtprotect::tooling {

struct CompileCommandEntry {
  std::string directory;
  std::string command;
  std::string file;
  std::vector<std::string> arguments;
};

class CompilationDatabase {
 public:
  static std::optional<CompilationDatabase> LoadFromFile(const std::string& json_path);
  static std::optional<CompilationDatabase> LoadFromDirectory(const std::string& build_dir);

  // Looks up compilation flags for a given source file
  std::vector<std::string> GetFlagsForFile(const std::string& file_path) const;

  std::size_t size() const { return entries_.size(); }
  bool empty() const { return entries_.empty(); }

 private:
  std::unordered_map<std::string, CompileCommandEntry> entries_; // normalized file -> entry
};

struct ClangFunctionDecl {
  std::string name;
  std::string return_type;
  std::vector<std::string> param_names;
  std::vector<std::string> param_types;
  std::size_t start_offset = 0;
  std::size_t end_offset = 0;
  std::size_t start_line = 0;
  std::size_t end_line = 0;
  bool is_virtualized_annotated = false;
  bool has_unsupported_constructs = false;
  std::string unsupported_reason;
};

class ClangAstScanner {
 public:
  static bool IsAvailable();
  static std::string GetClangBinaryPath();

  // Scans translation unit using real Clang AST
  static std::vector<ClangFunctionDecl> AnalyzeTranslationUnit(
      const std::string& source_path,
      const std::vector<std::string>& compiler_flags = {});

  // Validates if a function is eligible for bytecode virtualization
  static bool ValidateVirtualizationEligibility(const ClangFunctionDecl& fn, std::string* out_reason = nullptr);
};

}  // namespace rtprotect::tooling
