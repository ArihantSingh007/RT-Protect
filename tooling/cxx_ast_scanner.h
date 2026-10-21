// tooling/cxx_ast_scanner.h
//
// AST-aware lexical analysis and syntax transformer for C++ translation units.
// Robustly parses raw string literals (R"(...)"), multi-line concatenation,
// preprocessor conditionals, template boundaries, comments, and tagged functions.
// Provides global translation-unit string obfuscation.

#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace rtprotect::tooling {

struct SourceRange {
  std::size_t start = 0;
  std::size_t end = 0;  // exclusive
};

struct ExtractedFunction {
  std::string name;
  std::string return_type;
  std::string header;
  std::string params_raw;
  std::vector<std::string> arg_names;
  std::vector<std::string> arg_types;
  std::string body;
  std::string full_signature_and_body;
  SourceRange full_range;
  SourceRange body_range;
};

struct StringLiteralMatch {
  SourceRange range;
  std::string literal_text;
  bool is_raw = false;
};

class CxxAstScanner {
 public:
  explicit CxxAstScanner(std::string source_text);

  // Finds all functions tagged with RTPROTECT_VIRTUALIZE, [[rtprotect::virtualize]], etc.
  std::vector<ExtractedFunction> FindTaggedFunctions() const;

  // Finds all string literals across the translation unit (excluding comments, includes, and macros)
  std::vector<StringLiteralMatch> FindAllStringLiterals() const;

  // Rewrites all eligible string literals in the translation unit using OBFUSCATED_STRING(...)
  // Injects #include "obfuscation/obfuscated_string.h" if modifications were made.
  std::string RewriteTranslationUnitStrings(std::size_t* out_obfuscated_count = nullptr);

  // Helper verifying valid function boundary discovery
  static bool IsBalancedBraces(const std::string& code);

 private:
  std::string src_;
};

}  // namespace rtprotect::tooling
