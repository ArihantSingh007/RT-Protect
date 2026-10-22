// tooling/cxx_ast_scanner.cpp

#include "tooling/cxx_ast_scanner.h"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace rtprotect::tooling {

namespace {

// Skips raw string literal: R"delim(...)delim"
// pos must point to 'R' in 'R"'
std::size_t SkipRawString(const std::string& s, std::size_t pos) {
  if (pos + 2 >= s.size() || s[pos] != 'R' || s[pos + 1] != '"') {
    return pos + 1;
  }
  std::size_t delim_start = pos + 2;
  std::size_t paren_open = s.find('(', delim_start);
  if (paren_open == std::string::npos) {
    return s.size();
  }
  std::string delim = s.substr(delim_start, paren_open - delim_start);
  std::string closing_seq = ")" + delim + "\"";

  std::size_t close_pos = s.find(closing_seq, paren_open + 1);
  if (close_pos == std::string::npos) {
    return s.size();
  }
  return close_pos + closing_seq.size();
}

// Skips standard string literal "..."
// pos must point to opening quote '"'
std::size_t SkipStandardString(const std::string& s, std::size_t pos) {
  if (pos >= s.size() || s[pos] != '"') return pos + 1;
  std::size_t i = pos + 1;
  while (i < s.size()) {
    if (s[i] == '\\' && i + 1 < s.size()) {
      i += 2;
      continue;
    }
    if (s[i] == '"') {
      return i + 1;
    }
    ++i;
  }
  return s.size();
}

// Skips character literal '...'
std::size_t SkipCharLiteral(const std::string& s, std::size_t pos) {
  if (pos >= s.size() || s[pos] != '\'') return pos + 1;
  std::size_t i = pos + 1;
  while (i < s.size()) {
    if (s[i] == '\\' && i + 1 < s.size()) {
      i += 2;
      continue;
    }
    if (s[i] == '\'') {
      return i + 1;
    }
    ++i;
  }
  return s.size();
}

}  // namespace

CxxAstScanner::CxxAstScanner(std::string source_text) : src_(std::move(source_text)) {}

std::vector<ExtractedFunction> CxxAstScanner::FindTaggedFunctions() const {
  std::vector<ExtractedFunction> functions;
  static const std::vector<std::string> kTags = {
      "RTPROTECT_VIRTUALIZE",
      "// @rtprotect_virtualize",
      "/* @rtprotect_virtualize */",
      "[[rtprotect::virtualize]]",
      "[[gnu::virtualize]]"
  };

  for (const auto& tag : kTags) {
    std::size_t tag_pos = 0;
    while ((tag_pos = src_.find(tag, tag_pos)) != std::string::npos) {
      std::size_t fn_search_start = tag_pos + tag.size();
      while (fn_search_start < src_.size() &&
             std::isspace(static_cast<unsigned char>(src_[fn_search_start]))) {
        ++fn_search_start;
      }
      if (fn_search_start >= src_.size()) break;

      // Find opening brace '{' of function
      std::size_t brace_open = std::string::npos;
      std::size_t i = fn_search_start;
      while (i < src_.size()) {
        if (src_[i] == '/' && i + 1 < src_.size() && src_[i + 1] == '/') {
          i += 2;
          while (i < src_.size() && src_[i] != '\n') ++i;
          continue;
        }
        if (src_[i] == '/' && i + 1 < src_.size() && src_[i + 1] == '*') {
          i += 2;
          while (i + 1 < src_.size() && !(src_[i] == '*' && src_[i + 1] == '/')) ++i;
          if (i + 1 < src_.size()) i += 2;
          continue;
        }
        if (src_[i] == '{') {
          brace_open = i;
          break;
        }
        if (src_[i] == ';') {
          // Forward declaration, not a function definition
          break;
        }
        ++i;
      }

      if (brace_open == std::string::npos) {
        tag_pos = fn_search_start;
        continue;
      }

      // Parse signature between fn_search_start and brace_open
      std::string sig_text = src_.substr(fn_search_start, brace_open - fn_search_start);
      auto lparen = sig_text.find('(');
      auto rparen = sig_text.rfind(')');
      if (lparen == std::string::npos || rparen == std::string::npos || rparen < lparen) {
        tag_pos = brace_open + 1;
        continue;
      }

      std::string pre_paren = sig_text.substr(0, lparen);
      while (!pre_paren.empty() && std::isspace(static_cast<unsigned char>(pre_paren.back()))) {
        pre_paren.pop_back();
      }
      auto name_sep = pre_paren.find_last_of(" \t\n*&");
      std::string fn_name = (name_sep == std::string::npos) ? pre_paren : pre_paren.substr(name_sep + 1);
      std::string ret_type = (name_sep == std::string::npos) ? "int" : pre_paren.substr(0, name_sep);

      std::string params_raw = sig_text.substr(lparen + 1, rparen - lparen - 1);
      std::vector<std::string> arg_names;
      std::vector<std::string> arg_types;

      std::istringstream pss(params_raw);
      std::string param_segment;
      while (std::getline(pss, param_segment, ',')) {
        while (!param_segment.empty() && std::isspace(static_cast<unsigned char>(param_segment.front()))) {
          param_segment.erase(param_segment.begin());
        }
        while (!param_segment.empty() && std::isspace(static_cast<unsigned char>(param_segment.back()))) {
          param_segment.pop_back();
        }
        if (param_segment.empty() || param_segment == "void") continue;

        auto last_space = param_segment.find_last_of(" \t*&");
        if (last_space != std::string::npos) {
          arg_types.push_back(param_segment.substr(0, last_space + 1));
          arg_names.push_back(param_segment.substr(last_space + 1));
        } else {
          arg_names.push_back(param_segment);
          arg_types.push_back("int64_t");
        }
      }

      // Scan body with full raw string and comment awareness
      int depth = 1;
      std::size_t scan_idx = brace_open + 1;
      std::size_t brace_close = std::string::npos;

      while (scan_idx < src_.size() && depth > 0) {
        if (src_[scan_idx] == '/' && scan_idx + 1 < src_.size() && src_[scan_idx + 1] == '/') {
          scan_idx += 2;
          while (scan_idx < src_.size() && src_[scan_idx] != '\n') ++scan_idx;
          continue;
        }
        if (src_[scan_idx] == '/' && scan_idx + 1 < src_.size() && src_[scan_idx + 1] == '*') {
          scan_idx += 2;
          while (scan_idx + 1 < src_.size() && !(src_[scan_idx] == '*' && src_[scan_idx + 1] == '/')) ++scan_idx;
          if (scan_idx + 1 < src_.size()) scan_idx += 2;
          continue;
        }
        if (src_[scan_idx] == 'R' && scan_idx + 1 < src_.size() && src_[scan_idx + 1] == '"') {
          scan_idx = SkipRawString(src_, scan_idx);
          continue;
        }
        if (src_[scan_idx] == '"') {
          scan_idx = SkipStandardString(src_, scan_idx);
          continue;
        }
        if (src_[scan_idx] == '\'') {
          scan_idx = SkipCharLiteral(src_, scan_idx);
          continue;
        }
        if (src_[scan_idx] == '{') {
          ++depth;
        } else if (src_[scan_idx] == '}') {
          --depth;
          if (depth == 0) {
            brace_close = scan_idx;
            break;
          }
        }
        ++scan_idx;
      }

      if (depth == 0 && brace_close != std::string::npos) {
        ExtractedFunction fn;
        fn.name = fn_name;
        fn.return_type = ret_type;
        fn.header = sig_text;
        fn.params_raw = params_raw;
        fn.arg_names = arg_names;
        fn.arg_types = arg_types;
        fn.body = src_.substr(brace_open, brace_close - brace_open + 1);
        fn.full_signature_and_body = src_.substr(fn_search_start, brace_close - fn_search_start + 1);
        fn.full_range = {tag_pos, brace_close + 1};
        fn.body_range = {brace_open, brace_close + 1};
        functions.push_back(std::move(fn));

        tag_pos = brace_close + 1;
      } else {
        tag_pos = fn_search_start;
      }
    }
  }

  return functions;
}

std::vector<StringLiteralMatch> CxxAstScanner::FindAllStringLiterals() const {
  std::vector<StringLiteralMatch> literals;
  std::size_t i = 0;

  while (i < src_.size()) {
    // 1. Skip comments
    if (src_[i] == '/' && i + 1 < src_.size() && src_[i + 1] == '/') {
      i += 2;
      while (i < src_.size() && src_[i] != '\n') ++i;
      continue;
    }
    if (src_[i] == '/' && i + 1 < src_.size() && src_[i + 1] == '*') {
      i += 2;
      while (i + 1 < src_.size() && !(src_[i] == '*' && src_[i + 1] == '/')) ++i;
      if (i + 1 < src_.size()) i += 2;
      continue;
    }

    // 2. Skip preprocessor directives (e.g. #include "...")
    if (src_[i] == '#') {
      std::size_t line_start = i;
      while (i < src_.size() && src_[i] != '\n') {
        if (src_[i] == '\\' && i + 1 < src_.size() && src_[i + 1] == '\n') {
          i += 2;
          continue;
        }
        ++i;
      }
      (void)line_start;
      continue;
    }

    // 3. Skip char literals
    if (src_[i] == '\'') {
      i = SkipCharLiteral(src_, i);
      continue;
    }

    // 4. Raw string literals
    if (src_[i] == 'R' && i + 1 < src_.size() && src_[i + 1] == '"') {
      std::size_t start = i;
      std::size_t end = SkipRawString(src_, i);
      if (end > start) {
        literals.push_back({ {start, end}, src_.substr(start, end - start), true });
        i = end;
        continue;
      }
    }

    // 5. Standard string literals
    if (src_[i] == '"') {
      std::size_t start = i;
      std::size_t end = SkipStandardString(src_, i);
      if (end > start) {
        // Check if already enclosed by OBFUSCATED_STRING, RTPROTECT_STRING, or ScatterTamperCheck
        bool already_obfuscated = false;
        std::size_t lookback_len = (start >= 32) ? 32 : start;
        std::string prefix = src_.substr(start - lookback_len, lookback_len);
        if (prefix.find("OBFUSCATED_STRING") != std::string::npos ||
            prefix.find("RTPROTECT_STRING") != std::string::npos ||
            prefix.find("ScatterTamperCheck") != std::string::npos) {
          already_obfuscated = true;
        }
        if (!already_obfuscated) {
          literals.push_back({ {start, end}, src_.substr(start, end - start), false });
        }
        i = end;
        continue;
      }
    }

    ++i;
  }

  return literals;
}

std::string CxxAstScanner::RewriteTranslationUnitStrings(std::size_t* out_obfuscated_count) {
  auto literals = FindAllStringLiterals();
  if (literals.empty()) {
    if (out_obfuscated_count) *out_obfuscated_count = 0;
    return src_;
  }

  // Sort reverse order so index replacements do not shift offsets
  std::sort(literals.begin(), literals.end(), [](const StringLiteralMatch& a, const StringLiteralMatch& b) {
    return a.range.start > b.range.start;
  });

  std::string result = src_;
  std::size_t count = 0;

  for (const auto& lit : literals) {
    // Only rewrite non-empty string literals
    if (lit.literal_text.size() <= 2) continue; // Empty quotes ""

    std::string replacement;
    if (lit.is_raw) {
      replacement = lit.literal_text;
    } else {
      replacement = "OBFUSCATED_STRING(" + lit.literal_text + ")";
    }

    result.replace(lit.range.start, lit.range.end - lit.range.start, replacement);
    ++count;
  }

  if (count > 0 && result.find("obfuscation/obfuscated_string.h") == std::string::npos) {
    result = "#include \"obfuscation/obfuscated_string.h\"\n" + result;
  }

  if (out_obfuscated_count) *out_obfuscated_count = count;
  return result;
}

bool CxxAstScanner::IsBalancedBraces(const std::string& code) {
  int depth = 0;
  std::size_t i = 0;
  while (i < code.size()) {
    if (code[i] == '/' && i + 1 < code.size() && code[i + 1] == '/') {
      i += 2;
      while (i < code.size() && code[i] != '\n') ++i;
      continue;
    }
    if (code[i] == '/' && i + 1 < code.size() && code[i + 1] == '*') {
      i += 2;
      while (i + 1 < code.size() && !(code[i] == '*' && code[i + 1] == '/')) ++i;
      if (i + 1 < code.size()) i += 2;
      continue;
    }
    if (code[i] == 'R' && i + 1 < code.size() && code[i + 1] == '"') {
      i = SkipRawString(code, i);
      continue;
    }
    if (code[i] == '"') {
      i = SkipStandardString(code, i);
      continue;
    }
    if (code[i] == '\'') {
      i = SkipCharLiteral(code, i);
      continue;
    }
    if (code[i] == '{') ++depth;
    else if (code[i] == '}') {
      --depth;
      if (depth < 0) return false;
    }
    ++i;
  }
  return depth == 0;
}

}  // namespace rtprotect::tooling
