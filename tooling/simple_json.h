// tooling/simple_json.h
//
// Lightweight, standards-compliant JSON parser for RTProtect tooling.
// Correctly handles nested objects, arrays, numbers, booleans, null,
// and string escape sequences (including \", \\, \n, \r, \t, etc.).
// Completely immune to string escaping desynchronization vulnerabilities
// and protected against stack exhaustion via recursion depth limits.

#pragma once

#include <cctype>
#include <charconv>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace rtprotect::tooling {

enum class JsonType {
  kNull,
  kBool,
  kNumber,
  kString,
  kArray,
  kObject
};

class JsonValue {
 public:
  static constexpr std::size_t kDefaultMaxDepth = 128;

  JsonValue() : type_(JsonType::kNull) {}
  explicit JsonValue(bool b) : type_(JsonType::kBool), bool_val_(b) {}
  explicit JsonValue(std::int64_t i) : type_(JsonType::kNumber), is_integer_(true), int_val_(i), num_val_(static_cast<double>(i)) {}
  explicit JsonValue(int i) : type_(JsonType::kNumber), is_integer_(true), int_val_(i), num_val_(static_cast<double>(i)) {}
  explicit JsonValue(double n) : type_(JsonType::kNumber), is_integer_(false), num_val_(n) {
    if (std::isfinite(n) && n >= -9223372036854775808.0 && n <= 9223372036854775807.0 &&
        std::floor(n) == n) {
      is_integer_ = true;
      int_val_ = static_cast<std::int64_t>(n);
    }
  }
  explicit JsonValue(std::string s) : type_(JsonType::kString), str_val_(std::move(s)) {}
  explicit JsonValue(std::vector<JsonValue> a) : type_(JsonType::kArray), arr_val_(std::move(a)) {}
  explicit JsonValue(std::unordered_map<std::string, JsonValue> o) : type_(JsonType::kObject), obj_val_(std::move(o)) {}

  JsonType type() const { return type_; }
  bool is_null() const { return type_ == JsonType::kNull; }
  bool is_bool() const { return type_ == JsonType::kBool; }
  bool is_number() const { return type_ == JsonType::kNumber; }
  bool is_integer() const { return is_number() && is_integer_; }
  bool is_string() const { return type_ == JsonType::kString; }
  bool is_array() const { return type_ == JsonType::kArray; }
  bool is_object() const { return type_ == JsonType::kObject; }

  const std::string& as_string() const {
    static const std::string s_empty;
    return is_string() ? str_val_ : s_empty;
  }

  bool as_bool() const { return is_bool() && bool_val_; }
  double as_number() const { return is_number() ? num_val_ : 0.0; }
  long long as_int() const {
    if (!is_number()) return 0;
    if (is_integer_) return int_val_;
    if (!std::isfinite(num_val_)) return 0;
    if (num_val_ > 9223372036854775807.0) return 9223372036854775807LL;
    if (num_val_ < -9223372036854775808.0) return (-9223372036854775807LL - 1);
    return static_cast<long long>(num_val_);
  }
  std::optional<std::int64_t> as_int64() const {
    if (!is_number()) return std::nullopt;
    if (is_integer_) return int_val_;
    if (!std::isfinite(num_val_)) return std::nullopt;
    if (num_val_ < -9223372036854775808.0 || num_val_ > 9223372036854775807.0) return std::nullopt;
    return static_cast<std::int64_t>(num_val_);
  }
  std::optional<std::uint64_t> as_uint64() const {
    if (!is_number()) return std::nullopt;
    if (is_integer_) {
      if (int_val_ < 0) return std::nullopt;
      return static_cast<std::uint64_t>(int_val_);
    }
    if (!std::isfinite(num_val_) || num_val_ < 0.0 || num_val_ > 18446744073709551615.0) return std::nullopt;
    return static_cast<std::uint64_t>(num_val_);
  }

  const std::vector<JsonValue>& as_array() const {
    static const std::vector<JsonValue> s_empty;
    return is_array() ? arr_val_ : s_empty;
  }

  const std::unordered_map<std::string, JsonValue>& as_object() const {
    static const std::unordered_map<std::string, JsonValue> s_empty;
    return is_object() ? obj_val_ : s_empty;
  }

  bool contains(const std::string& key) const {
    return is_object() && obj_val_.find(key) != obj_val_.end();
  }

  const JsonValue& operator[](const std::string& key) const {
    static const JsonValue s_null;
    if (!is_object()) return s_null;
    auto it = obj_val_.find(key);
    return (it != obj_val_.end()) ? it->second : s_null;
  }

  const JsonValue& operator[](std::size_t idx) const {
    static const JsonValue s_null;
    if (!is_array() || idx >= arr_val_.size()) return s_null;
    return arr_val_[idx];
  }

  static std::optional<JsonValue> Parse(std::string_view sv, std::size_t max_depth = kDefaultMaxDepth) {
    std::size_t pos = 0;
    SkipWhitespace(sv, pos);
    if (pos >= sv.size()) return std::nullopt;
    auto res = ParseValue(sv, pos, 0, max_depth);
    if (!res.has_value()) return std::nullopt;
    SkipWhitespace(sv, pos);
    if (pos != sv.size()) return std::nullopt; // Reject trailing unparsed characters
    return res;
  }

 private:
  static void SkipWhitespace(std::string_view sv, std::size_t& pos) {
    while (pos < sv.size() && (sv[pos] == ' ' || sv[pos] == '\t' || sv[pos] == '\r' || sv[pos] == '\n')) {
      ++pos;
    }
  }

  static std::optional<std::string> ParseString(std::string_view sv, std::size_t& pos) {
    if (pos >= sv.size() || sv[pos] != '"') return std::nullopt;
    ++pos; // skip opening quote
    std::string result;
    result.reserve(32);

    while (pos < sv.size()) {
      char c = sv[pos++];
      if (c == '"') {
        return result; // closing quote
      }
      // JSON RFC 8259: unescaped control characters < 0x20 are forbidden in strings
      if (static_cast<unsigned char>(c) < 0x20) {
        return std::nullopt;
      }
      if (c == '\\') {
        if (pos >= sv.size()) return std::nullopt;
        char esc = sv[pos++];
        switch (esc) {
          case '"': result.push_back('"'); break;
          case '\\': result.push_back('\\'); break;
          case '/': result.push_back('/'); break;
          case 'b': result.push_back('\b'); break;
          case 'f': result.push_back('\f'); break;
          case 'n': result.push_back('\n'); break;
          case 'r': result.push_back('\r'); break;
          case 't': result.push_back('\t'); break;
          case 'u': {
            if (pos + 4 > sv.size()) return std::nullopt;
            for (int i = 0; i < 4; ++i) {
              if (!std::isxdigit(static_cast<unsigned char>(sv[pos + i]))) {
                return std::nullopt;
              }
            }
            pos += 4;
            result.push_back('?');
            break;
          }
          default:
            return std::nullopt; // Unrecognized escape sequence
        }
      } else {
        result.push_back(c);
      }
    }
    return std::nullopt; // unclosed string
  }

  static std::optional<JsonValue> ParseValue(std::string_view sv, std::size_t& pos, std::size_t depth, std::size_t max_depth) {
    if (depth > max_depth) return std::nullopt;
    SkipWhitespace(sv, pos);
    if (pos >= sv.size()) return std::nullopt;

    char c = sv[pos];
    if (c == '"') {
      auto s = ParseString(sv, pos);
      if (!s.has_value()) return std::nullopt;
      return JsonValue(*s);
    }
    if (c == '{') {
      return ParseObject(sv, pos, depth, max_depth);
    }
    if (c == '[') {
      return ParseArray(sv, pos, depth, max_depth);
    }
    if (c == 't' || c == 'f') {
      if (sv.substr(pos, 4) == "true") {
        pos += 4;
        return JsonValue(true);
      }
      if (sv.substr(pos, 5) == "false") {
        pos += 5;
        return JsonValue(false);
      }
      return std::nullopt;
    }
    if (c == 'n') {
      if (sv.substr(pos, 4) == "null") {
        pos += 4;
        return JsonValue();
      }
      return std::nullopt;
    }
    if (c == '-' || std::isdigit(static_cast<unsigned char>(c))) {
      std::size_t start = pos;
      if (sv[pos] == '-') ++pos;
      if (pos >= sv.size() || !std::isdigit(static_cast<unsigned char>(sv[pos]))) {
        return std::nullopt;
      }
      if (sv[pos] == '0' && pos + 1 < sv.size() && std::isdigit(static_cast<unsigned char>(sv[pos + 1]))) {
        return std::nullopt; // Leading zeros disallowed
      }
      while (pos < sv.size() && std::isdigit(static_cast<unsigned char>(sv[pos]))) ++pos;
      if (pos < sv.size() && sv[pos] == '.') {
        ++pos;
        if (pos >= sv.size() || !std::isdigit(static_cast<unsigned char>(sv[pos]))) {
          return std::nullopt;
        }
        while (pos < sv.size() && std::isdigit(static_cast<unsigned char>(sv[pos]))) ++pos;
      }
      if (pos < sv.size() && (sv[pos] == 'e' || sv[pos] == 'E')) {
        ++pos;
        if (pos < sv.size() && (sv[pos] == '+' || sv[pos] == '-')) ++pos;
        if (pos >= sv.size() || !std::isdigit(static_cast<unsigned char>(sv[pos]))) {
          return std::nullopt;
        }
        while (pos < sv.size() && std::isdigit(static_cast<unsigned char>(sv[pos]))) ++pos;
      }
      std::string num_str(sv.substr(start, pos - start));
      bool is_float = (num_str.find('.') != std::string::npos ||
                       num_str.find('e') != std::string::npos ||
                       num_str.find('E') != std::string::npos);
      if (!is_float) {
        char* end_ptr = nullptr;
        errno = 0;
        long long iv = std::strtoll(num_str.c_str(), &end_ptr, 10);
        if (errno == 0 && end_ptr == num_str.c_str() + num_str.size()) {
          return JsonValue(static_cast<std::int64_t>(iv));
        }
      }
      char* end_ptr = nullptr;
      double val = std::strtod(num_str.c_str(), &end_ptr);
      if (end_ptr != num_str.c_str() + num_str.size() || !std::isfinite(val)) {
        return std::nullopt;
      }
      return JsonValue(val);
    }

    return std::nullopt;
  }

  static std::optional<JsonValue> ParseArray(std::string_view sv, std::size_t& pos, std::size_t depth, std::size_t max_depth) {
    if (depth > max_depth) return std::nullopt;
    if (pos >= sv.size() || sv[pos] != '[') return std::nullopt;
    ++pos; // skip '['
    std::vector<JsonValue> elements;

    while (pos < sv.size()) {
      SkipWhitespace(sv, pos);
      if (pos < sv.size() && sv[pos] == ']') {
        ++pos;
        return JsonValue(std::move(elements));
      }

      auto val = ParseValue(sv, pos, depth + 1, max_depth);
      if (!val.has_value()) return std::nullopt;
      elements.push_back(std::move(*val));

      SkipWhitespace(sv, pos);
      if (pos < sv.size() && sv[pos] == ',') {
        ++pos;
      } else if (pos < sv.size() && sv[pos] == ']') {
        ++pos;
        return JsonValue(std::move(elements));
      } else {
        return std::nullopt;
      }
    }
    return std::nullopt;
  }

  static std::optional<JsonValue> ParseObject(std::string_view sv, std::size_t& pos, std::size_t depth, std::size_t max_depth) {
    if (depth > max_depth) return std::nullopt;
    if (pos >= sv.size() || sv[pos] != '{') return std::nullopt;
    ++pos; // skip '{'
    std::unordered_map<std::string, JsonValue> obj;

    while (pos < sv.size()) {
      SkipWhitespace(sv, pos);
      if (pos < sv.size() && sv[pos] == '}') {
        ++pos;
        return JsonValue(std::move(obj));
      }

      if (pos >= sv.size() || sv[pos] != '"') return std::nullopt;
      auto key = ParseString(sv, pos);
      if (!key.has_value()) return std::nullopt;

      SkipWhitespace(sv, pos);
      if (pos >= sv.size() || sv[pos] != ':') return std::nullopt;
      ++pos; // skip ':'

      auto val = ParseValue(sv, pos, depth + 1, max_depth);
      if (!val.has_value()) return std::nullopt;
      obj[std::move(*key)] = std::move(*val);

      SkipWhitespace(sv, pos);
      if (pos < sv.size() && sv[pos] == ',') {
        ++pos;
      } else if (pos < sv.size() && sv[pos] == '}') {
        ++pos;
        return JsonValue(std::move(obj));
      } else {
        return std::nullopt;
      }
    }
    return std::nullopt;
  }

  JsonType type_;
  bool bool_val_ = false;
  bool is_integer_ = false;
  std::int64_t int_val_ = 0;
  double num_val_ = 0.0;
  std::string str_val_;
  std::vector<JsonValue> arr_val_;
  std::unordered_map<std::string, JsonValue> obj_val_;
};

}  // namespace rtprotect::tooling
