// bytecode_vm/compiler.cpp

#include "bytecode_vm/compiler.h"
#include "bytecode_vm/builder.h"
#include "bytecode_vm/verifier.h"

#include <cctype>
#include <cstdlib>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <unordered_map>

namespace rtprotect::vm {

namespace {

enum class TokenType {
  kEof,
  kIdent,
  kNumber,
  kTypeInt64,
  kReturn,
  kIf,
  kElse,
  kWhile,
  kLoad8,
  kStore8,
  kLoad64,
  kStore64,
  kPlus,
  kMinus,
  kStar,
  kSlash,
  kPercent,
  kAmpersand,
  kPipe,
  kCaret,
  kTilde,
  kExclamation,
  kEqEq,
  kExclamationEq,
  kLess,
  kLessEq,
  kGreater,
  kGreaterEq,
  kAmpAmp,
  kPipePipe,
  kAssign,
  kSemicolon,
  kComma,
  kLParen,
  kRParen,
  kLBrace,
  kRBrace
};

struct Token {
  TokenType type = TokenType::kEof;
  std::string text;
  std::int64_t number = 0;
  std::size_t line = 1;
};

class Lexer {
 public:
  explicit Lexer(const std::string& src) : src_(src) {}

  Token Next() {
    SkipWhitespaceAndComments();
    if (pos_ >= src_.size()) {
      return {TokenType::kEof, "", 0, line_};
    }

    char c = src_[pos_];

    if (std::isalpha(static_cast<unsigned char>(c)) || c == '_') {
      std::size_t start = pos_;
      while (pos_ < src_.size() &&
             (std::isalnum(static_cast<unsigned char>(src_[pos_])) || src_[pos_] == '_')) {
        ++pos_;
      }
      std::string id = src_.substr(start, pos_ - start);
      if (id == "int64_t" || id == "int" || id == "long") return {TokenType::kTypeInt64, id, 0, line_};
      if (id == "return") return {TokenType::kReturn, id, 0, line_};
      if (id == "if") return {TokenType::kIf, id, 0, line_};
      if (id == "else") return {TokenType::kElse, id, 0, line_};
      if (id == "while") return {TokenType::kWhile, id, 0, line_};
      if (id == "load8") return {TokenType::kLoad8, id, 0, line_};
      if (id == "store8") return {TokenType::kStore8, id, 0, line_};
      if (id == "load64") return {TokenType::kLoad64, id, 0, line_};
      if (id == "store64") return {TokenType::kStore64, id, 0, line_};
      return {TokenType::kIdent, id, 0, line_};
    }

    if (std::isdigit(static_cast<unsigned char>(c))) {
      std::size_t start = pos_;
      if (c == '0' && pos_ + 1 < src_.size() && (src_[pos_ + 1] == 'x' || src_[pos_ + 1] == 'X')) {
        pos_ += 2;
        while (pos_ < src_.size() && std::isxdigit(static_cast<unsigned char>(src_[pos_]))) {
          ++pos_;
        }
      } else {
        while (pos_ < src_.size() && std::isdigit(static_cast<unsigned char>(src_[pos_]))) {
          ++pos_;
        }
      }
      std::string num_str = src_.substr(start, pos_ - start);
      char* end = nullptr;
      std::int64_t val = static_cast<std::int64_t>(std::strtoll(num_str.c_str(), &end, 0));
      return {TokenType::kNumber, num_str, val, line_};
    }

    ++pos_;
    switch (c) {
      case '+': return {TokenType::kPlus, "+", 0, line_};
      case '-': return {TokenType::kMinus, "-", 0, line_};
      case '*': return {TokenType::kStar, "*", 0, line_};
      case '/': return {TokenType::kSlash, "/", 0, line_};
      case '%': return {TokenType::kPercent, "%", 0, line_};
      case '~': return {TokenType::kTilde, "~", 0, line_};
      case '^': return {TokenType::kCaret, "^", 0, line_};
      case '(': return {TokenType::kLParen, "(", 0, line_};
      case ')': return {TokenType::kRParen, ")", 0, line_};
      case '{': return {TokenType::kLBrace, "{", 0, line_};
      case '}': return {TokenType::kRBrace, "}", 0, line_};
      case ';': return {TokenType::kSemicolon, ";", 0, line_};
      case ',': return {TokenType::kComma, ",", 0, line_};
      case '=':
        if (pos_ < src_.size() && src_[pos_] == '=') { ++pos_; return {TokenType::kEqEq, "==", 0, line_}; }
        return {TokenType::kAssign, "=", 0, line_};
      case '!':
        if (pos_ < src_.size() && src_[pos_] == '=') { ++pos_; return {TokenType::kExclamationEq, "!=", 0, line_}; }
        return {TokenType::kExclamation, "!", 0, line_};
      case '<':
        if (pos_ < src_.size() && src_[pos_] == '=') { ++pos_; return {TokenType::kLessEq, "<=", 0, line_}; }
        return {TokenType::kLess, "<", 0, line_};
      case '>':
        if (pos_ < src_.size() && src_[pos_] == '=') { ++pos_; return {TokenType::kGreaterEq, ">=", 0, line_}; }
        return {TokenType::kGreater, ">", 0, line_};
      case '&':
        if (pos_ < src_.size() && src_[pos_] == '&') { ++pos_; return {TokenType::kAmpAmp, "&&", 0, line_}; }
        return {TokenType::kAmpersand, "&", 0, line_};
      case '|':
        if (pos_ < src_.size() && src_[pos_] == '|') { ++pos_; return {TokenType::kPipePipe, "||", 0, line_}; }
        return {TokenType::kPipe, "|", 0, line_};
    }

    return {TokenType::kEof, std::string(1, c), 0, line_};
  }

 private:
  void SkipWhitespaceAndComments() {
    while (pos_ < src_.size()) {
      char c = src_[pos_];
      if (c == '\n') {
        ++line_;
        ++pos_;
      } else if (std::isspace(static_cast<unsigned char>(c))) {
        ++pos_;
      } else if (c == '/' && pos_ + 1 < src_.size() && src_[pos_ + 1] == '/') {
        // Line comment
        pos_ += 2;
        while (pos_ < src_.size() && src_[pos_] != '\n') ++pos_;
      } else if (c == '/' && pos_ + 1 < src_.size() && src_[pos_ + 1] == '*') {
        // Block comment
        pos_ += 2;
        while (pos_ + 1 < src_.size() && !(src_[pos_] == '*' && src_[pos_ + 1] == '/')) {
          if (src_[pos_] == '\n') ++line_;
          ++pos_;
        }
        if (pos_ + 1 < src_.size()) pos_ += 2;
      } else {
        break;
      }
    }
  }

  const std::string& src_;
  std::size_t pos_ = 0;
  std::size_t line_ = 1;
};

class Parser {
 public:
  Parser(const std::string& src, const CompilerOptions& opts)
      : lexer_(src), opts_(opts) {
    curr_ = lexer_.Next();
  }

  std::optional<Program> Parse(std::string* out_error) {
    try {
      // Check if function header exists: [type] [name]([args]) { ... }
      if (curr_.type == TokenType::kTypeInt64) {
        Consume(TokenType::kTypeInt64);
        if (curr_.type == TokenType::kIdent) {
          Token fn_name = Consume(TokenType::kIdent);
          if (curr_.type == TokenType::kLParen) {
            Consume(TokenType::kLParen);
            while (curr_.type != TokenType::kRParen && curr_.type != TokenType::kEof) {
              if (curr_.type == TokenType::kTypeInt64) Consume(TokenType::kTypeInt64);
              Token arg_name = Consume(TokenType::kIdent);
              AllocateLocal(arg_name.text);
              if (curr_.type == TokenType::kComma) Consume(TokenType::kComma);
            }
            Consume(TokenType::kRParen);
            if (curr_.type == TokenType::kLBrace) {
              Consume(TokenType::kLBrace);
              has_enclosing_brace_ = true;
            }
          }
        }
      }

      builder_ = std::make_unique<ProgramBuilder>(opts_.max_locals, opts_.opcode_map);

      while (curr_.type != TokenType::kEof) {
        if (has_enclosing_brace_ && curr_.type == TokenType::kRBrace) {
          Consume(TokenType::kRBrace);
          break;
        }
        ParseStatement();
      }

      if (!has_returned_) {
        // Emit default return 0
        builder_->PushConst(0);
        builder_->Ret();
      }

      Program p = builder_->Build();
      // Ensure num_locals matches allocated locals
      p.num_locals = std::max<std::uint8_t>(static_cast<std::uint8_t>(locals_.size()), 1);

      VerifyError verr = VerifyError::kNone;
      if (!VerifyProgram(p, &verr, opts_.opcode_map).has_value()) {
        if (out_error) *out_error = "Generated program failed verification: " + std::string(ToString(verr));
        return std::nullopt;
      }

      return p;
    } catch (const std::exception& e) {
      if (out_error) *out_error = e.what();
      return std::nullopt;
    }
  }

 private:
  Token Consume(TokenType expected) {
    if (curr_.type != expected) {
      std::ostringstream ss;
      ss << "Syntax error on line " << curr_.line << ": unexpected token '" << curr_.text << "'";
      throw std::runtime_error(ss.str());
    }
    Token t = curr_;
    curr_ = lexer_.Next();
    return t;
  }

  std::uint8_t AllocateLocal(const std::string& name) {
    if (locals_.find(name) != locals_.end()) {
      return locals_[name];
    }
    std::uint8_t idx = static_cast<std::uint8_t>(locals_.size());
    if (idx >= opts_.max_locals) {
      throw std::runtime_error("Exceeded maximum local variables (" + std::to_string(opts_.max_locals) + ")");
    }
    locals_[name] = idx;
    return idx;
  }

  std::uint8_t GetLocal(const std::string& name) {
    auto it = locals_.find(name);
    if (it == locals_.end()) {
      throw std::runtime_error("Undeclared identifier: " + name);
    }
    return it->second;
  }

  void ParseStatement() {
    if (curr_.type == TokenType::kSemicolon) {
      Consume(TokenType::kSemicolon);
      return;
    }

    if (curr_.type == TokenType::kLBrace) {
      Consume(TokenType::kLBrace);
      while (curr_.type != TokenType::kRBrace && curr_.type != TokenType::kEof) {
        ParseStatement();
      }
      Consume(TokenType::kRBrace);
      return;
    }

    if (curr_.type == TokenType::kReturn) {
      Consume(TokenType::kReturn);
      if (curr_.type != TokenType::kSemicolon) {
        ParseExpression();
      } else {
        builder_->PushConst(0);
      }
      builder_->Ret();
      Consume(TokenType::kSemicolon);
      has_returned_ = true;
      return;
    }

    if (curr_.type == TokenType::kIf) {
      Consume(TokenType::kIf);
      Consume(TokenType::kLParen);
      ParseExpression();
      Consume(TokenType::kRParen);

      auto else_lbl = builder_->NewLabel();
      auto end_lbl = builder_->NewLabel();

      builder_->Jz(else_lbl);
      has_returned_ = false;
      ParseStatement();
      bool then_returned = has_returned_;

      if (curr_.type == TokenType::kElse) {
        Consume(TokenType::kElse);
        if (!then_returned) {
          builder_->Jmp(end_lbl);
        }
        builder_->Mark(else_lbl);
        has_returned_ = false;
        ParseStatement();
        bool else_returned = has_returned_;
        if (!then_returned) {
          builder_->Mark(end_lbl);
        }
        has_returned_ = (then_returned && else_returned);
      } else {
        builder_->Mark(else_lbl);
        has_returned_ = false;
      }
      return;
    }

    if (curr_.type == TokenType::kWhile) {
      Consume(TokenType::kWhile);
      auto loop_start = builder_->NewLabel();
      auto loop_end = builder_->NewLabel();

      builder_->Mark(loop_start);
      Consume(TokenType::kLParen);
      ParseExpression();
      Consume(TokenType::kRParen);

      builder_->Jz(loop_end);
      ParseStatement();
      builder_->Jmp(loop_start);
      builder_->Mark(loop_end);
      return;
    }

    if (curr_.type == TokenType::kStore8 || curr_.type == TokenType::kStore64) {
      bool is8 = (curr_.type == TokenType::kStore8);
      Consume(curr_.type);
      Consume(TokenType::kLParen);
      ParseExpression(); // addr
      Consume(TokenType::kComma);
      ParseExpression(); // val
      Consume(TokenType::kRParen);
      Consume(TokenType::kSemicolon);
      if (is8) builder_->StoreMem8();
      else builder_->StoreMem64();
      return;
    }

    if (curr_.type == TokenType::kTypeInt64) {
      Consume(TokenType::kTypeInt64);
      Token var_token = Consume(TokenType::kIdent);
      std::uint8_t local_idx = AllocateLocal(var_token.text);
      if (curr_.type == TokenType::kAssign) {
        Consume(TokenType::kAssign);
        ParseExpression();
        builder_->StoreLocal(local_idx);
      }
      Consume(TokenType::kSemicolon);
      return;
    }

    if (curr_.type == TokenType::kIdent) {
      Token var_token = Consume(TokenType::kIdent);
      std::uint8_t local_idx = GetLocal(var_token.text);
      Consume(TokenType::kAssign);
      ParseExpression();
      builder_->StoreLocal(local_idx);
      Consume(TokenType::kSemicolon);
      return;
    }

    throw std::runtime_error("Unexpected statement beginning with '" + curr_.text + "' on line " + std::to_string(curr_.line));
  }

  void ParseExpression() {
    ParseLogicalOr();
  }

  void ParseLogicalOr() {
    ParseLogicalAnd();
    while (curr_.type == TokenType::kPipePipe) {
      Consume(TokenType::kPipePipe);
      ParseLogicalAnd();
      builder_->BitOr();
    }
  }

  void ParseLogicalAnd() {
    ParseBitwiseOr();
    while (curr_.type == TokenType::kAmpAmp) {
      Consume(TokenType::kAmpAmp);
      ParseBitwiseOr();
      builder_->BitAnd();
    }
  }

  void ParseBitwiseOr() {
    ParseBitwiseXor();
    while (curr_.type == TokenType::kPipe) {
      Consume(TokenType::kPipe);
      ParseBitwiseXor();
      builder_->BitOr();
    }
  }

  void ParseBitwiseXor() {
    ParseBitwiseAnd();
    while (curr_.type == TokenType::kCaret) {
      Consume(TokenType::kCaret);
      ParseBitwiseAnd();
      builder_->BitXor();
    }
  }

  void ParseBitwiseAnd() {
    ParseEquality();
    while (curr_.type == TokenType::kAmpersand) {
      Consume(TokenType::kAmpersand);
      ParseEquality();
      builder_->BitAnd();
    }
  }

  void ParseEquality() {
    ParseRelational();
    while (curr_.type == TokenType::kEqEq || curr_.type == TokenType::kExclamationEq) {
      TokenType op = curr_.type;
      Consume(op);
      ParseRelational();
      if (op == TokenType::kEqEq) {
        builder_->CmpEq();
      } else {
        builder_->CmpEq();
        builder_->PushConst(0);
        builder_->CmpEq(); // !eq
      }
    }
  }

  void ParseRelational() {
    ParseAdditive();
    while (curr_.type == TokenType::kLess || curr_.type == TokenType::kLessEq ||
           curr_.type == TokenType::kGreater || curr_.type == TokenType::kGreaterEq) {
      TokenType op = curr_.type;
      Consume(op);
      ParseAdditive();
      if (op == TokenType::kLess) {
        builder_->CmpLt();
      } else if (op == TokenType::kGreater) {
        builder_->CmpGt();
      } else if (op == TokenType::kLessEq) {
        // a <= b <=> !(a > b)
        builder_->CmpGt();
        builder_->PushConst(0);
        builder_->CmpEq();
      } else if (op == TokenType::kGreaterEq) {
        // a >= b <=> !(a < b)
        builder_->CmpLt();
        builder_->PushConst(0);
        builder_->CmpEq();
      }
    }
  }

  void ParseAdditive() {
    ParseMultiplicative();
    while (curr_.type == TokenType::kPlus || curr_.type == TokenType::kMinus) {
      TokenType op = curr_.type;
      Consume(op);
      ParseMultiplicative();
      if (op == TokenType::kPlus) builder_->Add();
      else builder_->Sub();
    }
  }

  void ParseMultiplicative() {
    ParseUnary();
    while (curr_.type == TokenType::kStar || curr_.type == TokenType::kSlash || curr_.type == TokenType::kPercent) {
      TokenType op = curr_.type;
      Consume(op);
      ParseUnary();
      if (op == TokenType::kStar) builder_->Mul();
      else if (op == TokenType::kSlash) builder_->Div();
      else if (op == TokenType::kPercent) builder_->Mod();
    }
  }

  void ParseUnary() {
    if (curr_.type == TokenType::kMinus) {
      Consume(TokenType::kMinus);
      builder_->PushConst(0);
      ParseUnary();
      builder_->Sub();
      return;
    }
    if (curr_.type == TokenType::kTilde) {
      Consume(TokenType::kTilde);
      ParseUnary();
      builder_->BitNot();
      return;
    }
    if (curr_.type == TokenType::kExclamation) {
      Consume(TokenType::kExclamation);
      ParseUnary();
      builder_->PushConst(0);
      builder_->CmpEq();
      return;
    }
    ParsePrimary();
  }

  void ParsePrimary() {
    if (curr_.type == TokenType::kNumber) {
      Token t = Consume(TokenType::kNumber);
      builder_->PushConst(t.number);
      return;
    }

    if (curr_.type == TokenType::kLoad8) {
      Consume(TokenType::kLoad8);
      Consume(TokenType::kLParen);
      ParseExpression();
      Consume(TokenType::kRParen);
      builder_->LoadMem8();
      return;
    }

    if (curr_.type == TokenType::kLoad64) {
      Consume(TokenType::kLoad64);
      Consume(TokenType::kLParen);
      ParseExpression();
      Consume(TokenType::kRParen);
      builder_->LoadMem64();
      return;
    }

    if (curr_.type == TokenType::kIdent) {
      Token t = Consume(TokenType::kIdent);
      std::uint8_t local_idx = GetLocal(t.text);
      builder_->PushLocal(local_idx);
      return;
    }

    if (curr_.type == TokenType::kLParen) {
      Consume(TokenType::kLParen);
      ParseExpression();
      Consume(TokenType::kRParen);
      return;
    }

    throw std::runtime_error("Unexpected token in expression: '" + curr_.text + "' on line " + std::to_string(curr_.line));
  }

  Lexer lexer_;
  CompilerOptions opts_;
  Token curr_;
  std::unique_ptr<ProgramBuilder> builder_;
  std::unordered_map<std::string, std::uint8_t> locals_;
  bool has_returned_ = false;
  bool has_enclosing_brace_ = false;
};

}  // namespace

std::optional<Program> CompileCSubset(const std::string& source,
                                      std::string* out_error,
                                      const CompilerOptions& options) {
  Parser parser(source, options);
  return parser.Parse(out_error);
}

}  // namespace rtprotect::vm
