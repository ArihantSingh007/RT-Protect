// tooling/integration_engine.cpp

#include "tooling/integration_engine.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <unordered_map>

#include <windows.h>

#include "antitamper/risk_policy.h"
#include "bytecode_vm/compiler.h"
#include "bytecode_vm/opcode_map.h"
#include "tooling/cxx_ast_scanner.h"
#include "tooling/clang_ast_scanner.h"
#include "tooling/unreal_integration.h"
#include "bytecode_vm/serialize.h"
#include "bytecode_vm/vm.h"
#include "crypto/aead.h"
#include "crypto/kdf.h"
#include "integrity/keys.h"
#include "integrity/manifest.h"
#include "integrity/sha256.h"
#include "integrity/signer.h"
#include "integrity/verifier.h"
#include "licensing/activation.h"
#include "licensing/activation_client.h"
#include "licensing/activation_server.h"
#include "licensing/secure_storage.h"
#include "licensing/hardware_id.h"
#include "licensing/license.h"
#include "licensing/license_signer.h"
#include "licensing/license_verifier.h"
#include "tooling/file_io.h"
#include <openssl/rand.h>

namespace fs = std::filesystem;

namespace rtprotect::tooling {

namespace {

std::string GetToolExecutablePath() {
#if defined(_WIN32)
  DWORD size = 512;
  while (size <= 65536) {
    std::vector<char> buf(size);
    DWORD ret = ::GetModuleFileNameA(NULL, buf.data(), size);
    if (ret == 0) return "";
    if (ret < size - 1) return std::string(buf.data(), ret);
    size *= 2;
  }
  return "";
#else
  return "";
#endif
}

std::string EscapeJson(const std::string& str) {
  std::string out;
  out.reserve(str.size() * 2);
  for (char c : str) {
    if (c == '\\') out += "\\\\";
    else if (c == '"') out += "\\\"";
    else if (c == '\n') out += "\\n";
    else if (c == '\r') out += "\\r";
    else if (c == '\t') out += "\\t";
    else if (static_cast<unsigned char>(c) < 0x20) {
      char buf[8];
      std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
      out += buf;
    } else {
      out += c;
    }
  }
  return out;
}

std::string EscapeCxxStringLiteral(const std::string& str) {
  std::string out;
  out.reserve(str.size() * 2);
  for (unsigned char c : str) {
    if (c == '\\') out += "\\\\";
    else if (c == '"') out += "\\\"";
    else if (c == '\n') out += "\\n";
    else if (c == '\r') out += "\\r";
    else if (c == '\t') out += "\\t";
    else if (c < 32 || c >= 127) {
      char buf[8];
      std::snprintf(buf, sizeof(buf), "\\x%02x", c);
      out += buf;
    } else {
      out += static_cast<char>(c);
    }
  }
  return out;
}

bool IsPathWithin(const fs::path& child, const fs::path& base) {
  std::error_code ec;
  auto abs_child = fs::weakly_canonical(child, ec);
  if (ec) return false;
  auto abs_base = fs::weakly_canonical(base, ec);
  if (ec) return false;

  auto rel = fs::relative(abs_child, abs_base, ec);
  if (ec || rel.empty()) return false;
  auto rel_str = rel.string();
  if (rel_str == ".." ||
      rel_str.rfind(std::string("..") + static_cast<char>(fs::path::preferred_separator), 0) == 0 ||
      rel_str.rfind("../", 0) == 0 || rel_str.rfind("..\\", 0) == 0 ||
      rel.is_absolute()) {
    return false;
  }
  return true;
}

bool IsValidIdentifier(const std::string& str) {
  if (str.empty() || str.size() > 128) return false;
  for (char c : str) {
    if (!std::isalnum(static_cast<unsigned char>(c)) && c != '.' && c != '_' && c != '-') {
      return false;
    }
  }
  return true;
}

std::vector<std::string> DiscoverCMakeExecutableTargets(const fs::path& cmake_file) {
  std::vector<std::string> targets;
  auto content = ReadTextFile(cmake_file.string());
  if (!content.has_value()) return targets;

  std::string stripped;
  std::istringstream stream(*content);
  std::string line;
  while (std::getline(stream, line)) {
    auto comment_pos = line.find('#');
    if (comment_pos != std::string::npos) {
      line = line.substr(0, comment_pos);
    }
    stripped += line + "\n";
  }

  std::size_t pos = 0;
  const std::string keyword = "add_executable";
  while ((pos = stripped.find(keyword, pos)) != std::string::npos) {
    std::size_t after_kw = pos + keyword.size();
    while (after_kw < stripped.size() && std::isspace(static_cast<unsigned char>(stripped[after_kw]))) {
      after_kw++;
    }
    if (after_kw < stripped.size() && stripped[after_kw] == '(') {
      std::size_t start_token = after_kw + 1;
      while (start_token < stripped.size() && std::isspace(static_cast<unsigned char>(stripped[start_token]))) {
        start_token++;
      }
      std::size_t end_token = start_token;
      while (end_token < stripped.size() &&
             !std::isspace(static_cast<unsigned char>(stripped[end_token])) &&
             stripped[end_token] != ')' &&
             stripped[end_token] != ';') {
        end_token++;
      }
      if (end_token > start_token) {
        std::string target = stripped.substr(start_token, end_token - start_token);
        if (target != "IMPORTED" && target != "ALIAS" && !target.empty() && target[0] != '$') {
          if (std::find(targets.begin(), targets.end(), target) == targets.end()) {
            targets.push_back(target);
          }
        }
      }
      pos = end_token;
    } else {
      pos = after_kw;
    }
  }
  return targets;
}

int RunProcess(const std::string& exe, const std::vector<std::string>& args) {
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

  STARTUPINFOA si{};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi{};

  std::vector<char> cmd_buf(cmd_line.begin(), cmd_line.end());
  cmd_buf.push_back('\0');

  BOOL ok = CreateProcessA(NULL, cmd_buf.data(), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
  if (!ok) return -1;

  WaitForSingleObject(pi.hProcess, INFINITE);
  DWORD exit_code = 1;
  GetExitCodeProcess(pi.hProcess, &exit_code);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  return static_cast<int>(exit_code);
}

std::string GenerateRandomHex(std::size_t num_bytes) {
  std::vector<unsigned char> buf(num_bytes);
  if (RAND_bytes(buf.data(), static_cast<int>(num_bytes)) != 1) {
    auto now_ns = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    std::ostringstream ss;
    ss << std::hex << now_ns;
    return ss.str();
  }
  std::ostringstream ss;
  for (unsigned char b : buf) {
    char h[3];
    std::snprintf(h, sizeof(h), "%02x", b);
    ss << h;
  }
  return ss.str();
}

std::string FormatByteArrayLiteral(const std::uint8_t* data, std::size_t len) {
  std::ostringstream ss;
  for (std::size_t i = 0; i < len; ++i) {
    char h[8];
    std::snprintf(h, sizeof(h), "0x%02X", data[i]);
    ss << h;
    if (i + 1 < len) ss << ", ";
    if ((i + 1) % 12 == 0 && i + 1 < len) ss << "\n        ";
  }
  return ss.str();
}

bool IsExcludedSourcePath(const fs::path& p, const fs::path& proj_root) {
  std::error_code ec;
  auto rel = fs::relative(p, proj_root, ec);
  if (ec) return false;

  for (const auto& part : rel) {
    std::string s = part.string();
    if (s == ".git" || s == ".rtp_backup" || s == "third_party" || s == "external" || s == "tests") {
      return true;
    }
    if (s.rfind("build", 0) == 0) {
      return true;
    }
  }

  std::string fname = p.filename().string();
  if (fname.rfind("rtprotect_", 0) == 0) {
    return true;
  }
  if (fname == "release.manifest" || fname == "release.sig" || fname == "release.pub" ||
      fname == "license.pub" || fname == "activation.pub" || fname == "client.license") {
    return true;
  }

  return false;
}

}  // namespace

std::optional<crypto::Aes256Key> DeriveBuildFunctionMasterKey(
    const std::array<std::uint8_t, 32>& vm_root,
    const integrity::Ed25519PublicKey& manifest_pubkey,
    const std::string& product_id,
    const std::uint8_t* salt,
    std::size_t salt_len) {
  std::vector<std::uint8_t> hkdf_salt(manifest_pubkey.begin(), manifest_pubkey.end());
  if (salt && salt_len > 0) {
    hkdf_salt.insert(hkdf_salt.end(), salt, salt + salt_len);
  }
  std::string info = std::string("rtprotect/virtualize/") + product_id;
  crypto::SecureBuffer sec_seed(vm_root.data(), vm_root.size());
  auto derived = crypto::Hkdf::DeriveKey(sec_seed, hkdf_salt, info, crypto::kAes256KeyLen);
  if (!derived.has_value()) return std::nullopt;
  return crypto::Aes256Key::FromBytes(derived->data(), derived->size());
}

bool TransformSourceFile(const fs::path& file_path,
                         const ProtectionProfile profile,
                         const std::uint32_t opcode_seed,
                         const std::array<std::uint8_t, 32>& vm_root,
                         const integrity::Ed25519PublicKey& manifest_pubkey,
                         const std::string& product_id,
                         std::vector<std::string>& out_virtualized,
                         std::size_t& out_obfuscated_count,
                         std::size_t& out_scattered_count,
                         std::string* out_error_message) {
  auto content_opt = ReadTextFile(file_path.string());
  if (!content_opt.has_value()) {
    if (out_error_message) *out_error_message = "Failed to read source file: " + file_path.string();
    return false;
  }
  std::string content = *content_opt;
  bool modified = false;

  auto opcode_map = rtprotect::vm::OpcodeMap::FromSeed(opcode_seed);

  // 1. Clang AST semantic validation with compilation database flags (Stage 3)
  std::unordered_map<std::string, ClangFunctionDecl> clang_decls;
  if (ClangAstScanner::IsAvailable()) {
    std::vector<std::string> compiler_flags;
    auto comp_db = CompilationDatabase::LoadFromDirectory(file_path.parent_path().string());
    if (!comp_db.has_value() && file_path.parent_path().has_parent_path()) {
      comp_db = CompilationDatabase::LoadFromDirectory(file_path.parent_path().parent_path().string());
    }
    if (comp_db.has_value()) {
      compiler_flags = comp_db->GetFlagsForFile(file_path.string());
    }

    auto clang_fns = ClangAstScanner::AnalyzeTranslationUnit(file_path.string(), compiler_flags);
    for (const auto& cfn : clang_fns) {
      if (!cfn.signature.empty()) {
        clang_decls[cfn.signature] = cfn;
      }
      clang_decls[cfn.name] = cfn;
    }
  }

  // 2. AST-aware scan for functions marked with RTPROTECT_VIRTUALIZE or [[rtprotect::virtualize]]
  CxxAstScanner scanner(content);
  auto tagged_fns = scanner.FindTaggedFunctions();

  // Process in reverse order so replacements do not invalidate earlier offsets
  std::sort(tagged_fns.begin(), tagged_fns.end(), [](const ExtractedFunction& a, const ExtractedFunction& b) {
    return a.full_range.start > b.full_range.start;
  });

  for (auto& fn : tagged_fns) {
    std::string fn_name = fn.name;
    const auto& arg_names = fn.arg_names;

    // A. Clang AST semantic validation with overload signature matching
    std::string sig_key = fn_name + "(" + fn.params_raw + ")";
    auto it = clang_decls.find(sig_key);
    if (it == clang_decls.end()) {
      it = clang_decls.find(fn_name);
    }

    if (it != clang_decls.end()) {
      const auto& cfn = it->second;
      std::string reject_reason;
      if (!ClangAstScanner::ValidateVirtualizationEligibility(cfn, &reject_reason)) {
        if (profile == ProtectionProfile::kMaximum || profile == ProtectionProfile::kBalanced) {
          if (out_error_message) {
            *out_error_message = "Function '" + fn_name + "' marked for virtualization failed Clang AST semantic validation: " + reject_reason;
          }
          return false;
        }
        continue;
      }
      if (!cfn.return_type.empty()) {
        fn.return_type = cfn.return_type;
      }
    }

    // B. Compile function using CompileCSubset with seeded OpcodeMap
    std::string compile_err;
    rtprotect::vm::CompilerOptions compiler_opts;
    compiler_opts.opcode_map = &opcode_map;

    auto prog = rtprotect::vm::CompileCSubset(fn.full_signature_and_body, &compile_err, compiler_opts);
    if (!prog.has_value()) {
      prog = rtprotect::vm::CompileCSubset(fn.body, &compile_err, compiler_opts);
    }

    if (!prog.has_value()) {
      if (profile == ProtectionProfile::kMaximum || profile == ProtectionProfile::kBalanced) {
        if (out_error_message) {
          *out_error_message = "Function '" + fn_name + "' marked for virtualization failed bytecode compilation: " + compile_err;
        }
        return false;
      }
      continue;
    }

    auto serialized = rtprotect::vm::Serialize(*prog);

    // C. Function salt generation without deterministic fallback
    std::array<std::uint8_t, 16> fn_salt{};
    if (RAND_bytes(fn_salt.data(), static_cast<int>(fn_salt.size())) != 1) {
      if (out_error_message) {
        *out_error_message = "Cryptographic RNG failure (RAND_bytes) while generating salt for function '" + fn_name + "'";
      }
      return false;
    }

    auto master_key = DeriveBuildFunctionMasterKey(vm_root, manifest_pubkey, product_id, fn_salt.data(), fn_salt.size());
    if (!master_key.has_value()) {
      if (out_error_message) {
        *out_error_message = "Failed to derive function master key for function '" + fn_name + "'";
      }
      return false;
    }

    rtprotect::antitamper::RiskAssessment clean_risk;
    clean_risk.risk_score = 0;
    auto bound_key = rtprotect::antitamper::DeriveTamperBoundKey(*master_key, clean_risk, fn_name);
    auto encrypted = rtprotect::crypto::Encrypt(bound_key, serialized.data(), serialized.size());
    if (!encrypted.has_value()) {
      if (out_error_message) {
        *out_error_message = "Encryption failed for virtualized function '" + fn_name + "'";
      }
      return false;
    }

    // D. Extract function header signature & determine return type
    std::string header = fn.header;
    while (!header.empty() && std::isspace(static_cast<unsigned char>(header.front()))) header.erase(0, 1);
    while (!header.empty() && std::isspace(static_cast<unsigned char>(header.back()))) header.pop_back();

    std::string ret_type = fn.return_type;
    while (!ret_type.empty() && std::isspace(static_cast<unsigned char>(ret_type.front()))) ret_type.erase(0, 1);
    while (!ret_type.empty() && std::isspace(static_cast<unsigned char>(ret_type.back()))) ret_type.pop_back();
    if (ret_type.empty()) ret_type = "int";

    bool is_void = (ret_type == "void");
    std::string fail_stmt = is_void ? "return;" : ("return static_cast<" + ret_type + ">(0);");
    std::string ok_stmt = is_void ? "return;" : ("return static_cast<" + ret_type + ">(s_res.value);");

    std::ostringstream rep_ss;
    rep_ss << "// [RTProtect Bytecode-Virtualized Function: " << fn_name << "]\n";
    rep_ss << header << " {\n";
    rep_ss << "    static const std::uint8_t s_enc_code[] = {\n        "
           << FormatByteArrayLiteral(encrypted->ciphertext.data(), encrypted->ciphertext.size()) << "\n    };\n";
    rep_ss << "    static const std::uint8_t s_nonce[] = {\n        "
           << FormatByteArrayLiteral(encrypted->nonce.bytes, sizeof(encrypted->nonce.bytes)) << "\n    };\n";
    rep_ss << "    static const std::uint8_t s_tag[] = {\n        "
           << FormatByteArrayLiteral(encrypted->tag, sizeof(encrypted->tag)) << "\n    };\n";
    rep_ss << "    static const std::uint8_t s_fn_salt[] = {\n        "
           << FormatByteArrayLiteral(fn_salt.data(), fn_salt.size()) << "\n    };\n";
    rep_ss << "    std::uint64_t s_tamper_accum = 0;\n";
    rep_ss << "    rtprotect::antitamper::ScatterTamperCheck(\"" << fn_name << "_entry\", &s_tamper_accum);\n";
    rep_ss << "    auto s_risk = rtprotect::antitamper::AssessFastEnvironmentRisk();\n";
    rep_ss << "    if (s_tamper_accum != 0) s_risk.risk_score = 100;\n";
    rep_ss << "    auto s_fn_key = rtprotect_client::GetFunctionMasterKey(s_fn_salt, sizeof(s_fn_salt));\n";
    rep_ss << "    if (!s_fn_key.has_value()) " << fail_stmt << "\n";
    rep_ss << "    auto s_bound_key = rtprotect::antitamper::DeriveTamperBoundKey(*s_fn_key, s_risk, \"" << fn_name << "\");\n";
    rep_ss << "    rtprotect::crypto::EncryptedMessage s_msg;\n";
    rep_ss << "    std::memcpy(s_msg.nonce.bytes, s_nonce, sizeof(s_nonce));\n";
    rep_ss << "    s_msg.ciphertext.assign(s_enc_code, s_enc_code + sizeof(s_enc_code));\n";
    rep_ss << "    std::memcpy(s_msg.tag, s_tag, sizeof(s_tag));\n";
    rep_ss << "    auto s_plain = rtprotect::crypto::Decrypt(s_bound_key, s_msg, nullptr, 0, nullptr);\n";
    rep_ss << "    if (!s_plain.has_value()) " << fail_stmt << "\n";
    rep_ss << "    auto s_prog = rtprotect::vm::Deserialize(s_plain->data(), s_plain->size());\n";
    rep_ss << "    if (!s_prog.has_value()) " << fail_stmt << "\n";
    rep_ss << "    std::vector<std::int64_t> s_args = {";
    for (std::size_t k = 0; k < arg_names.size(); ++k) {
      if (k > 0) rep_ss << ", ";
      rep_ss << "static_cast<std::int64_t>(" << arg_names[k] << ")";
    }
    rep_ss << "};\n";
    rep_ss << "    rtprotect::vm::MemoryContext s_mem_ctx(65536);\n";

    // Randomize VM engine flavor per-function: (fn_hash ^ opcode_seed) % 4
    std::uint32_t fn_hash = 2166136261u;
    for (char c : fn_name) {
      fn_hash = (fn_hash ^ static_cast<std::uint8_t>(c)) * 16777619u;
    }
    std::uint32_t engine_flavor = (fn_hash ^ opcode_seed) % 4;
    const char* flavor_enum = "rtprotect::vm::VmEngineFlavor::kStackBased";
    if (engine_flavor == 1) {
      flavor_enum = "rtprotect::vm::VmEngineFlavor::kRegisterThreaded";
    } else if (engine_flavor == 2) {
      flavor_enum = "rtprotect::vm::VmEngineFlavor::kDirectThreadedTable";
    } else if (engine_flavor == 3) {
      flavor_enum = "rtprotect::vm::VmEngineFlavor::kIndirectTokenThreaded";
    }

    rep_ss << "    auto s_native_tbl = reinterpret_cast<const rtprotect::vm::NativeFunctionTable*>(rtprotect::antitamper::GetAntiTamperNativeTableVoid());\n";
    rep_ss << "    auto s_res = rtprotect::vm::Run(*s_prog, s_args, &rtprotect_client::GetBuildOpcodeMap(), &s_mem_ctx, "
           << flavor_enum << ", 0, s_native_tbl);\n";
    rep_ss << "    if (s_res.error != rtprotect::vm::VmError::kNone) {\n";
    rep_ss << "        s_tamper_accum ^= (0xDEADBEEF00000000ULL | static_cast<std::uint64_t>(s_res.error));\n";
    rep_ss << "        rtprotect::antitamper::ScatterTamperCheck(\"" << fn_name << "_fault\", &s_tamper_accum);\n";
    rep_ss << "        " << fail_stmt << "\n";
    rep_ss << "    }\n";
    rep_ss << "    std::uint64_t s_delta = rtprotect::antitamper::FoldTamperStateDelta(s_risk, 0x5EEDCAFEULL) ^ s_tamper_accum;\n";
    rep_ss << "    rtprotect::antitamper::FunctionCrossLink::DepositToken(" << fn_hash << "ULL, static_cast<std::uint64_t>(s_res.value) ^ 0xFEEDFACECAFEULL);\n";
    rep_ss << "    if (!rtprotect::antitamper::FunctionCrossLink::VerifyToken(" << fn_hash << "ULL, static_cast<std::uint64_t>(s_res.value) ^ 0xFEEDFACECAFEULL)) {\n";
    rep_ss << "        s_delta ^= 0xBADF00D1ULL;\n";
    rep_ss << "    }\n";
    if (is_void) {
      rep_ss << "    return;\n";
    } else {
      rep_ss << "    return static_cast<" << ret_type << ">(rtprotect::obfuscation::MbaSub<std::int64_t>(s_res.value, static_cast<std::int64_t>(s_delta)));\n";
    }
    rep_ss << "}";

    content.replace(fn.full_range.start, fn.full_range.end - fn.full_range.start, rep_ss.str());
    out_virtualized.push_back(fn_name);
    modified = true;
  }

  // 2. Translation-unit string obfuscation (Step 5)
  if (profile == ProtectionProfile::kMaximum || profile == ProtectionProfile::kBalanced) {
    CxxAstScanner post_scanner(content);
    std::size_t unit_obf = 0;
    std::string rewritten = post_scanner.RewriteTranslationUnitStrings(&unit_obf);
    if (unit_obf > 0) {
      content = rewritten;
      out_obfuscated_count += unit_obf;
      modified = true;
    }
  } else {
    // Explicit RTPROTECT_STRING("...") handling
    std::size_t str_pos = 0;
    while ((str_pos = content.find("RTPROTECT_STRING(\"", str_pos)) != std::string::npos) {
      auto end_quote = content.find("\")", str_pos + 18);
      if (end_quote != std::string::npos) {
        std::string str_lit = content.substr(str_pos + 17, end_quote - str_pos - 16);
        std::string repl = "OBFUSCATED_STRING(" + str_lit + ")";
        content.replace(str_pos, (end_quote + 2) - str_pos, repl);
        str_pos += repl.size();
        ++out_obfuscated_count;
        modified = true;
      } else {
        str_pos += 18;
      }
    }
  }

  // 3. Ensure required headers are included if modified
  if (modified) {
    const std::vector<std::string> required_includes = {
        "#include \"rtprotect_config.h\"",
        "#include \"bytecode_vm/vm.h\"",
        "#include \"bytecode_vm/serialize.h\"",
        "#include \"crypto/aead.h\"",
        "#include \"antitamper/risk_policy.h\"",
        "#include \"obfuscation/control_flow.h\"",
        "#include \"obfuscation/obfuscated_string.h\"",
        "#include <cstdint>",
        "#include <cstring>",
        "#include <vector>",
    };
    std::string missing_includes;
    for (const auto& include_line : required_includes) {
      if (content.find(include_line) == std::string::npos) {
        missing_includes += include_line + "\n";
      }
    }
    if (!missing_includes.empty()) {
      content = missing_includes + "\n" + content;
    }
    ++out_scattered_count;
    if (!WriteTextFile(file_path.string(), content)) {
      return false;
    }
  }

  return modified;
}

const char* ToString(ProtectionProfile p) {
  switch (p) {
    case ProtectionProfile::kDevelopment: return "development";
    case ProtectionProfile::kBalanced: return "balanced";
    case ProtectionProfile::kMaximum: return "maximum";
  }
  return "unknown";
}

ProtectionProfile ParseProfile(const std::string& str) {
  if (str == "dev" || str == "development") return ProtectionProfile::kDevelopment;
  if (str == "max" || str == "maximum") return ProtectionProfile::kMaximum;
  return ProtectionProfile::kBalanced;
}

const char* ToString(IntegrationState s) {
  switch (s) {
    case IntegrationState::kPlanned: return "planned";
    case IntegrationState::kIntegrated: return "integrated";
    case IntegrationState::kBuilt: return "built";
    case IntegrationState::kAwaitingSignature: return "awaiting_signature";
    case IntegrationState::kValidated: return "validated";
    case IntegrationState::kFailed: return "failed";
  }
  return "unknown";
}

std::string ChangePlan::FormatSummary() const {
  std::ostringstream ss;
  ss << "RTProtect Integration Change Plan\n";
  ss << "=================================\n";
  ss << "Detected Language:     " << detected_language << "\n";
  ss << "Detected Build System: " << detected_build_system << "\n";
  ss << "Detected Sources:      " << detected_sources.size() << " file(s)\n";
  for (const auto& s : detected_sources) {
    ss << "  - " << s << "\n";
  }
  ss << "\nFiles to Create:\n";
  for (const auto& f : files_to_create) {
    ss << "  + " << f << "\n";
  }
  ss << "\nFiles to Modify:\n";
  for (const auto& f : files_to_modify) {
    ss << "  * " << f << "\n";
  }
  if (!warnings.empty()) {
    ss << "\nWarnings:\n";
    for (const auto& w : warnings) {
      ss << "  ! " << w << "\n";
    }
  }
  ss << "Supported: " << (is_supported ? "YES" : "NO") << "\n";
  return ss.str();
}

std::string IntegrationReport::ToJson() const {
  std::ostringstream ss;
  ss << "{\n";
  ss << "  \"success\": " << (success ? "true" : "false") << ",\n";
  ss << "  \"state\": \"" << ToString(state) << "\",\n";
  ss << "  \"is_staged_only\": " << (is_staged_only ? "true" : "false") << ",\n";
  ss << "  \"target_name\": \"" << EscapeJson(target_name) << "\",\n";
  ss << "  \"error_message\": \"" << EscapeJson(error_message) << "\",\n";
  ss << "  \"backup_path\": \"" << EscapeJson(backup_path) << "\",\n";
  ss << "  \"build_succeeded\": " << (build_succeeded ? "true" : "false") << ",\n";
  ss << "  \"validation_succeeded\": " << (validation_succeeded ? "true" : "false") << ",\n";

  auto write_array = [&](const char* name, const std::vector<std::string>& list, bool trailing_comma) {
    ss << "  \"" << name << "\": [";
    for (std::size_t i = 0; i < list.size(); ++i) {
      ss << "\"" << EscapeJson(list[i]) << "\"";
      if (i + 1 < list.size()) ss << ", ";
    }
    ss << "]" << (trailing_comma ? "," : "") << "\n";
  };

  write_array("modified_files", modified_files, true);
  write_array("generated_files", generated_files, true);
  write_array("warnings", warnings, true);
  write_array("virtualized_functions", virtualized_functions, true);

  ss << "  \"obfuscated_string_count\": " << obfuscated_string_count << ",\n";
  ss << "  \"scattered_check_count\": " << scattered_check_count << ",\n";
  char seed_hex[32];
  std::snprintf(seed_hex, sizeof(seed_hex), "0x%08X", opcode_seed);
  ss << "  \"opcode_seed\": \"" << seed_hex << "\",\n";

  ss << "  \"public_key_file\": \"" << EscapeJson(public_key_file) << "\",\n";
  ss << "  \"manifest_public_key_file\": \"" << EscapeJson(manifest_public_key_file) << "\",\n";
  ss << "  \"license_public_key_file\": \"" << EscapeJson(license_public_key_file) << "\",\n";
  ss << "  \"activation_public_key_file\": \"" << EscapeJson(activation_public_key_file) << "\",\n";
  ss << "  \"countermeasure_public_key_file\": \"" << EscapeJson(countermeasure_public_key_file) << "\",\n";
  if (!private_key_file.empty()) {
    ss << "  \"private_key_file\": \"" << EscapeJson(private_key_file) << "\",\n";
  }
  ss << "  \"manifest_file\": \"" << EscapeJson(manifest_file) << "\",\n";
  ss << "  \"signature_file\": \"" << EscapeJson(signature_file) << "\",\n";
  ss << "  \"license_file\": \"" << EscapeJson(license_file) << "\"\n";
  ss << "}\n";
  return ss.str();
}

ChangePlan PlanIntegration(const IntegrationOptions& options) {
  ChangePlan plan;
  if (options.target_project_path.empty()) {
    plan.explanation = "Target project path is empty";
    return plan;
  }

  if (!IsValidIdentifier(options.product_id)) {
    plan.is_supported = false;
    plan.explanation = "Invalid product identifier: '" + options.product_id + "'. Must match ^[A-Za-z0-9_.-]+$ and be <= 128 characters.";
    return plan;
  }
  if (!IsValidIdentifier(options.release_version)) {
    plan.is_supported = false;
    plan.explanation = "Invalid release version: '" + options.release_version + "'. Must match ^[A-Za-z0-9_.-]+$ and be <= 128 characters.";
    return plan;
  }

  if (!options.use_dev_keys && (!options.sign_manifest_key_path.empty() || !options.sign_license_key_path.empty())) {
    plan.warnings.push_back(
        "Vendor private signing keys were supplied to build integration. For production environments, "
        "use public keys during build and invoke 'sign-release' on an isolated signing machine.");
  }

  std::error_code ec;
  fs::path proj_path = fs::canonical(options.target_project_path, ec);
  if (ec || !fs::is_directory(proj_path)) {
    plan.explanation = "Target project path does not exist or is not a directory";
    return plan;
  }

  // Detect build system
  fs::path cmake_file = proj_path / "CMakeLists.txt";
  if (fs::exists(cmake_file)) {
    plan.detected_build_system = "CMake";
    plan.detected_language = "C++";

    auto targets = DiscoverCMakeExecutableTargets(cmake_file);
    if (targets.empty()) {
      plan.is_supported = false;
      plan.explanation = "No executable target (add_executable) detected in CMakeLists.txt";
      return plan;
    }

    if (targets.size() > 1 && options.target_name.empty()) {
      std::string t_list;
      for (std::size_t i = 0; i < targets.size(); ++i) {
        if (i > 0) t_list += ", ";
        t_list += targets[i];
      }
      plan.warnings.push_back("Multiple executable targets found: [" + t_list + "]. Specify --target <name> to select.");
    }

    plan.is_supported = true;
    plan.files_to_modify.push_back(cmake_file.string());
  } else if (IsUnrealProject(proj_path)) {
    return PlanUnrealIntegration(options);
  } else {
    plan.explanation = "No supported build system found (CMakeLists.txt or .uproject required)";
    return plan;
  }

  // Scan sources (filtering out build, test, third_party, and non-C++ files)
  for (const auto& entry : fs::recursive_directory_iterator(proj_path, ec)) {
    if (entry.is_regular_file()) {
      if (IsExcludedSourcePath(entry.path(), proj_path)) {
        continue;
      }
      auto ext = entry.path().extension().string();
      if (ext == ".cpp" || ext == ".cc" || ext == ".cxx") {
        plan.detected_sources.push_back(entry.path().string());
      }
    }
  }

  if (plan.detected_sources.empty()) {
    plan.warnings.push_back("No C++ source files found in target directory");
  }

  // Determine candidate source files that will actually be modified
  for (const auto& src_path_str : plan.detected_sources) {
    auto file_content = ReadTextFile(src_path_str);
    if (!file_content.has_value()) continue;
    bool will_modify = false;
    if (file_content->find("RTPROTECT_VIRTUALIZE") != std::string::npos ||
        file_content->find("[[rtprotect::virtualize]]") != std::string::npos ||
        file_content->find("RTPROTECT_STRING") != std::string::npos) {
      will_modify = true;
    } else if (options.profile == ProtectionProfile::kMaximum || options.profile == ProtectionProfile::kBalanced) {
      CxxAstScanner scan(*file_content);
      auto lits = scan.FindAllStringLiterals();
      if (!lits.empty()) {
        will_modify = true;
      }
    }
    if (will_modify) {
      plan.files_to_modify.push_back(src_path_str);
    }
  }

  plan.files_to_create.push_back((proj_path / "rtprotect_config.h").string());
  plan.files_to_create.push_back((proj_path / "rtprotect_runtime_glue.cpp").string());
  plan.files_to_create.push_back((proj_path / "release.pub").string());
  plan.files_to_create.push_back((proj_path / "license.pub").string());
  plan.files_to_create.push_back((proj_path / "activation.pub").string());
  plan.files_to_create.push_back((proj_path / "countermeasure.pub").string());
  plan.files_to_create.push_back((proj_path / "release.manifest").string());
  plan.files_to_create.push_back((proj_path / "release.sig").string());
  plan.files_to_create.push_back((proj_path / "client.license").string());
  // NOTE: release.priv is NEVER created in the client project

  return plan;
}

IntegrationReport ExecuteIntegration(const IntegrationOptions& options) {
  IntegrationReport report;
  auto plan = PlanIntegration(options);
  if (!plan.is_supported) {
    report.success = false;
    report.error_message = plan.explanation;
    return report;
  }

  if (plan.detected_build_system == "UnrealBuildTool (UBT)") {
    return ExecuteUnrealIntegration(options);
  }

  // Validate identifiers
  if (!IsValidIdentifier(options.product_id)) {
    report.success = false;
    report.error_message = "Invalid product identifier: '" + options.product_id + "'. Must match ^[A-Za-z0-9_.-]+$ and be <= 128 characters.";
    return report;
  }
  if (!IsValidIdentifier(options.release_version)) {
    report.success = false;
    report.error_message = "Invalid release version: '" + options.release_version + "'. Must match ^[A-Za-z0-9_.-]+$ and be <= 128 characters.";
    return report;
  }

  fs::path proj_path = fs::canonical(options.target_project_path);

  // Discover and validate target
  fs::path cmake_file = proj_path / "CMakeLists.txt";
  auto discovered_targets = DiscoverCMakeExecutableTargets(cmake_file);
  std::string target_name;

  if (!options.target_name.empty()) {
    if (std::find(discovered_targets.begin(), discovered_targets.end(), options.target_name) == discovered_targets.end()) {
      report.success = false;
      report.error_message = "Specified target '" + options.target_name + "' was not found in CMakeLists.txt.";
      return report;
    }
    target_name = options.target_name;
  } else {
    if (discovered_targets.size() == 1) {
      target_name = discovered_targets[0];
    } else if (discovered_targets.size() > 1) {
      std::string t_list;
      for (std::size_t i = 0; i < discovered_targets.size(); ++i) {
        if (i > 0) t_list += ", ";
        t_list += discovered_targets[i];
      }
      report.success = false;
      report.error_message = "Multiple executable targets detected in CMakeLists.txt: [" + t_list + "]. Please specify the target to protect using --target <name>.";
      return report;
    } else {
      report.success = false;
      report.error_message = "No executable target found in CMakeLists.txt.";
      return report;
    }
  }
  report.target_name = target_name;

  // If dry-run requested, report planned changes and exit
  if (options.dry_run) {
    report.success = true;
    report.state = IntegrationState::kPlanned;
    report.modified_files = plan.files_to_modify;
    report.generated_files = plan.files_to_create;
    report.warnings = plan.warnings;
    if (!options.report_json_path.empty()) {
      WriteTextFile(options.report_json_path, report.ToJson());
    }
    return report;
  }

  auto now = std::chrono::system_clock::now().time_since_epoch();
  auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(now).count();

  // 1. Transactional Backup Directory (Outside project by default)
  fs::path backup_dir;
  if (!options.backup_dir.empty()) {
    backup_dir = fs::path(options.backup_dir);
    if (IsPathWithin(backup_dir, proj_path)) {
      report.success = false;
      report.state = IntegrationState::kFailed;
      report.error_message = "Security policy violation: --backup-dir must point to a location outside the client project.";
      return report;
    }
  } else {
    backup_dir = fs::temp_directory_path() / ("rtprotect_backup_" + std::to_string(timestamp) + "_" + GenerateRandomHex(8));
  }

  std::error_code ec;
  fs::create_directories(backup_dir, ec);
  if (ec) {
    report.success = false;
    report.state = IntegrationState::kFailed;
    report.error_message = "Failed to create backup directory: " + backup_dir.string();
    return report;
  }
  report.backup_path = backup_dir.string();

  // 2. Cryptographic Key Handling (CRITICAL 1 REMEDIATION)
  // Production security: Private keys are NEVER placed in the client project or backup directory.
  // Enforces strict role separation across THREE distinct keys:
  // 1. manifest.pub (Release resource integrity and anti-rollback)
  // 2. license.pub  (Customer entitlement, edition, and capabilities)
  // 3. activation.pub (Online Activation Authority token verification)
  integrity::Ed25519PublicKey manifest_pubkey{};
  integrity::Ed25519PublicKey license_pubkey{};
  integrity::Ed25519PublicKey activation_pubkey{};
  integrity::Ed25519PublicKey countermeasure_pubkey{};
  std::optional<integrity::Ed25519PrivateKey> manifest_privkey;
  std::optional<integrity::Ed25519PrivateKey> license_privkey;
  std::optional<integrity::Ed25519PrivateKey> activation_privkey;
  std::optional<integrity::Ed25519PrivateKey> countermeasure_privkey;
  bool has_manifest_privkey = false;
  bool has_license_privkey = false;
  bool has_activation_privkey = false;
  bool has_countermeasure_privkey = false;
  (void)has_activation_privkey;
  (void)has_countermeasure_privkey;

  if (options.use_dev_keys) {
    // Development-only testing workflow
    fs::path dev_keys_dir;
    if (!options.dev_keys_dir.empty()) {
      dev_keys_dir = fs::path(options.dev_keys_dir);
      if (IsPathWithin(dev_keys_dir, proj_path) || IsPathWithin(dev_keys_dir, backup_dir)) {
        report.success = false;
        report.state = IntegrationState::kFailed;
        report.error_message = "Security policy violation: --dev-keys-dir must point to a location outside the client project and backup directory.";
        return report;
      }
    } else {
      // Guaranteed outside client project: system temp directory with collision-resistant suffix
      dev_keys_dir = fs::temp_directory_path() / ("rtprotect_dev_keys_" + std::to_string(timestamp) + "_" + GenerateRandomHex(8));
    }

    fs::create_directories(dev_keys_dir, ec);
    if (ec) {
      report.success = false;
      report.state = IntegrationState::kFailed;
      report.error_message = "Failed to create dev_keys directory: " + dev_keys_dir.string();
      return report;
    }

    auto man_kp = integrity::GenerateEd25519KeyPair();
    auto lic_kp = integrity::GenerateEd25519KeyPair();
    auto act_kp = integrity::GenerateEd25519KeyPair();
    auto cm_kp = integrity::GenerateEd25519KeyPair();
    if (!man_kp.has_value() || !lic_kp.has_value() || !act_kp.has_value() || !cm_kp.has_value()) {
      report.success = false;
      report.state = IntegrationState::kFailed;
      report.error_message = "Failed to generate ephemeral development keypairs.";
      return report;
    }

    manifest_pubkey = man_kp->public_key;
    license_pubkey = lic_kp->public_key;
    activation_pubkey = act_kp->public_key;
    countermeasure_pubkey = cm_kp->public_key;

    fs::path dev_man_priv = dev_keys_dir / "manifest.priv";
    fs::path dev_lic_priv = dev_keys_dir / "license.priv";
    fs::path dev_act_priv = dev_keys_dir / "activation.priv";
    fs::path dev_cm_priv = dev_keys_dir / "countermeasure.priv";
    if (!WriteSecretFile(dev_man_priv.string(), man_kp->private_key.data(), man_kp->private_key.size()) ||
        !WriteSecretFile(dev_lic_priv.string(), lic_kp->private_key.data(), lic_kp->private_key.size()) ||
        !WriteSecretFile(dev_act_priv.string(), act_kp->private_key.data(), act_kp->private_key.size()) ||
        !WriteSecretFile(dev_cm_priv.string(), cm_kp->private_key.data(), cm_kp->private_key.size())) {
      report.success = false;
      report.state = IntegrationState::kFailed;
      report.error_message = "Failed to write development private keys to secure storage";
      return report;
    }

    manifest_privkey = std::move(man_kp->private_key);
    license_privkey = std::move(lic_kp->private_key);
    activation_privkey = std::move(act_kp->private_key);
    countermeasure_privkey = std::move(cm_kp->private_key);
    has_manifest_privkey = true;
    has_license_privkey = true;
    has_activation_privkey = true;
    has_countermeasure_privkey = true;

    report.private_key_file = dev_man_priv.string();
    report.warnings.push_back("Development test keys generated outside project at: " + dev_keys_dir.string() + " (Not for production distribution)");
  } else {
    // Production integration workflow: public keys REQUIRED
    if (options.manifest_pubkey_path.empty() || options.license_pubkey_path.empty()) {
      report.success = false;
      report.state = IntegrationState::kFailed;
      report.error_message = "Production integration requires pre-provisioned public verification keys (--manifest-pubkey and --license-pubkey). Private signing keys must be retained exclusively on vendor signing infrastructure. For isolated development/testing, explicitly supply --dev-keys.";
      return report;
    }

    auto man_bytes = ReadFile(options.manifest_pubkey_path);
    if (!man_bytes.has_value() || man_bytes->size() != integrity::kEd25519PublicKeyLen) {
      report.success = false;
      report.state = IntegrationState::kFailed;
      report.error_message = "Invalid or unreadable manifest public key file: " + options.manifest_pubkey_path;
      return report;
    }
    std::memcpy(manifest_pubkey.data(), man_bytes->data(), integrity::kEd25519PublicKeyLen);

    auto lic_bytes = ReadFile(options.license_pubkey_path);
    if (!lic_bytes.has_value() || lic_bytes->size() != integrity::kEd25519PublicKeyLen) {
      report.success = false;
      report.state = IntegrationState::kFailed;
      report.error_message = "Invalid or unreadable license public key file: " + options.license_pubkey_path;
      return report;
    }
    std::memcpy(license_pubkey.data(), lic_bytes->data(), integrity::kEd25519PublicKeyLen);

    if (!options.activation_pubkey_path.empty()) {
      auto act_bytes = ReadFile(options.activation_pubkey_path);
      if (!act_bytes.has_value() || act_bytes->size() != integrity::kEd25519PublicKeyLen) {
        report.success = false;
        report.state = IntegrationState::kFailed;
        report.error_message = "Invalid or unreadable activation public key file: " + options.activation_pubkey_path;
        return report;
      }
      std::memcpy(activation_pubkey.data(), act_bytes->data(), integrity::kEd25519PublicKeyLen);
    } else {
      if (!options.use_dev_keys) {
        report.success = false;
        report.state = IntegrationState::kFailed;
        report.error_message = "Production mode requires --activation-pubkey pointing to the vendor activation server public key";
        return report;
      }
      auto act_kp = integrity::GenerateEd25519KeyPair();
      if (act_kp.has_value()) {
        activation_pubkey = act_kp->public_key;
      }
    }

    if (!options.countermeasure_pubkey_path.empty()) {
      auto cm_bytes = ReadFile(options.countermeasure_pubkey_path);
      if (!cm_bytes.has_value() || cm_bytes->size() != integrity::kEd25519PublicKeyLen) {
        report.success = false;
        report.state = IntegrationState::kFailed;
        report.error_message = "Invalid or unreadable countermeasure public key file: " + options.countermeasure_pubkey_path;
        return report;
      }
      std::memcpy(countermeasure_pubkey.data(), cm_bytes->data(), integrity::kEd25519PublicKeyLen);
    } else {
      countermeasure_pubkey = activation_pubkey;
    }

    if (!options.use_dev_keys && (!options.sign_manifest_key_path.empty() || !options.sign_license_key_path.empty() || !options.sign_countermeasure_key_path.empty())) {
      if (options.run_build) {
        report.success = false;
        report.state = IntegrationState::kFailed;
        report.error_message =
            "Security Policy Violation: Passing vendor private signing keys to 'integrate' with customer build execution enabled is prohibited in production mode. "
            "Integrate and build using public verification keys, then sign artifacts using 'sign-release' in an isolated signing environment.";
        return report;
      }
      report.warnings.push_back(
          "Vendor private signing keys were supplied to build integration. For production environments, "
          "use public keys during build and invoke 'sign-release' on an isolated signing machine.");
    }

    // Optional signing keys for authorized build machine
    if (!options.sign_manifest_key_path.empty()) {
      auto m_priv = ReadFile(options.sign_manifest_key_path);
      if (m_priv.has_value() && m_priv->size() == integrity::kEd25519PrivateKeyLen) {
        manifest_privkey = integrity::Ed25519PrivateKey::FromBytes(m_priv->data(), m_priv->size());
        if (manifest_privkey.has_value()) {
          has_manifest_privkey = true;
        }
      }
    }
    if (!options.sign_license_key_path.empty()) {
      auto l_priv = ReadFile(options.sign_license_key_path);
      if (l_priv.has_value() && l_priv->size() == integrity::kEd25519PrivateKeyLen) {
        license_privkey = integrity::Ed25519PrivateKey::FromBytes(l_priv->data(), l_priv->size());
        if (license_privkey.has_value()) {
          has_license_privkey = true;
        }
      }
    }
    if (!options.sign_activation_key_path.empty()) {
      auto a_priv = ReadFile(options.sign_activation_key_path);
      if (a_priv.has_value() && a_priv->size() == integrity::kEd25519PrivateKeyLen) {
        activation_privkey = integrity::Ed25519PrivateKey::FromBytes(a_priv->data(), a_priv->size());
        if (activation_privkey.has_value()) {
          has_activation_privkey = true;
        }
      }
    }
  }

  // 3. Track File Operations and Back Up Pre-existing Files Safely
  std::vector<std::string> backed_up_relative;
  std::vector<std::string> planned_created;

  auto backup_file = [&](const fs::path& target) -> bool {
    if (fs::exists(target)) {
      auto rel = fs::relative(target, proj_path);
      auto dest = backup_dir / rel;
      fs::create_directories(dest.parent_path(), ec);
      if (ec) return false;
      fs::copy_file(target, dest, fs::copy_options::overwrite_existing, ec);
      if (ec) return false;
      backed_up_relative.push_back(rel.string());
    } else {
      auto rel = fs::relative(target, proj_path);
      planned_created.push_back(rel.string());
    }
    return true;
  };

  for (const auto& f_str : plan.files_to_modify) {
    if (!backup_file(fs::path(f_str))) {
      report.success = false;
      report.error_message = "Backup copy failed for modified file: " + f_str;
      return report;
    }
  }
  for (const auto& f_str : plan.files_to_create) {
    if (!backup_file(fs::path(f_str))) {
      report.success = false;
      report.error_message = "Backup copy failed for target file: " + f_str;
      return report;
    }
  }

  // Write Transactional Journal BEFORE performing file modifications
  {
    std::ostringstream jss;
    jss << "{\n";
    jss << "  \"timestamp\": " << timestamp << ",\n";
    jss << "  \"target_project\": \"" << EscapeJson(proj_path.string()) << "\",\n";
    jss << "  \"created_files\": [\n";
    for (std::size_t i = 0; i < planned_created.size(); ++i) {
      jss << "    \"" << EscapeJson(planned_created[i]) << "\"" << (i + 1 < planned_created.size() ? "," : "") << "\n";
    }
    jss << "  ],\n";
    jss << "  \"backed_up_files\": [\n";
    for (std::size_t i = 0; i < backed_up_relative.size(); ++i) {
      jss << "    \"" << EscapeJson(backed_up_relative[i]) << "\"" << (i + 1 < backed_up_relative.size() ? "," : "") << "\n";
    }
    jss << "  ]\n";
    jss << "}\n";
    if (!WriteTextFile((backup_dir / "integration_journal.json").string(), jss.str())) {
      report.success = false;
      report.state = IntegrationState::kFailed;
      report.error_message = "Failed to write integration journal to backup directory";
      return report;
    }
  }

  // 4. Write Public Keys to Project
  fs::path manifest_pub_path = proj_path / "release.pub";
  fs::path license_pub_path = proj_path / "license.pub";
  fs::path activation_pub_path = proj_path / "activation.pub";
  fs::path countermeasure_pub_path = proj_path / "countermeasure.pub";
  if (!WriteFile(manifest_pub_path.string(), manifest_pubkey.data(), manifest_pubkey.size()) ||
      !WriteFile(license_pub_path.string(), license_pubkey.data(), license_pubkey.size()) ||
      !WriteFile(activation_pub_path.string(), activation_pubkey.data(), activation_pubkey.size()) ||
      !WriteFile(countermeasure_pub_path.string(), countermeasure_pubkey.data(), countermeasure_pubkey.size())) {
    report.success = false;
    report.state = IntegrationState::kFailed;
    report.error_message = "Failed to write public verification key files into project directory";
    return report;
  }

  report.public_key_file = manifest_pub_path.string();
  report.manifest_public_key_file = manifest_pub_path.string();
  report.license_public_key_file = license_pub_path.string();
  report.activation_public_key_file = activation_pub_path.string();
  report.countermeasure_public_key_file = countermeasure_pub_path.string();
  report.generated_files.push_back(manifest_pub_path.string());
  report.generated_files.push_back(license_pub_path.string());
  report.generated_files.push_back(activation_pub_path.string());
  report.generated_files.push_back(countermeasure_pub_path.string());

  std::string expected_exe_name = target_name;
#if defined(_WIN32)
  expected_exe_name += ".exe";
#endif

  // 5. Generate rtprotect_config.h
  std::uint32_t opcode_seed = 0;
  if (RAND_bytes(reinterpret_cast<unsigned char*>(&opcode_seed), sizeof(opcode_seed)) != 1 || opcode_seed == 0) {
    report.success = false;
    report.state = IntegrationState::kFailed;
    report.error_message = "Cryptographic RNG failure (RAND_bytes) while generating VM opcode seed";
    return report;
  }
  report.opcode_seed = opcode_seed;

  std::string dev_lic_id = "dev-license";
  if (options.use_dev_keys) {
    dev_lic_id = "lic-dev-" + std::to_string(timestamp);
  } else if (!options.license_file_path.empty()) {
    auto lic_data = ReadFile(options.license_file_path);
    if (lic_data.has_value()) {
      auto lic_opt = licensing::DeserializeLicense(lic_data->data(), lic_data->size());
      if (lic_opt.has_value() && !lic_opt->license_id.empty()) {
        dev_lic_id = lic_opt->license_id;
      }
    }
  }

  std::array<std::uint8_t, 32> vm_root{};
  bool vm_root_set = false;

  // 1. Dedicated content key path (Cryptographic key separation from signing keys)
  if (!options.content_key_path.empty()) {
    auto file_bytes = ReadFile(options.content_key_path);
    if (!file_bytes.has_value() || file_bytes->size() < 32) {
      report.success = false;
      report.state = IntegrationState::kFailed;
      report.error_message = "Failed to load dedicated content key from " + options.content_key_path;
      return report;
    }
    std::memcpy(vm_root.data(), file_bytes->data(), 32);
    vm_root_set = true;
  }

  // 2. Explicit VM root provided via options (file or hex string)
  if (!vm_root_set && !options.vm_root_file.empty()) {
    auto file_bytes = ReadFile(options.vm_root_file);
    if (file_bytes.has_value() && file_bytes->size() >= 32) {
      std::memcpy(vm_root.data(), file_bytes->data(), 32);
      vm_root_set = true;
    }
  } else if (!vm_root_set && !options.vm_root_hex.empty() && options.vm_root_hex.size() == 64) {
    for (std::size_t i = 0; i < 32; ++i) {
      unsigned int byte_val = 0;
      std::sscanf(options.vm_root_hex.c_str() + i * 2, "%02x", &byte_val);
      vm_root[i] = static_cast<std::uint8_t>(byte_val);
    }
    vm_root_set = true;
  }

  // 3. Online Activation Authority provisioning at build time (if server URL is configured)
  if (!vm_root_set && !options.activation_server_url.empty()) {
    std::string act_err;
    auto srv_token = rtprotect::licensing::RequestOnlineActivation(
        options.activation_server_url, dev_lic_id, options.product_id, activation_pubkey, &act_err, options.activation_credential, 0, &countermeasure_pubkey);
    if (srv_token.has_value()) {
      vm_root = srv_token->vm_root;
      vm_root_set = true;
      rtprotect::licensing::SaveActivationToken(options.product_id, *srv_token);
    }
  }

  // 4. In development mode with dev keys: mint a signed development ActivationToken and save it locally
  if (!vm_root_set && options.use_dev_keys) {
    if (has_activation_privkey && activation_privkey.has_value()) {
      rtprotect::licensing::ActivationToken dev_token;
      dev_token.schema_version = rtprotect::licensing::kActivationSchemaVersion;
      dev_token.license_id = dev_lic_id;
      dev_token.device_fingerprint_hash = rtprotect::licensing::GetLocalHardwareId();
      auto now_sec = static_cast<std::uint64_t>(std::time(nullptr));
      dev_token.issued_at = now_sec;
      dev_token.expires_at = now_sec + (14 * 86400); // 14-day dev token
      dev_token.grace_expires_at = dev_token.expires_at + (3 * 86400); // 3-day grace
      dev_token.sequence_number = 1;
      if (RAND_bytes(dev_token.server_nonce.data(), static_cast<int>(dev_token.server_nonce.size())) != 1 ||
          RAND_bytes(dev_token.vm_root.data(), static_cast<int>(dev_token.vm_root.size())) != 1) {
        report.success = false;
        report.state = IntegrationState::kFailed;
        report.error_message = "Cryptographic RNG failure (RAND_bytes) while generating dev token keys";
        return report;
      }
      if (!rtprotect::licensing::SignActivationToken(dev_token, *activation_privkey)) {
        report.success = false;
        report.state = IntegrationState::kFailed;
        report.error_message = "Failed to sign dev activation token";
        return report;
      }
      vm_root = dev_token.vm_root;
      vm_root_set = true;
      rtprotect::licensing::SaveActivationToken(options.product_id, dev_token);
    }
  }

  // 5. In production mode: enforce cryptographic key separation
  if (!vm_root_set) {
    report.success = false;
    report.state = IntegrationState::kFailed;
    report.error_message = "Production release requires dedicated content protection key separation. Please supply --content-key, --vm-root-file, --vm-root-hex, or --activation-server-url.";
    return report;
  }

  fs::path config_header_path = proj_path / "rtprotect_config.h";
  {
    std::ostringstream ss;
    ss << "// Generated by RTProtect Integration Engine\n";
    ss << "#pragma once\n\n";
    ss << "#include <cstdint>\n";
    ss << "#include <array>\n";
    ss << "#include <string>\n";
    ss << "#include <optional>\n";
    ss << "#include <vector>\n";
    ss << "#include <cstring>\n";
    ss << "#include \"crypto/aead.h\"\n";
    ss << "#include \"crypto/kdf.h\"\n";
    ss << "#include \"crypto/secure_buffer.h\"\n\n";
    ss << "namespace rtprotect_client {\n\n";
    ss << "inline constexpr const char* kProductId = \"" << EscapeCxxStringLiteral(options.product_id) << "\";\n";
    ss << "inline constexpr const char* kReleaseVersion = \"" << EscapeCxxStringLiteral(options.release_version) << "\";\n";
    ss << "inline constexpr const char* kProtectionProfile = \"" << EscapeCxxStringLiteral(ToString(options.profile)) << "\";\n";
    ss << "inline constexpr const char* kExpectedExecutableName = \"" << EscapeCxxStringLiteral(expected_exe_name) << "\";\n";
    ss << "inline constexpr const char* kActivationServerUrl = \"" << EscapeCxxStringLiteral(options.activation_server_url) << "\";\n";
    ss << "inline constexpr bool kAllowDevTokenFallback = " << (options.use_dev_keys ? "true" : "false") << ";\n";
    ss << "inline constexpr std::uint64_t kRequiredCapabilities = 0x01; // kCapCoreExecution\n";
    ss << "inline constexpr std::uint64_t kMinimumReleaseSequence = " << options.minimum_release_sequence << "ULL;\n\n";

    char seed_buf[32];
    std::snprintf(seed_buf, sizeof(seed_buf), "0x%08XU", opcode_seed);
    ss << "// Per-build randomized opcode map seed (Phase 3 bytecode VM hardening)\n";
    ss << "inline constexpr std::uint32_t kBuildOpcodeSeed = " << seed_buf << ";\n\n";

    auto dump_key = [&](const char* name, const integrity::Ed25519PublicKey& k) {
      ss << "// Embedded " << name << " Verification Key\n";
      ss << "inline constexpr std::array<std::uint8_t, 32> " << name << " = {\n  ";
      for (std::size_t i = 0; i < k.size(); ++i) {
        char h[8];
        std::snprintf(h, sizeof(h), "0x%02X", k[i]);
        ss << h;
        if (i + 1 < k.size()) ss << ", ";
        if ((i + 1) % 8 == 0 && i + 1 < k.size()) ss << "\n  ";
      }
      ss << "\n};\n\n";
    };

    dump_key("kManifestPublicKey", manifest_pubkey);
    dump_key("kLicensePublicKey", license_pubkey);
    dump_key("kActivationPublicKey", activation_pubkey);
    dump_key("kCountermeasurePublicKey", countermeasure_pubkey);
    dump_key("kPublicKey", manifest_pubkey);

    ss << "bool VerifyClientIntegrityAndLicense(const char* activation_credential = nullptr);\n";
    ss << "void SetClientActivationCredential(const char* credential);\n";
    ss << "std::string GetLicenseEdition();\n";
    ss << "std::uint64_t GetLicenseCapabilities();\n";
    ss << "bool HasCapability(std::uint64_t cap);\n";
    ss << "void SetRuntimeManifestRoot(const std::uint8_t* root_hash, std::size_t len);\n";
    ss << "std::optional<rtprotect::crypto::Aes256Key> GetFunctionMasterKey(const std::uint8_t* salt, std::size_t salt_len);\n\n";

    ss << "}  // namespace rtprotect_client\n\n";

    ss << "#include \"bytecode_vm/opcode_map.h\"\n";
    ss << "namespace rtprotect_client {\n";
    ss << "inline const rtprotect::vm::OpcodeMap& GetBuildOpcodeMap() {\n";
    ss << "  static const rtprotect::vm::OpcodeMap s_map = rtprotect::vm::OpcodeMap::FromSeed(kBuildOpcodeSeed);\n";
    ss << "  return s_map;\n";
    ss << "}\n";
    ss << "}  // namespace rtprotect_client\n\n";
    ss << "#ifndef RTPROTECT_VIRTUALIZE\n#define RTPROTECT_VIRTUALIZE\n#endif\n";
    ss << "#ifndef RTPROTECT_STRING\n#define RTPROTECT_STRING(s) s\n#endif\n\n";

    if (!WriteTextFile(config_header_path.string(), ss.str())) {
      report.success = false;
      report.state = IntegrationState::kFailed;
      report.error_message = "Failed to write rtprotect_config.h";
      return report;
    }
    report.generated_files.push_back(config_header_path.string());
  }

  // 6. Generate rtprotect_runtime_glue.cpp (CRITICAL 2 REMEDIATION: FAIL-CLOSED RUNTIME INTEGRITY)
  fs::path glue_path = proj_path / "rtprotect_runtime_glue.cpp";
  {
    std::ostringstream ss;
    ss << "// Generated by RTProtect Integration Engine\n";
    ss << "#include \"rtprotect_config.h\"\n";
    ss << "#include \"licensing/license.h\"\n";
    ss << "#include \"licensing/license_verifier.h\"\n";
    ss << "#include \"licensing/activation.h\"\n";
    ss << "#include \"licensing/activation_client.h\"\n";
    ss << "#include \"licensing/countermeasure_config.h\"\n";
    ss << "#include \"licensing/trusted_time.h\"\n";
    ss << "#include \"licensing/secure_storage.h\"\n";
    ss << "#include \"licensing/hardware_id.h\"\n";
    ss << "#include \"integrity/manifest.h\"\n";
    ss << "#include \"integrity/verifier.h\"\n";
    ss << "#include \"integrity/sha256.h\"\n";
    ss << "#include \"antitamper/risk_policy.h\"\n";
    ss << "#include \"antitamper/anti_debug.h\"\n";
    ss << "#include \"obfuscation/control_flow.h\"\n";
    ss << "#include \"tooling/file_io.h\"\n\n";
    ss << "#include <ctime>\n";
    ss << "#include <cstdio>\n";
    ss << "#include <cstdlib>\n";
    ss << "#include <cstring>\n";
    ss << "#include <filesystem>\n";
    ss << "#include <fstream>\n";
    ss << "#include <string>\n";
    ss << "#include <vector>\n";
    ss << "#include <thread>\n";
    ss << "#include <atomic>\n\n";

    ss << "#include <windows.h>\n\n";

    ss << "namespace rtprotect_client {\n\n";
    ss << "static bool s_license_validated = false;\n";
    ss << "static rtprotect::licensing::License s_validated_license{};\n";
    ss << "static std::array<std::uint8_t, 32> s_runtime_manifest_vm_root{};\n";
    ss << "static bool s_runtime_root_initialized = false;\n";
    ss << "static std::string s_client_activation_credential;\n";
    ss << "static rtprotect::licensing::ActivationToken s_active_activation_token{};\n";
    ss << "static std::atomic<std::uint64_t> s_last_revalidation_time{0};\n";
    ss << "static std::atomic<bool> s_stop_revalidation{false};\n\n";

    ss << "static bool RevalidateLicenseAndTime() {\n";
    ss << "  if (!s_license_validated || !s_runtime_root_initialized) return false;\n";
    ss << "  auto trusted_time = rtprotect::licensing::TrustedTime::GetTrustedTime(kProductId);\n";
    ss << "  if (!trusted_time.has_value()) {\n";
    ss << "    s_runtime_root_initialized = false;\n";
    ss << "    std::fill(s_runtime_manifest_vm_root.begin(), s_runtime_manifest_vm_root.end(), 0);\n";
    ss << "    return false;\n";
    ss << "  }\n";
    ss << "  auto val_res = rtprotect::licensing::TrustedTime::ValidateToken(kProductId, s_active_activation_token, /*allow_grace=*/true);\n";
    ss << "  if (val_res != rtprotect::licensing::TimeValidationResult::kValid &&\n";
    ss << "      val_res != rtprotect::licensing::TimeValidationResult::kInGracePeriod) {\n";
    ss << "    s_runtime_root_initialized = false;\n";
    ss << "    std::fill(s_runtime_manifest_vm_root.begin(), s_runtime_manifest_vm_root.end(), 0);\n";
    ss << "    return false;\n";
    ss << "  }\n";
    ss << "  return true;\n";
    ss << "}\n\n";

    ss << "static void StartPeriodicRevalidation() {\n";
    ss << "  static std::atomic<bool> s_watchdog_started{false};\n";
    ss << "  if (s_watchdog_started.exchange(true)) return;\n";
    ss << "  try {\n";
    ss << "    std::thread t([]() {\n";
    ss << "      while (!s_stop_revalidation.load(std::memory_order_relaxed)) {\n";
    ss << "        for (int i = 0; i < 30 && !s_stop_revalidation.load(std::memory_order_relaxed); ++i) {\n";
    ss << "          std::this_thread::sleep_for(std::chrono::seconds(1));\n";
    ss << "        }\n";
    ss << "        if (s_stop_revalidation.load(std::memory_order_relaxed)) break;\n";
    ss << "        if (!RevalidateLicenseAndTime()) {\n";
    ss << "          std::fprintf(stderr, \"[RTProtect] Fatal: Runtime license or clock freeze violation detected during execution. Terminating.\\n\");\n";
    ss << "          std::exit(1);\n";
    ss << "        }\n";
    ss << "      }\n";
    ss << "    });\n";
    ss << "    t.detach();\n";
    ss << "  } catch (...) {}\n";
    ss << "}\n\n";

    ss << "void SetClientActivationCredential(const char* credential) {\n";
    ss << "  if (credential) {\n";
    ss << "    s_client_activation_credential = credential;\n";
    ss << "  } else {\n";
    ss << "    s_client_activation_credential.clear();\n";
    ss << "  }\n";
    ss << "}\n\n";

    ss << "void SetRuntimeManifestRoot(const std::uint8_t* root_hash, std::size_t len) {\n";
    ss << "  if (root_hash && len == 32) {\n";
    ss << "    std::memcpy(s_runtime_manifest_vm_root.data(), root_hash, 32);\n";
    ss << "    s_runtime_root_initialized = true;\n";
    ss << "  }\n";
    ss << "}\n\n";

    ss << "std::optional<rtprotect::crypto::Aes256Key> GetFunctionMasterKey(const std::uint8_t* salt, std::size_t salt_len) {\n";
    ss << "  using namespace rtprotect::obfuscation;\n";
    ss << "  if (!s_runtime_root_initialized) return std::nullopt;\n";
    ss << "  std::uint64_t now_check = static_cast<std::uint64_t>(std::time(nullptr));\n";
    ss << "  std::uint64_t last_check = s_last_revalidation_time.load(std::memory_order_relaxed);\n";
    ss << "  if (now_check >= last_check + 10) {\n";
    ss << "    if (s_last_revalidation_time.compare_exchange_strong(last_check, now_check)) {\n";
    ss << "      if (!RevalidateLicenseAndTime()) return std::nullopt;\n";
    ss << "    }\n";
    ss << "  }\n";
    ss << "  std::optional<rtprotect::crypto::Aes256Key> derived_key = std::nullopt;\n";
    ss << "  rtprotect::crypto::SecureBuffer raw_seed(32);\n";
    ss << "  std::vector<std::uint8_t> hkdf_salt;\n";
    ss << "  std::string info;\n\n";
    ss << "  RTPROTECT_FLATTEN_BEGIN(st, 0x10)\n";
    ss << "    RTPROTECT_FLATTEN_CASE(0x10) {\n";
    ss << "      if (OpaquePredicateTrue(static_cast<std::uint64_t>(salt_len) ^ 0x1337ULL)) {\n";
    ss << "        RTPROTECT_FLATTEN_TRANSITION(st, 0x20);\n";
    ss << "      } else {\n";
    ss << "        RTPROTECT_FLATTEN_EXIT();\n";
    ss << "      }\n";
    ss << "    }\n";
    ss << "    RTPROTECT_FLATTEN_CASE(0x20) {\n";
    ss << "      std::memcpy(raw_seed.data(), s_runtime_manifest_vm_root.data(), 32);\n";
    ss << "      hkdf_salt.assign(kManifestPublicKey.begin(), kManifestPublicKey.end());\n";
    ss << "      if (salt && salt_len > 0) {\n";
    ss << "        hkdf_salt.insert(hkdf_salt.end(), salt, salt + salt_len);\n";
    ss << "      }\n";
    ss << "      info = std::string(\"rtprotect/virtualize/\") + kProductId;\n";
    ss << "      RTPROTECT_FLATTEN_TRANSITION(st, 0x30);\n";
    ss << "    }\n";
    ss << "    RTPROTECT_FLATTEN_CASE(0x30) {\n";
    ss << "      auto derived = rtprotect::crypto::Hkdf::DeriveKey(raw_seed, hkdf_salt, info, rtprotect::crypto::kAes256KeyLen);\n";
    ss << "      if (derived.has_value()) {\n";
    ss << "        derived_key = rtprotect::crypto::Aes256Key::FromBytes(derived->data(), derived->size());\n";
    ss << "      }\n";
    ss << "      RTPROTECT_FLATTEN_EXIT();\n";
    ss << "    }\n";
    ss << "  RTPROTECT_FLATTEN_END();\n\n";
    ss << "  return derived_key;\n";
    ss << "}\n\n";

    ss << "namespace {\n\n";
    ss << "std::string GetCurrentExecutablePath() {\n";
    ss << "  DWORD size = 512;\n";
    ss << "  while (size <= 65536) {\n";
    ss << "    std::vector<char> buf(size);\n";
    ss << "    DWORD ret = ::GetModuleFileNameA(NULL, buf.data(), size);\n";
    ss << "    if (ret == 0) return \"\";\n";
    ss << "    if (ret < size - 1) return std::string(buf.data(), ret);\n";
    ss << "    size *= 2;\n";
    ss << "  }\n";
    ss << "  return \"\";\n";
    ss << "}\n\n";

    // HIGH 9 REMEDIATION: Authoritative auxiliary file location ONLY next to binary
    ss << "std::optional<std::vector<std::uint8_t>> ReadAuxiliaryFile(const std::string& name) {\n";
    ss << "  namespace fs = std::filesystem;\n";
    ss << "  std::string exe = GetCurrentExecutablePath();\n";
    ss << "  if (exe.empty()) return std::nullopt;\n";
    ss << "  auto auth_path = fs::path(exe).parent_path() / name;\n";
    ss << "  if (fs::exists(auth_path)) {\n";
    ss << "    return rtprotect::tooling::ReadFile(auth_path.string());\n";
    ss << "  }\n";
    ss << "  return std::nullopt;\n";
    ss << "}\n\n";
    ss << "}  // namespace\n\n";

    ss << "bool VerifyClientIntegrityAndLicense(const char* activation_credential) {\n";
    ss << "  s_license_validated = false;\n";
    ss << "  s_validated_license = {};\n";
    ss << "  if (!kAllowDevTokenFallback) {\n";
    ss << "    rtprotect::licensing::SecureStorage::SetRequireDpapi(true);\n";
    ss << "  }\n";
    ss << "  // 0. Register countermeasure update notification hook\n";
    ss << "  rtprotect::licensing::SetCountermeasureUpdateHook([](const rtprotect::licensing::CountermeasureConfig& cfg) {\n";
    ss << "    rtprotect::antitamper::ApplyCountermeasures(\n";
    ss << "        cfg.blacklisted_process_names,\n";
    ss << "        cfg.blacklisted_window_titles,\n";
    ss << "        cfg.risk_threshold_restrict,\n";
    ss << "        cfg.risk_threshold_terminate,\n";
    ss << "        cfg.expires_at,\n";
    ss << "        cfg.blacklisted_process_hashes,\n";
    ss << "        cfg.blacklisted_driver_hashes,\n";
    ss << "        cfg.enforce_hardware_breakpoints,\n";
    ss << "        cfg.enforce_timing_checks,\n";
    ss << "        cfg.enforce_memory_hooks,\n";
    ss << "        cfg.enforce_anti_dump);\n";
    ss << "  });\n\n";
    ss << "  // 0b. Load and apply any active unexpired countermeasure configuration from secure storage\n";
    ss << "  auto active_cm = rtprotect::licensing::LoadCountermeasureConfig(kProductId);\n";
    ss << "  if (active_cm.has_value() && rtprotect::licensing::VerifyCountermeasureConfigSignature(*active_cm, kCountermeasurePublicKey)) {\n";
    ss << "    rtprotect::antitamper::ApplyCountermeasures(\n";
    ss << "        active_cm->blacklisted_process_names,\n";
    ss << "        active_cm->blacklisted_window_titles,\n";
    ss << "        active_cm->risk_threshold_restrict,\n";
    ss << "        active_cm->risk_threshold_terminate,\n";
    ss << "        active_cm->expires_at,\n";
    ss << "        active_cm->blacklisted_process_hashes,\n";
    ss << "        active_cm->blacklisted_driver_hashes,\n";
    ss << "        active_cm->enforce_hardware_breakpoints,\n";
    ss << "        active_cm->enforce_timing_checks,\n";
    ss << "        active_cm->enforce_memory_hooks,\n";
    ss << "        active_cm->enforce_anti_dump);\n";
    ss << "  }\n\n";
    ss << "  // 1. Runtime environment risk assessment\n";
    ss << "  auto risk = rtprotect::antitamper::AssessEnvironmentRisk();\n";
    if (options.profile == ProtectionProfile::kMaximum) {
      ss << "  if (!rtprotect::antitamper::EnforceRiskPolicy(rtprotect::antitamper::RiskAction::kTerminate, risk)) return false;\n";
    } else if (options.profile == ProtectionProfile::kBalanced) {
      ss << "  if (!rtprotect::antitamper::EnforceRiskPolicy(rtprotect::antitamper::RiskAction::kRestrict, risk)) return false;\n";
    } else {
      ss << "  rtprotect::antitamper::EnforceRiskPolicy(rtprotect::antitamper::RiskAction::kReportOnly, risk);\n";
    }

    ss << "\n  // 2. Client license verification\n";
    ss << "  auto lic_data = ReadAuxiliaryFile(\"client.license\");\n";
    ss << "  if (!lic_data.has_value()) return false;\n";
    ss << "  rtprotect::licensing::LicenseVerificationContext ctx;\n";
    ss << "  ctx.current_time = static_cast<std::uint64_t>(std::time(nullptr));\n";
    ss << "  ctx.expected_product_id = kProductId;\n";
    ss << "  ctx.current_hardware_id = rtprotect::licensing::GetLocalHardwareId();\n";
    ss << "  ctx.reject_degraded_hardware = true; // Reject degraded hardware state\n";
    ss << "  rtprotect::licensing::License lic;\n";
    ss << "  auto lic_status = rtprotect::licensing::VerifyLicenseBytes(lic_data->data(), lic_data->size(), kLicensePublicKey, ctx, &lic);\n";
    ss << "  if (lic_status != rtprotect::licensing::LicenseStatus::kValid) return false;\n";
    ss << "  if (lic.product_id != kProductId) return false;\n";
    ss << "  if ((lic.capabilities & kRequiredCapabilities) != kRequiredCapabilities) return false;\n";

    ss << "\n  // 3. Manifest signature and anti-rollback verification\n";
    ss << "  auto man_bytes = ReadAuxiliaryFile(\"release.manifest\");\n";
    ss << "  auto sig_bytes = ReadAuxiliaryFile(\"release.sig\");\n";
    ss << "  if (!man_bytes.has_value() || !sig_bytes.has_value() || sig_bytes->size() != 64) return false;\n";
    ss << "  rtprotect::integrity::Ed25519Signature sig;\n";
    ss << "  std::memcpy(sig.data(), sig_bytes->data(), 64);\n";
    ss << "  if (!rtprotect::integrity::VerifyManifestSignature(*man_bytes, sig, kManifestPublicKey)) return false;\n";
    ss << "  auto manifest = rtprotect::integrity::DeserializeManifest(man_bytes->data(), man_bytes->size());\n";
    ss << "  if (!manifest.has_value() || manifest->release_sequence < kMinimumReleaseSequence) return false;\n";

    ss << "\n  // 4. Activation token retrieval and VM root derivation\n";
    ss << "  rtprotect::licensing::ActivationToken token;\n";
    ss << "  bool token_loaded = false;\n\n";
    ss << "  // 4a. Check OS secure storage (Windows DPAPI) with strict cryptographic signature verification\n";
    ss << "  auto cached_tok = rtprotect::licensing::LoadActivationToken(kProductId);\n";
    ss << "  if (cached_tok.has_value() && !cached_tok->license_id.empty() && cached_tok->license_id == lic.license_id) {\n";
    ss << "    bool sig_ok = rtprotect::licensing::VerifyActivationTokenSignature(*cached_tok, kActivationPublicKey);\n";
    ss << "    bool hw_ok = rtprotect::licensing::VerifyHardwareMatch(cached_tok->device_fingerprint_hash, ctx.current_hardware_id, 0.75);\n";
    ss << "    auto time_res = rtprotect::licensing::TrustedTime::ValidateToken(kProductId, *cached_tok, /*allow_grace=*/true);\n";
    ss << "    bool time_ok = (time_res == rtprotect::licensing::TimeValidationResult::kValid || time_res == rtprotect::licensing::TimeValidationResult::kInGracePeriod);\n";
    ss << "    if (sig_ok && hw_ok && time_ok) {\n";
    ss << "      token = *cached_tok;\n";
    ss << "      token_loaded = true;\n";
    ss << "      if (time_res == rtprotect::licensing::TimeValidationResult::kInGracePeriod) {\n";
    ss << "        std::fprintf(stderr, \"[RTProtect] Notice: License activation is currently in grace period.\\n\");\n";
    ss << "      }\n";
    ss << "    }\n";
    ss << "  }\n\n";
    ss << "  // 4b. Online Activation against server if uncached or expired\n";
    ss << "  if (!token_loaded && kActivationServerUrl[0] != '\\0') {\n";
    ss << "    const char* effective_cred = activation_credential;\n";
    ss << "    if (!effective_cred || effective_cred[0] == '\\0') {\n";
    ss << "      if (!s_client_activation_credential.empty()) {\n";
    ss << "        effective_cred = s_client_activation_credential.c_str();\n";
    ss << "      } else {\n";
    ss << "        const char* env_cred = std::getenv(\"RTPROTECT_ACTIVATION_CREDENTIAL\");\n";
    ss << "        if (env_cred && env_cred[0] != '\\0') {\n";
    ss << "          effective_cred = env_cred;\n";
    ss << "        }\n";
    ss << "      }\n";
    ss << "    }\n";
    ss << "    std::string act_err;\n";
    ss << "    auto online_token = rtprotect::licensing::RequestOnlineActivation(\n";
    ss << "        kActivationServerUrl, lic.license_id, kProductId, kActivationPublicKey, &act_err, effective_cred ? effective_cred : \"\", ctx.current_time, &kCountermeasurePublicKey);\n";
    ss << "    if (online_token.has_value()) {\n";
    ss << "      token = *online_token;\n";
    ss << "      rtprotect::licensing::SaveActivationToken(kProductId, token);\n";
    ss << "      token_loaded = true;\n";
    ss << "    }\n";
    ss << "  }\n\n";
    ss << "  if (!token_loaded) return false; // Activation required -> fail closed\n";
    ss << "  auto final_time = rtprotect::licensing::TrustedTime::ValidateToken(kProductId, token, /*allow_grace=*/true);\n";
    ss << "  if (final_time != rtprotect::licensing::TimeValidationResult::kValid && final_time != rtprotect::licensing::TimeValidationResult::kInGracePeriod) {\n";
    ss << "    return false;\n";
    ss << "  }\n";
    ss << "  SetRuntimeManifestRoot(token.vm_root.data(), 32);\n";
    ss << "  s_active_activation_token = token;\n";

    ss << "\n  // 5. Executable integrity verification (FAIL CLOSED)\n";
    ss << "  std::string exe_path = GetCurrentExecutablePath();\n";
    ss << "  if (exe_path.empty()) return false;\n";
    ss << "  std::uint64_t actual_size = 0;\n";
    ss << "  auto actual_hash = rtprotect::integrity::Sha256File(exe_path, &actual_size);\n";
    ss << "  if (!actual_hash.has_value()) return false;\n";
    ss << "  std::string exe_name = std::filesystem::path(exe_path).filename().string();\n";
    ss << "  auto res = manifest->Find(exe_name);\n";
    ss << "  if (!res) res = manifest->Find(kExpectedExecutableName);\n";
    ss << "  if (!res) return false; // Mandatory executable resource missing in manifest -> FAIL\n";
    ss << "  if (res->size != actual_size || res->sha256 != *actual_hash) return false;\n";

    ss << "\n  s_validated_license = lic;\n";
    ss << "  s_license_validated = true;\n";
    ss << "  StartPeriodicRevalidation();\n";
    ss << "  return true;\n";
    ss << "}\n\n";

    ss << "std::string GetLicenseEdition() {\n";
    ss << "  return s_license_validated ? s_validated_license.edition : \"\";\n";
    ss << "}\n";
    ss << "std::uint64_t GetLicenseCapabilities() {\n";
    ss << "  return s_license_validated ? s_validated_license.capabilities : 0;\n";
    ss << "}\n";
    ss << "bool HasCapability(std::uint64_t cap) {\n";
    ss << "  return s_license_validated && ((s_validated_license.capabilities & cap) == cap);\n";
    ss << "}\n\n";

    ss << "}  // namespace rtprotect_client\n\n";

    // Automatic pre-main() startup constructor hook (STRICT FAIL-CLOSED)
    ss << "static int InitializeRtProtectStartupHook() {\n";
    ss << "  static bool s_executed = false;\n";
    ss << "  if (s_executed) return 0;\n";
    ss << "  s_executed = true;\n";
    ss << "  const char* env_cred = std::getenv(\"RTPROTECT_ACTIVATION_CREDENTIAL\");\n";
    ss << "  if (!rtprotect_client::VerifyClientIntegrityAndLicense(env_cred)) {\n";
    ss << "    std::fprintf(stderr, \"[RTProtect] Fatal: Integrity or license verification failed. Terminating.\\n\");\n";
    ss << "    std::exit(1);\n";
    ss << "  }\n";
    ss << "  return 0;\n";
    ss << "}\n\n";

    ss << "#if defined(_MSC_VER)\n";
    ss << "#pragma section(\".CRT$XCU\", read)\n";
    ss << "extern \"C\" __declspec(allocate(\".CRT$XCU\")) int (*g_rtprotect_init_hook)() = InitializeRtProtectStartupHook;\n";
    ss << "#if defined(_WIN64)\n";
    ss << "#pragma comment(linker, \"/include:g_rtprotect_init_hook\")\n";
    ss << "#else\n";
    ss << "#pragma comment(linker, \"/include:_g_rtprotect_init_hook\")\n";
    ss << "#endif\n\n";
    ss << "namespace {\n";
    ss << "struct RtProtectStartupInitializer {\n";
    ss << "  RtProtectStartupInitializer() {\n";
    ss << "    InitializeRtProtectStartupHook();\n";
    ss << "  }\n";
    ss << "};\n";
    ss << "static const RtProtectStartupInitializer g_rtprotect_startup_obj;\n";
    ss << "}  // namespace\n";
    ss << "#else\n";
    ss << "__attribute__((constructor(101))) static void InitializeRtProtectStartupHookAttribute() {\n";
    ss << "  InitializeRtProtectStartupHook();\n";
    ss << "}\n";
    ss << "#endif\n";

    if (!WriteTextFile(glue_path.string(), ss.str())) {
      report.success = false;
      report.state = IntegrationState::kFailed;
      report.error_message = "Failed to write rtprotect_runtime_glue.cpp";
      return report;
    }
    report.generated_files.push_back(glue_path.string());
  }

  // 6a-2. Run AST Weak Entanglement Linter across detected sources
  for (const auto& src_file : plan.detected_sources) {
    auto lints = ClangAstScanner::CheckFunctionEntanglement(src_file);
    for (const auto& lint : lints) {
      report.warnings.push_back("Entanglement Lint [" + fs::path(lint.file_path).filename().string() + ":" +
                                std::to_string(lint.line_number) + "]: " + lint.warning_message);
    }
  }

  // 6a-3. Whole-Program Automated Candidate Selection (--auto-virtualize)
  if (options.auto_virtualize) {
    auto candidates = ClangAstScanner::AnalyzeProjectCandidates(plan.detected_sources, nullptr, options.virtualization_budget);
    std::unordered_map<std::string, std::vector<FunctionSuitabilityScore>> file_to_candidates;
    for (const auto& cand : candidates) {
      if (cand.is_eligible) {
        file_to_candidates[cand.file_path].push_back(cand);
      }
    }

    for (auto& [file_path, cands] : file_to_candidates) {
      auto file_content = ReadTextFile(file_path);
      if (!file_content.has_value()) {
        report.success = false;
        report.state = IntegrationState::kFailed;
        report.error_message = "Failed to read source file for auto-virtualization: " + file_path;
        return report;
      }

      // Sort candidates descending by start_offset so insertions don't invalidate subsequent offsets
      std::sort(cands.begin(), cands.end(), [](const FunctionSuitabilityScore& a, const FunctionSuitabilityScore& b) {
        return a.start_offset > b.start_offset;
      });

      bool file_modified = false;
      for (const auto& cand : cands) {
        if (cand.start_offset > file_content->size()) continue;
        std::size_t lookback = cand.start_offset > 50 ? 50 : cand.start_offset;
        std::string prefix = file_content->substr(cand.start_offset - lookback, lookback);
        if (prefix.find("RTPROTECT_VIRTUALIZE") == std::string::npos &&
            prefix.find("[[rtprotect::virtualize]]") == std::string::npos) {
          file_content->insert(cand.start_offset, "RTPROTECT_VIRTUALIZE\n");
          file_modified = true;
        }
      }

      if (file_modified) {
        if (!WriteTextFile(file_path, *file_content)) {
          report.success = false;
          report.state = IntegrationState::kFailed;
          report.error_message = "Failed to write modified source file during auto-virtualization: " + file_path;
          return report;
        }
      }
    }
  }

  // 6b. Transform Client Sources (Function Virtualization, String Obfuscation, Anti-Tamper)
  for (const auto& src_file : plan.detected_sources) {
    std::string transform_err;
    bool transformed = TransformSourceFile(src_file, options.profile, opcode_seed,
                            vm_root, manifest_pubkey, options.product_id,
                            report.virtualized_functions,
                            report.obfuscated_string_count,
                            report.scattered_check_count,
                            &transform_err);
    if (!transform_err.empty()) {
      if (options.profile == ProtectionProfile::kMaximum || options.profile == ProtectionProfile::kBalanced) {
        report.success = false;
        report.state = IntegrationState::kFailed;
        report.error_message = "Transformation failed for " + src_file + ": " + transform_err;
        return report;
      } else {
        report.warnings.push_back("Transformation warning for " + src_file + ": " + transform_err);
      }
    }
    if (transformed) {
      if (std::find(report.modified_files.begin(), report.modified_files.end(), src_file) == report.modified_files.end()) {
        report.modified_files.push_back(src_file);
      }
    }
  }

  std::string root = options.rtprotect_root.empty() ? "." : options.rtprotect_root;
  std::error_code ec_root;
  auto abs_root = fs::weakly_canonical(fs::path(root), ec_root);
  std::string root_str = ec_root ? root : abs_root.string();
  std::replace(root_str.begin(), root_str.end(), '\\', '/');

  // 7. Update CMakeLists.txt (HIGH 7 REMEDIATION: Relocatable SDK and Source Tree Support)
  auto cmake_content = ReadTextFile(cmake_file.string());
  if (cmake_content.has_value()) {
    std::ostringstream ss;
    ss << "\n# --- Added by RTProtect Integration Tool ---\n";
    ss << "if(NOT DEFINED OPENSSL_ROOT_DIR AND EXISTS \"" << root_str << "/third_party/openssl\")\n";
    ss << "  set(OPENSSL_ROOT_DIR \"" << root_str << "/third_party/openssl\")\n";
    ss << "endif()\n";
    ss << "find_package(OpenSSL REQUIRED)\n";

    ss << "# Support both packaged SDK layout (include/ and lib/) and source tree layout\n";
    ss << "if(EXISTS \"" << root_str << "/include\" AND EXISTS \"" << root_str << "/lib\")\n";
    ss << "  target_include_directories(" << target_name << " PRIVATE \"" << root_str << "/include\")\n";
    ss << "  target_link_directories(" << target_name << " PRIVATE \"" << root_str << "/lib\")\n";
    ss << "else()\n";
    ss << "  target_include_directories(" << target_name << " PRIVATE\n";
    ss << "      \"" << root_str << "\"\n";
    ss << "      \"" << root_str << "/third_party/openssl/include\"\n";
    ss << "  )\n";
    ss << "  target_link_directories(" << target_name << " PRIVATE\n";
    std::vector<std::string> bld_prefixes = {
      root_str + "/build",
      root_str + "/build-mingw",
      root_str + "/build-vs2022",
      root_str + "/build-ninja",
      root_str + "/build-reconst"
    };
    std::string tool_path_str = GetToolExecutablePath();
    if (!tool_path_str.empty()) {
      namespace fs = std::filesystem;
      fs::path tp(tool_path_str);
      fs::path p = tp.parent_path();
      if (p.filename() == "Release" || p.filename() == "Debug" || p.filename() == "RelWithDebInfo") {
        p = p.parent_path();
      }
      if (p.filename() == "tooling" || p.filename() == "bin") {
        std::string tb = p.parent_path().string();
        std::replace(tb.begin(), tb.end(), '\\', '/');
        bld_prefixes.push_back(tb);
      }
    }
    std::vector<std::string> submods = {"integrity", "licensing", "antitamper", "crypto", "bytecode_vm", "obfuscation"};
    for (const auto& bfx : bld_prefixes) {
      for (const auto& sm : submods) {
        ss << "      \"" << bfx << "/" << sm << "\"\n";
        ss << "      \"" << bfx << "/" << sm << "/$<CONFIG>\"\n";
        ss << "      \"" << bfx << "/" << sm << "/Release\"\n";
        ss << "      \"" << bfx << "/" << sm << "/Debug\"\n";
      }
      ss << "      \"" << bfx << "/lib\"\n";
    }
    ss << "      \"" << root_str << "/third_party/openssl/lib\"\n";
    ss << "      \"" << root_str << "/lib\"\n";
    ss << "  )\n";
    ss << "endif()\n";

    ss << "target_sources(" << target_name << " PRIVATE rtprotect_runtime_glue.cpp)\n";
    ss << "target_link_libraries(" << target_name << " PRIVATE\n";
    ss << "    rtprotect_licensing\n";
    ss << "    rtprotect_integrity\n";
    ss << "    rtprotect_antitamper\n";
    ss << "    rtprotect_crypto\n";
    ss << "    rtprotect_vm\n";
    // rtprotect_obfuscation is an INTERFACE (header-only) CMake target in
    // this source tree, so a consumer without an exported package target
    // must not be asked to link a nonexistent librtprotect_obfuscation.
    ss << "    OpenSSL::Crypto\n";
    ss << "    OpenSSL::SSL\n";
    ss << "    $<$<PLATFORM_ID:Windows>:iphlpapi>\n";
    ss << "    $<$<PLATFORM_ID:Windows>:ws2_32>\n";
    ss << "    $<$<PLATFORM_ID:Windows>:winhttp>\n";
    ss << "    $<$<PLATFORM_ID:Windows>:crypt32>\n";
    ss << ")\n\n";

    ss << "if(WIN32)\n";
    ss << "  if(DEFINED OPENSSL_ROOT_DIR AND EXISTS \"${OPENSSL_ROOT_DIR}/bin\")\n";
    ss << "    file(GLOB RTPROTECT_OPENSSL_DLLS \"${OPENSSL_ROOT_DIR}/bin/*.dll\")\n";
    ss << "    if(RTPROTECT_OPENSSL_DLLS)\n";
    ss << "      add_custom_command(TARGET " << target_name << " POST_BUILD\n";
    ss << "        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${RTPROTECT_OPENSSL_DLLS} $<TARGET_FILE_DIR:" << target_name << ">\n";
    ss << "      )\n";
    ss << "    endif()\n";
    ss << "  endif()\n";
    ss << "endif()\n";

    ss << "\n# Compiler & Linker Hardening Profile: " << ToString(options.profile) << "\n";
    if (options.profile == ProtectionProfile::kMaximum) {
      ss << "if(MSVC)\n";
      ss << "  target_compile_options(" << target_name << " PRIVATE /guard:cf)\n";
      ss << "  target_link_options(" << target_name << " PRIVATE /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA)\n";
      ss << "else()\n";
      ss << "  target_compile_options(" << target_name << " PRIVATE -fstack-protector-strong -fPIE)\n";
      ss << "  target_link_options(" << target_name << " PRIVATE -pie -Wl,-z,relro,-z,now)\n";
      ss << "endif()\n";
    } else if (options.profile == ProtectionProfile::kBalanced) {
      ss << "if(MSVC)\n";
      ss << "  target_link_options(" << target_name << " PRIVATE /DYNAMICBASE /NXCOMPAT)\n";
      ss << "else()\n";
      ss << "  target_compile_options(" << target_name << " PRIVATE -fstack-protector)\n";
      ss << "endif()\n";
    }

    std::string updated_cmake = *cmake_content + ss.str();
    if (!WriteTextFile(cmake_file.string(), updated_cmake)) {
      report.success = false;
      report.state = IntegrationState::kFailed;
      report.error_message = "Failed to update CMakeLists.txt";
      return report;
    }
    report.modified_files.push_back(cmake_file.string());
  }

  // 8. License Handling (CRITICAL 4 & FINDING 3 REMEDIATION)
  fs::path lic_path = proj_path / "client.license";
  if (options.use_dev_keys) {
    licensing::License lic;
    lic.license_id = "lic-dev-" + std::to_string(timestamp);
    lic.product_id = options.product_id;
    lic.edition = "Development-Test";
    lic.customer_id = "developer-local-test";
    lic.capabilities = licensing::kCapCoreExecution | licensing::kCapCommercialUse | licensing::kCapAdvancedFeatures;
    lic.issued_at = static_cast<std::uint64_t>(std::time(nullptr));
    lic.expires_at = 0; // Perpetual test license
    lic.hardware_id = licensing::GetLocalHardwareId();

    if (has_license_privkey && license_privkey.has_value()) {
      if (!licensing::SignLicense(lic, *license_privkey)) {
        report.success = false;
        report.state = IntegrationState::kFailed;
        report.error_message = "Failed to sign development test license.";
        return report;
      }
    }
    auto lic_bytes = licensing::SerializeLicense(lic);
    if (!WriteFile(lic_path.string(), lic_bytes.data(), lic_bytes.size())) {
      report.success = false;
      report.state = IntegrationState::kFailed;
      report.error_message = "Failed to write development client.license";
      return report;
    }
    report.license_file = lic_path.string();
    report.generated_files.push_back(lic_path.string());
  } else if (!options.license_file_path.empty()) {
    // Explicit pre-issued customer license has highest priority over auto-generation
    auto ldata = ReadFile(options.license_file_path);
    if (!ldata.has_value()) {
      report.success = false;
      report.state = IntegrationState::kFailed;
      report.error_message = "Cannot read supplied license file: " + options.license_file_path;
      return report;
    }
    auto lic_opt = licensing::DeserializeLicense(ldata->data(), ldata->size());
    if (!lic_opt.has_value()) {
      report.success = false;
      report.state = IntegrationState::kFailed;
      report.error_message = "Supplied license file is malformed or corrupted";
      return report;
    }
    const auto& verified_lic = *lic_opt;
    auto sig_bytes = licensing::SerializeLicenseForSigning(verified_lic);
    if (!integrity::VerifyManifestSignature(sig_bytes, verified_lic.signature, license_pubkey)) {
      report.success = false;
      report.state = IntegrationState::kFailed;
      report.error_message = "Supplied license file failed cryptographic Ed25519 signature verification against license.pub";
      return report;
    }
    if (verified_lic.product_id != options.product_id) {
      report.success = false;
      report.state = IntegrationState::kFailed;
      report.error_message = "Supplied license product_id (" + verified_lic.product_id + ") does not match target (" + options.product_id + ")";
      return report;
    }
    if (!WriteFile(lic_path.string(), ldata->data(), ldata->size())) {
      report.success = false;
      report.state = IntegrationState::kFailed;
      report.error_message = "Failed to deploy verified license file to project";
      return report;
    }
    report.license_file = lic_path.string();
    report.generated_files.push_back(lic_path.string());
  } else if (has_license_privkey && license_privkey.has_value()) {
    // Production license issuance workflow via --sign-license-key on vendor infrastructure
    licensing::License lic;
    lic.license_id = "lic-prod-" + std::to_string(timestamp);
    lic.product_id = options.product_id;
    lic.edition = options.license_edition.empty() ? "Production" : options.license_edition;
    lic.customer_id = options.customer_id.empty() ? "authorized-client" : options.customer_id;
    lic.capabilities = licensing::kCapCoreExecution | licensing::kCapCommercialUse | licensing::kCapAdvancedFeatures;
    lic.issued_at = static_cast<std::uint64_t>(std::time(nullptr));
    lic.expires_at = options.license_expires_at;
    lic.hardware_id = ""; // Unbound to build machine; client activation binds device seat

    if (!licensing::SignLicense(lic, *license_privkey)) {
      report.success = false;
      report.state = IntegrationState::kFailed;
      report.error_message = "Failed to sign production license with supplied license signing key";
      return report;
    }
    auto lic_bytes = licensing::SerializeLicense(lic);
    if (!WriteFile(lic_path.string(), lic_bytes.data(), lic_bytes.size())) {
      report.success = false;
      report.state = IntegrationState::kFailed;
      report.error_message = "Failed to write signed production client.license";
      return report;
    }
    report.license_file = lic_path.string();
    report.generated_files.push_back(lic_path.string());
    report.license_file = lic_path.string();
    report.generated_files.push_back(lic_path.string());
  } else {
    report.warnings.push_back("No license file provided. An authorized client.license must be generated via 'rtprotect-tool license-generate' and placed alongside the application.");
  }

  // 9. Initial Release Manifest
  fs::path manifest_path = proj_path / "release.manifest";
  fs::path sig_path = proj_path / "release.sig";
  {
    integrity::Manifest manifest;
    manifest.release_version = options.release_version;
    manifest.release_sequence = options.minimum_release_sequence;

    std::uint64_t cfg_size = 0;
    auto cfg_hash = integrity::Sha256File(config_header_path.string(), &cfg_size);
    if (cfg_hash.has_value()) {
      manifest.AddResourceWithHash("rtprotect_config.h", *cfg_hash, cfg_size);
    }

    auto man_bytes = integrity::SerializeManifest(manifest);
    if (!WriteFile(manifest_path.string(), man_bytes.data(), man_bytes.size())) {
      report.success = false;
      report.state = IntegrationState::kFailed;
      report.error_message = "Failed to write initial release.manifest";
      return report;
    }

    if (has_manifest_privkey && manifest_privkey.has_value()) {
      auto sig = integrity::SignManifestBytes(man_bytes, *manifest_privkey);
      if (sig.has_value()) {
        if (!WriteFile(sig_path.string(), sig->data(), sig->size())) {
          report.success = false;
          report.state = IntegrationState::kFailed;
          report.error_message = "Failed to write initial release.sig";
          return report;
        }
      }
    }

    report.manifest_file = manifest_path.string();
    report.signature_file = sig_path.string();
    report.generated_files.push_back(manifest_path.string());
    if (has_manifest_privkey) {
      report.generated_files.push_back(sig_path.string());
    }
  }

  // 10. Build and Post-Build Measurement (HIGH 6 REMEDIATION: Process Invocation)
  if (options.run_build) {
    fs::path build_dir = proj_path / "build_protected";
    std::string openssl_dir = root_str + "/third_party/openssl";

    std::vector<std::string> cfg_args = {
      "-B", build_dir.string(),
      "-S", proj_path.string()
    };
    if (fs::exists(openssl_dir)) {
      cfg_args.push_back("-DOPENSSL_ROOT_DIR=" + openssl_dir);
    }
    const char* env_gen = std::getenv("CMAKE_GENERATOR");
    if (env_gen && env_gen[0] != '\0') {
      cfg_args.push_back("-G");
      cfg_args.push_back(env_gen);
    }
    const char* env_bt = std::getenv("CMAKE_BUILD_TYPE");
    if (env_bt && env_bt[0] != '\0') {
      cfg_args.push_back("-DCMAKE_BUILD_TYPE=" + std::string(env_bt));
    }

    int cr = RunProcess("cmake", cfg_args);
    if (cr != 0) {
      report.build_succeeded = false;
      report.success = false;
      report.state = IntegrationState::kFailed;
      report.error_message = "CMake configuration failed for target project (exit code " + std::to_string(cr) + ")";
      return report;
    }

    std::string config_name = (env_bt && env_bt[0] != '\0') ? env_bt : "Release";
    std::vector<std::string> bld_args = {
      "--build", build_dir.string(),
      "--config", config_name
    };
    int br = RunProcess("cmake", bld_args);
    if (br != 0) {
      report.build_succeeded = false;
      report.success = false;
      report.state = IntegrationState::kFailed;
      report.error_message = "Protected build compilation failed (exit code " + std::to_string(br) + ")";
      return report;
    }
    report.build_succeeded = true;

    // Locate compiled binary
    std::string exe_filename = target_name;
#if defined(_WIN32)
    exe_filename += ".exe";
#endif

    fs::path built_exe;
    std::vector<fs::path> candidate_dirs = {
      build_dir / config_name,
      build_dir / "Release",
      build_dir / "Debug",
      build_dir / "RelWithDebInfo",
      build_dir
    };
    for (const auto& cd : candidate_dirs) {
      if (fs::exists(cd / exe_filename)) {
        built_exe = cd / exe_filename;
        break;
      }
    }

    if (built_exe.empty()) {
      report.success = false;
      report.state = IntegrationState::kFailed;
      report.error_message = "Compiled target binary '" + exe_filename + "' was not found in build outputs.";
      return report;
    }

    // Measure the actual compiled executable via streaming SHA-256
    integrity::Manifest manifest;
    manifest.release_version = options.release_version;
    manifest.release_sequence = options.minimum_release_sequence;

    std::uint64_t cfg_size = 0;
    auto cfg_hash = integrity::Sha256File(config_header_path.string(), &cfg_size);
    if (cfg_hash.has_value()) {
      manifest.AddResourceWithHash("rtprotect_config.h", *cfg_hash, cfg_size);
    }

    std::uint64_t exe_size = 0;
    auto exe_hash = integrity::Sha256File(built_exe.string(), &exe_size);
    if (!exe_hash.has_value()) {
      report.success = false;
      report.state = IntegrationState::kFailed;
      report.error_message = "Failed to compute SHA-256 digest of built binary: " + built_exe.string();
      return report;
    }
    manifest.AddResourceWithHash(exe_filename, *exe_hash, exe_size);

    auto man_bytes = integrity::SerializeManifest(manifest);
    if (!WriteFile(manifest_path.string(), man_bytes.data(), man_bytes.size())) {
      report.success = false;
      report.state = IntegrationState::kFailed;
      report.error_message = "Failed to write measured release.manifest";
      return report;
    }

    // CRITICAL 3 REMEDIATION: Production signing check
    if (has_manifest_privkey && manifest_privkey.has_value()) {
      auto sig = integrity::SignManifestBytes(man_bytes, *manifest_privkey);
      if (!sig.has_value()) {
        report.success = false;
        report.state = IntegrationState::kFailed;
        report.error_message = "Failed to sign release manifest.";
        return report;
      }
      if (!WriteFile(sig_path.string(), sig->data(), sig->size())) {
        report.success = false;
        report.state = IntegrationState::kFailed;
        report.error_message = "Failed to write release.sig";
        return report;
      }

      // Deploy signed artifacts next to the executable
      auto dest_dir = built_exe.parent_path();
      fs::copy_file(manifest_path, dest_dir / "release.manifest", fs::copy_options::overwrite_existing, ec);
      fs::copy_file(sig_path, dest_dir / "release.sig", fs::copy_options::overwrite_existing, ec);
      fs::copy_file(manifest_pub_path, dest_dir / "release.pub", fs::copy_options::overwrite_existing, ec);
      if (fs::exists(license_pub_path)) {
        fs::copy_file(license_pub_path, dest_dir / "license.pub", fs::copy_options::overwrite_existing, ec);
      }
      if (fs::exists(activation_pub_path)) {
        fs::copy_file(activation_pub_path, dest_dir / "activation.pub", fs::copy_options::overwrite_existing, ec);
      }
      if (fs::exists(lic_path)) {
        fs::copy_file(lic_path, dest_dir / "client.license", fs::copy_options::overwrite_existing, ec);
      }

      // Deploy bundled OpenSSL runtime DLLs next to executable so target runs standalone
      fs::path openssl_bin_dir = fs::path(root_str) / "third_party" / "openssl" / "bin";
      if (fs::exists(openssl_bin_dir)) {
        for (const auto& entry : fs::directory_iterator(openssl_bin_dir)) {
          if (entry.path().extension() == ".dll") {
            fs::copy_file(entry.path(), dest_dir / entry.path().filename(), fs::copy_options::overwrite_existing, ec);
          }
        }
      }

      // Validate protected build
      std::string val_err;
      report.validation_succeeded = ValidateProtectedBuild(
          proj_path.string(), manifest_pub_path.string(), manifest_path.string(), sig_path.string(), &val_err);
      if (!report.validation_succeeded) {
        report.success = false;
        report.state = IntegrationState::kFailed;
        report.error_message = "Protected build validation failed: " + val_err;
        return report;
      }
      report.state = IntegrationState::kValidated;
      report.success = true;
    } else {
      // Unsigned production build
      if (options.staging_only) {
        report.is_staged_only = true;
        report.state = IntegrationState::kAwaitingSignature;
        report.success = true;
        report.warnings.push_back("Project compiled in staging mode without signing. Use 'rtprotect-tool sign-release' with vendor private key to sign release before distribution.");
      } else {
        report.success = false;
        report.state = IntegrationState::kFailed;
        report.error_message = "Build succeeded, but release artifacts cannot be finalized without vendor signing key. Supply --sign-manifest-key or pass --staging to stage unsigned outputs.";
        return report;
      }
    }
  } else {
    // !options.run_build
    report.state = IntegrationState::kIntegrated;
    report.success = true;
    report.warnings.push_back("Build skipped (--no-build). Project has been instrumented but NOT compiled, signed, or validated.");
  }

  if (!options.report_json_path.empty()) {
    WriteTextFile(options.report_json_path, report.ToJson());
  }

  return report;
}

bool ExecuteRollback(const std::string& target_project_path,
                     const std::string& backup_dir,
                     std::string* error_out) {
  std::error_code ec;
  fs::path proj_path = fs::canonical(target_project_path, ec);
  if (ec || !fs::is_directory(proj_path)) {
    if (error_out) *error_out = "Target project directory does not exist";
    return false;
  }

  fs::path bkp_path = fs::canonical(backup_dir, ec);
  if (ec || !fs::is_directory(bkp_path)) {
    if (error_out) *error_out = "Backup directory does not exist: " + backup_dir;
    return false;
  }

  // Parse integration_journal.json
  fs::path journal_path = bkp_path / "integration_journal.json";
  if (fs::exists(journal_path)) {
    auto jtext = ReadTextFile(journal_path.string());
    if (jtext.has_value()) {
      auto extract_list = [](const std::string& json, const std::string& key) -> std::vector<std::string> {
        std::vector<std::string> items;
        auto pos = json.find("\"" + key + "\"");
        if (pos == std::string::npos) return items;
        auto open_bracket = json.find('[', pos);
        auto close_bracket = json.find(']', open_bracket);
        if (open_bracket == std::string::npos || close_bracket == std::string::npos) return items;
        std::string array_str = json.substr(open_bracket + 1, close_bracket - open_bracket - 1);
        std::istringstream iss(array_str);
        std::string line;
        while (std::getline(iss, line, ',')) {
          auto q1 = line.find('"');
          auto q2 = line.rfind('"');
          if (q1 != std::string::npos && q2 != std::string::npos && q2 > q1) {
            items.push_back(line.substr(q1 + 1, q2 - q1 - 1));
          }
        }
        return items;
      };

      auto created_files = extract_list(*jtext, "created_files");
      auto backed_up_files = extract_list(*jtext, "backed_up_files");

      // Remove only files created by the integration transaction
      for (const auto& rel_file : created_files) {
        fs::path target_file = proj_path / rel_file;
        if (IsPathWithin(target_file, proj_path) && fs::exists(target_file)) {
          fs::remove(target_file, ec);
        }
      }

      // Restore backed-up files
      for (const auto& rel_file : backed_up_files) {
        fs::path src = bkp_path / rel_file;
        fs::path dest = proj_path / rel_file;
        if (IsPathWithin(dest, proj_path) && fs::exists(src)) {
          fs::create_directories(dest.parent_path(), ec);
          fs::copy_file(src, dest, fs::copy_options::overwrite_existing, ec);
          if (ec) {
            if (error_out) *error_out = "Failed restoring: " + dest.string();
            return false;
          }
        }
      }

      return true;
    }
  }

  // Fallback: restore backed-up files
  for (const auto& entry : fs::recursive_directory_iterator(bkp_path, ec)) {
    if (entry.is_regular_file()) {
      auto rel = fs::relative(entry.path(), bkp_path);
      if (rel.string() == "integration_journal.json") continue;
      auto dest = proj_path / rel;
      if (!IsPathWithin(dest, proj_path)) {
        if (error_out) *error_out = "Path traversal detected in backup target: " + dest.string();
        return false;
      }
      fs::create_directories(dest.parent_path(), ec);
      fs::copy_file(entry.path(), dest, fs::copy_options::overwrite_existing, ec);
      if (ec) {
        if (error_out) *error_out = "Failed restoring: " + dest.string();
        return false;
      }
    }
  }

  std::vector<std::string> to_remove = {
    "rtprotect_config.h",
    "rtprotect_runtime_glue.cpp",
    "release.pub",
    "license.pub",
    "activation.pub",
    "countermeasure.pub",
    "release.priv",
    "activation.priv",
    "countermeasure.priv",
    "release.manifest",
    "release.sig",
    "client.license"
  };
  for (const auto& f : to_remove) {
    fs::path target_file = proj_path / f;
    if (IsPathWithin(target_file, proj_path) && fs::exists(target_file)) {
      fs::remove(target_file, ec);
    }
  }

  return true;
}

bool SignRelease(const std::string& project_dir,
                 const std::string& manifest_privkey_path,
                 const std::string& license_file_path,
                 std::string* error_out) {
  std::error_code ec;
  fs::path root = fs::canonical(project_dir, ec);
  if (ec || !fs::is_directory(root)) {
    if (error_out) *error_out = "Target project directory does not exist: " + project_dir;
    return false;
  }

  // Extract expected product ID from rtprotect_config.h if present
  std::string expected_product_id;
  fs::path cfg_path = root / "rtprotect_config.h";
  if (!fs::exists(cfg_path)) cfg_path = root / "include" / "rtprotect_config.h";
  if (fs::exists(cfg_path)) {
    auto cfg_bytes = ReadFile(cfg_path.string());
    if (cfg_bytes.has_value()) {
      std::string cfg_str(reinterpret_cast<const char*>(cfg_bytes->data()), cfg_bytes->size());
      auto pos = cfg_str.find("kProductId = \"");
      if (pos != std::string::npos) {
        auto end_pos = cfg_str.find('"', pos + 14);
        if (end_pos != std::string::npos) {
          expected_product_id = cfg_str.substr(pos + 14, end_pos - (pos + 14));
        }
      }
    }
  }

  // 1. Locate and read the target project's release.pub verification key
  fs::path pub_path = root / "release.pub";
  if (!fs::exists(pub_path)) {
    std::vector<fs::path> candidate_dirs = {
      root / "build_protected",
      root / "build_protected" / "Release",
      root / "build_protected" / "Debug",
      root / "build"
    };
    for (const auto& cd : candidate_dirs) {
      if (fs::exists(cd / "release.pub")) {
        pub_path = cd / "release.pub";
        break;
      }
    }
  }

  auto pub_bytes = ReadFile(pub_path.string());
  if (!pub_bytes.has_value() || pub_bytes->size() != integrity::kEd25519PublicKeyLen) {
    if (error_out) *error_out = "Target release public key not found or invalid (32 bytes required): " + pub_path.string();
    return false;
  }
  integrity::Ed25519PublicKey expected_pub{};
  std::memcpy(expected_pub.data(), pub_bytes->data(), integrity::kEd25519PublicKeyLen);

  // 2. Read and parse vendor private key
  auto priv_bytes = ReadFile(manifest_privkey_path);
  if (!priv_bytes.has_value() || priv_bytes->size() != integrity::kEd25519PrivateKeyLen) {
    if (error_out) *error_out = "Invalid or unreadable private key: " + manifest_privkey_path;
    return false;
  }
  auto priv = integrity::Ed25519PrivateKey::FromBytes(priv_bytes->data(), priv_bytes->size());
  if (!priv.has_value()) {
    if (error_out) *error_out = "Failed to load private key bytes";
    return false;
  }

  // 3. Read and deserialize manifest
  fs::path manifest_path = root / "release.manifest";
  auto man_bytes = ReadFile(manifest_path.string());
  if (!man_bytes.has_value()) {
    if (error_out) *error_out = "Manifest file not found: " + manifest_path.string();
    return false;
  }

  auto manifest = integrity::DeserializeManifest(man_bytes->data(), man_bytes->size());
  if (!manifest.has_value()) {
    if (error_out) *error_out = "Failed to deserialize release manifest";
    return false;
  }

  // Update resource hashes for build output files
  for (auto& res : manifest->resources) {
    fs::path res_path = root / res.name;
    if (!fs::exists(res_path)) {
      std::vector<fs::path> candidate_dirs = {
        root / "build_protected",
        root / "build_protected" / "Release",
        root / "build_protected" / "Debug",
        root / "build",
        root / "build" / "Release",
        root / "build" / "Debug"
      };
      for (const auto& cd : candidate_dirs) {
        if (fs::exists(cd / res.name)) {
          res_path = cd / res.name;
          break;
        }
      }
    }
    if (fs::exists(res_path)) {
      std::uint64_t sz = 0;
      auto h = integrity::Sha256File(res_path.string(), &sz);
      if (h.has_value()) {
        res.sha256 = *h;
        res.size = sz;
      }
    }
  }

  // 4. Verify client license exists and validate its product ID binding
  std::vector<std::uint8_t> effective_lic_bytes;
  if (!license_file_path.empty()) {
    auto ldata = ReadFile(license_file_path);
    if (!ldata.has_value()) {
      if (error_out) *error_out = "Cannot read supplied license file: " + license_file_path;
      return false;
    }
    effective_lic_bytes = std::move(*ldata);
  } else {
    fs::path lic_path = root / "client.license";
    if (!fs::exists(lic_path)) {
      std::vector<fs::path> candidate_dirs = {
        root / "build_protected",
        root / "build_protected" / "Release",
        root / "build_protected" / "Debug",
        root / "build"
      };
      for (const auto& cd : candidate_dirs) {
        if (fs::exists(cd / "client.license")) {
          lic_path = cd / "client.license";
          break;
        }
      }
    }
    auto ldata = ReadFile(lic_path.string());
    if (ldata.has_value()) {
      effective_lic_bytes = std::move(*ldata);
    }
  }

  if (effective_lic_bytes.empty()) {
    if (error_out) *error_out = "Production release signing failed: client.license is missing. Production packages require a valid signed license.";
    return false;
  }

  // Verify license against project's license.pub
  fs::path lic_pub_path = root / "license.pub";
  if (!fs::exists(lic_pub_path)) {
    std::vector<fs::path> candidate_dirs = {
      root / "build_protected",
      root / "build_protected" / "Release",
      root / "build_protected" / "Debug",
      root / "build"
    };
    for (const auto& cd : candidate_dirs) {
      if (fs::exists(cd / "license.pub")) {
        lic_pub_path = cd / "license.pub";
        break;
      }
    }
  }
  auto lpub_bytes = ReadFile(lic_pub_path.string());
  if (!lpub_bytes.has_value() || lpub_bytes->size() != integrity::kEd25519PublicKeyLen) {
    if (error_out) *error_out = "Missing or invalid license.pub verification key: " + lic_pub_path.string();
    return false;
  }
  integrity::Ed25519PublicKey lic_pub{};
  std::memcpy(lic_pub.data(), lpub_bytes->data(), integrity::kEd25519PublicKeyLen);
  licensing::LicenseVerificationContext ctx;
  ctx.current_time = static_cast<std::uint64_t>(std::time(nullptr));
  ctx.enforce_hardware_binding = false; // Decoupled from build machine HWID
  if (!expected_product_id.empty()) {
    ctx.expected_product_id = expected_product_id;
  }
  licensing::License verified_lic;
  auto lstatus = licensing::VerifyLicenseBytes(effective_lic_bytes.data(), effective_lic_bytes.size(), lic_pub, ctx, &verified_lic);
  if (lstatus != licensing::LicenseStatus::kValid) {
    if (error_out) {
      if (lstatus == licensing::LicenseStatus::kProductMismatch) {
        *error_out = "License product ID mismatch: license was issued for '" + verified_lic.product_id + "' but release requires '" + expected_product_id + "'";
      } else {
        *error_out = "License verification failed during release signing: status " + std::string(licensing::ToString(lstatus));
      }
    }
    return false;
  }
  if (!expected_product_id.empty() && verified_lic.product_id != expected_product_id) {
    if (error_out) *error_out = "License product ID mismatch: license was issued for '" + verified_lic.product_id + "' but release requires '" + expected_product_id + "'";
    return false;
  }

  // 5. Serialize manifest and compute signature
  auto updated_man_bytes = integrity::SerializeManifest(*manifest);
  auto sig = integrity::SignManifestBytes(updated_man_bytes, *priv);
  if (!sig.has_value()) {
    if (error_out) *error_out = "Failed to compute manifest signature with private key";
    return false;
  }

  // Cryptographic public/private key correspondence check
  if (!integrity::VerifyManifestSignature(updated_man_bytes, *sig, expected_pub)) {
    if (error_out) *error_out = "Signing key mismatch: supplied private key does not correspond to the target project's release.pub verification key";
    return false;
  }

  // 6. Transactional Staging: stage to temporary files and validate before committing
  fs::path manifest_tmp = root / "release.manifest.tmp";
  fs::path sig_tmp = root / "release.sig.tmp";
  fs::path lic_tmp = root / "client.license.tmp";

  if (!WriteFile(manifest_tmp.string(), updated_man_bytes.data(), updated_man_bytes.size()) ||
      !WriteFile(sig_tmp.string(), sig->data(), sig->size()) ||
      !WriteFile(lic_tmp.string(), effective_lic_bytes.data(), effective_lic_bytes.size())) {
    fs::remove(manifest_tmp, ec);
    fs::remove(sig_tmp, ec);
    fs::remove(lic_tmp, ec);
    if (error_out) *error_out = "Failed to write staged release artifacts";
    return false;
  }

  std::string val_err;
  if (!ValidateProtectedBuild(root.string(), pub_path.string(), manifest_tmp.string(), sig_tmp.string(),
                              &val_err, true, manifest->release_sequence, expected_product_id)) {
    fs::remove(manifest_tmp, ec);
    fs::remove(sig_tmp, ec);
    fs::remove(lic_tmp, ec);
    if (error_out) *error_out = "Post-signing release validation failed on staged artifacts: " + val_err;
    return false;
  }

  // 7. Atomic Commit of Validated Staged Artifacts
  fs::path sig_path = root / "release.sig";
  fs::path final_lic_path = root / "client.license";

  fs::rename(manifest_tmp, manifest_path, ec);
  if (ec) {
    fs::remove(manifest_path, ec);
    fs::rename(manifest_tmp, manifest_path, ec);
  }
  fs::rename(sig_tmp, sig_path, ec);
  if (ec) {
    fs::remove(sig_path, ec);
    fs::rename(sig_tmp, sig_path, ec);
  }
  fs::rename(lic_tmp, final_lic_path, ec);
  if (ec) {
    fs::remove(final_lic_path, ec);
    fs::rename(lic_tmp, final_lic_path, ec);
  }

  // Copy signed manifest, sig, and license next to built executable
  std::vector<fs::path> candidate_dirs = {
    root / "build_protected",
    root / "build_protected" / "Release",
    root / "build_protected" / "Debug",
    root / "build",
    root / "build" / "Release",
    root / "build" / "Debug"
  };
  for (const auto& cd : candidate_dirs) {
    if (fs::is_directory(cd)) {
      fs::copy_file(manifest_path, cd / "release.manifest", fs::copy_options::overwrite_existing, ec);
      fs::copy_file(sig_path, cd / "release.sig", fs::copy_options::overwrite_existing, ec);
      fs::copy_file(final_lic_path, cd / "client.license", fs::copy_options::overwrite_existing, ec);
      if (fs::exists(root / "release.pub")) {
        fs::copy_file(root / "release.pub", cd / "release.pub", fs::copy_options::overwrite_existing, ec);
      }
      if (fs::exists(root / "license.pub")) {
        fs::copy_file(root / "license.pub", cd / "license.pub", fs::copy_options::overwrite_existing, ec);
      }
      if (fs::exists(root / "activation.pub")) {
        fs::copy_file(root / "activation.pub", cd / "activation.pub", fs::copy_options::overwrite_existing, ec);
      }
    }
  }

  return true;
}

bool ValidateProtectedBuild(const std::string& project_dir,
                            const std::string& public_key_path,
                            const std::string& manifest_path,
                            const std::string& signature_path,
                            std::string* error_out,
                            bool require_license,
                            std::uint64_t minimum_release_sequence,
                            const std::string& expected_product_id) {
  auto pub_bytes = ReadFile(public_key_path);
  if (!pub_bytes.has_value() || pub_bytes->size() != integrity::kEd25519PublicKeyLen) {
    if (error_out) *error_out = "Invalid or missing public key file (32 bytes required): " + public_key_path;
    return false;
  }

  auto man_bytes = ReadFile(manifest_path);
  if (!man_bytes.has_value()) {
    if (error_out) *error_out = "Missing manifest file: " + manifest_path;
    return false;
  }

  auto sig_bytes = ReadFile(signature_path);
  if (!sig_bytes.has_value() || sig_bytes->size() != integrity::kEd25519SignatureLen) {
    if (error_out) *error_out = "Invalid or missing signature file (64 bytes required): " + signature_path;
    return false;
  }

  integrity::Ed25519PublicKey pub;
  std::memcpy(pub.data(), pub_bytes->data(), integrity::kEd25519PublicKeyLen);

  integrity::Ed25519Signature sig;
  std::memcpy(sig.data(), sig_bytes->data(), integrity::kEd25519SignatureLen);

  if (!integrity::VerifyManifestSignature(*man_bytes, sig, pub)) {
    if (error_out) *error_out = "Manifest digital signature verification failed under provided public key";
    return false;
  }

  auto manifest = integrity::DeserializeManifest(man_bytes->data(), man_bytes->size());
  if (!manifest.has_value()) {
    if (error_out) *error_out = "Failed deserializing signed manifest";
    return false;
  }

  if (manifest->release_version.empty()) {
    if (error_out) *error_out = "Signed manifest contains empty release_version";
    return false;
  }

  if (manifest->release_sequence < minimum_release_sequence) {
    if (error_out) {
      *error_out = "Anti-rollback violation: manifest release sequence (" +
                   std::to_string(manifest->release_sequence) +
                   ") is less than required minimum (" +
                   std::to_string(minimum_release_sequence) + ")";
    }
    return false;
  }

  if (manifest->resources.empty()) {
    if (error_out) *error_out = "Signed manifest contains no committed resources";
    return false;
  }

  fs::path root(project_dir);
  for (const auto& res : manifest->resources) {
    fs::path res_path = root / res.name;
    if (!fs::exists(res_path)) {
      std::vector<fs::path> candidate_dirs = {
        root / "build_protected",
        root / "build_protected" / "Release",
        root / "build_protected" / "Debug",
        root / "build",
        root / "build" / "Release",
        root / "build" / "Debug"
      };
      for (const auto& cd : candidate_dirs) {
        if (fs::exists(cd / res.name)) {
          res_path = cd / res.name;
          break;
        }
      }
    }

    if (!fs::exists(res_path)) {
      if (error_out) *error_out = "Committed resource missing on disk: " + res.name;
      return false;
    }

    std::uint64_t actual_size = 0;
    auto actual_hash = integrity::Sha256File(res_path.string(), &actual_size);
    if (!actual_hash.has_value()) {
      if (error_out) *error_out = "Cannot compute hash of resource: " + res.name;
      return false;
    }

    if (actual_size != res.size || *actual_hash != res.sha256) {
      if (error_out) *error_out = std::string("Committed resource verification failed (hash mismatch): ") + res.name;
      return false;
    }
  }

  // Validate license file
  fs::path lic_path = root / "client.license";
  fs::path lic_pub_path = root / "license.pub";
  std::vector<fs::path> candidate_dirs = {
    root / "build_protected",
    root / "build_protected" / "Release",
    root / "build_protected" / "Debug",
    root / "build"
  };

  if (!fs::exists(lic_path)) {
    if (fs::exists(root / "client.license.tmp")) {
      lic_path = root / "client.license.tmp";
    } else {
      for (const auto& cd : candidate_dirs) {
        if (fs::exists(cd / "client.license")) {
          lic_path = cd / "client.license";
          break;
        }
      }
    }
  }

  if (!fs::exists(lic_pub_path)) {
    for (const auto& cd : candidate_dirs) {
      if (fs::exists(cd / "license.pub")) {
        lic_pub_path = cd / "license.pub";
        break;
      }
    }
  }

  if (require_license) {
    if (!fs::exists(lic_path)) {
      if (error_out) *error_out = "Protected build validation failed: missing client.license file";
      return false;
    }
    if (!fs::exists(lic_pub_path)) {
      if (error_out) *error_out = "Protected build validation failed: missing license.pub file";
      return false;
    }
  }

  if (fs::exists(lic_path)) {
    if (!fs::exists(lic_pub_path)) {
      if (error_out) *error_out = "Found client.license but missing license.pub public key for verification";
      return false;
    }

    auto lic_data = ReadFile(lic_path.string());
    if (!lic_data.has_value()) {
      if (error_out) *error_out = "Unreadable client.license file: " + lic_path.string();
      return false;
    }

    auto lpub_bytes = ReadFile(lic_pub_path.string());
    if (!lpub_bytes.has_value() || lpub_bytes->size() != integrity::kEd25519PublicKeyLen) {
      if (error_out) *error_out = "Invalid or unreadable license.pub file: " + lic_pub_path.string();
      return false;
    }

    integrity::Ed25519PublicKey lic_pub{};
    std::memcpy(lic_pub.data(), lpub_bytes->data(), integrity::kEd25519PublicKeyLen);
    licensing::LicenseVerificationContext ctx;
    ctx.current_time = static_cast<std::uint64_t>(std::time(nullptr));
    ctx.enforce_hardware_binding = false; // Decoupled build validation from client machine HWID

    std::string eff_prod_id = expected_product_id;
    if (eff_prod_id.empty()) {
      fs::path cfg_path = root / "rtprotect_config.h";
      if (!fs::exists(cfg_path)) cfg_path = root / "include" / "rtprotect_config.h";
      if (fs::exists(cfg_path)) {
        auto cfg_bytes = ReadFile(cfg_path.string());
        if (cfg_bytes.has_value()) {
          std::string cfg_str(reinterpret_cast<const char*>(cfg_bytes->data()), cfg_bytes->size());
          auto pos = cfg_str.find("kProductId = \"");
          if (pos != std::string::npos) {
            auto end_pos = cfg_str.find('"', pos + 14);
            if (end_pos != std::string::npos) {
              eff_prod_id = cfg_str.substr(pos + 14, end_pos - (pos + 14));
            }
          }
        }
      }
    }
    if (!eff_prod_id.empty()) {
      ctx.expected_product_id = eff_prod_id;
    }

    licensing::License verified_lic;
    auto lstatus = licensing::VerifyLicenseBytes(lic_data->data(), lic_data->size(), lic_pub, ctx, &verified_lic);
    if (lstatus != licensing::LicenseStatus::kValid) {
      if (error_out) *error_out = "client.license validation failed: status " + std::to_string(static_cast<int>(lstatus));
      return false;
    }
  }

  return true;
}

}  // namespace rtprotect::tooling
