// tooling/unreal_integration.cpp

#include "tooling/unreal_integration.h"
#include "tooling/cxx_ast_scanner.h"

#include <algorithm>
#include <fstream>
#include <sstream>
#include <regex>

namespace fs = std::filesystem;

namespace rtprotect::tooling {

namespace {

std::string ReadFileToString(const fs::path& path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return {};
  std::ostringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

bool WriteStringToFile(const fs::path& path, const std::string& content) {
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  if (!f) return false;
  f << content;
  return f.good();
}

}  // namespace

bool IsUnrealProject(const fs::path& project_path) {
  return FindUProjectFile(project_path).has_value();
}

std::optional<fs::path> FindUProjectFile(const fs::path& project_path) {
  std::error_code ec;
  if (!fs::exists(project_path, ec) || !fs::is_directory(project_path, ec)) {
    return std::nullopt;
  }

  for (const auto& entry : fs::directory_iterator(project_path, ec)) {
    if (entry.is_regular_file() && entry.path().extension() == ".uproject") {
      return entry.path();
    }
  }

  return std::nullopt;
}

UnrealProjectInfo InspectUnrealProject(const fs::path& project_path) {
  UnrealProjectInfo info;
  info.project_root = project_path;

  auto uproj_opt = FindUProjectFile(project_path);
  if (!uproj_opt) {
    info.is_valid = false;
    info.error_message = "No .uproject file found in " + project_path.string();
    return info;
  }

  info.uproject_path = *uproj_opt;
  info.project_name = info.uproject_path.stem().string();

  std::string uproj_text = ReadFileToString(info.uproject_path);
  if (uproj_text.empty()) {
    info.is_valid = false;
    info.error_message = "Failed to read .uproject file: " + info.uproject_path.string();
    return info;
  }

  // Parse EngineAssociation from JSON
  std::regex engine_regex("\"EngineAssociation\"\\s*:\\s*\"([^\"]+)\"");
  std::smatch engine_match;
  if (std::regex_search(uproj_text, engine_match, engine_regex)) {
    info.engine_association = engine_match[1].str();
  }

  // Discover modules under Source/ directory
  fs::path source_dir = project_path / "Source";
  std::error_code ec;
  if (fs::exists(source_dir, ec) && fs::is_directory(source_dir, ec)) {
    for (const auto& entry : fs::directory_iterator(source_dir, ec)) {
      if (entry.is_directory()) {
        std::string mod_name = entry.path().filename().string();
        fs::path build_cs = entry.path() / (mod_name + ".Build.cs");
        if (fs::exists(build_cs, ec)) {
          UnrealModuleInfo mod;
          mod.name = mod_name;
          mod.module_dir = entry.path();
          mod.build_cs_path = build_cs;

          // Scan module for source files
          for (const auto& src_entry : fs::recursive_directory_iterator(entry.path(), ec)) {
            if (src_entry.is_regular_file()) {
              auto ext = src_entry.path().extension().string();
              if (ext == ".cpp" || ext == ".h" || ext == ".cc" || ext == ".cxx") {
                mod.source_files.push_back(src_entry.path());

                // Scan for RTPROTECT_VIRTUALIZE functions
                std::string code = ReadFileToString(src_entry.path());
                if (!code.empty()) {
                  CxxAstScanner scanner(code);
                  auto funcs = scanner.FindTaggedFunctions();
                  for (const auto& fn : funcs) {
                    mod.tagged_functions.push_back(fn.name);
                  }
                }
              }
            }
          }

          info.modules.push_back(std::move(mod));
        }
      }
    }
  }

  // Fallback: if no module directory found under Source/, check if default project module exists
  if (info.modules.empty()) {
    fs::path default_build_cs = source_dir / info.project_name / (info.project_name + ".Build.cs");
    if (fs::exists(default_build_cs, ec)) {
      UnrealModuleInfo mod;
      mod.name = info.project_name;
      mod.module_dir = source_dir / info.project_name;
      mod.build_cs_path = default_build_cs;
      info.modules.push_back(std::move(mod));
    }
  }

  info.is_valid = !info.modules.empty();
  if (!info.is_valid) {
    info.error_message = "No Unreal modules (Source/<Module>/<Module>.Build.cs) found in project";
  }

  return info;
}

bool IsUnrealBuildCsPatched(const fs::path& build_cs_path) {
  std::string content = ReadFileToString(build_cs_path);
  return content.find("// RTPROTECT_BEGIN_INJECTION") != std::string::npos;
}

bool PatchUnrealBuildCs(const fs::path& build_cs_path,
                        const std::string& relative_rtprotect_dir,
                        std::string* out_error) {
  if (IsUnrealBuildCsPatched(build_cs_path)) {
    return true;  // Idempotent
  }

  std::string content = ReadFileToString(build_cs_path);
  if (content.empty()) {
    if (out_error) *out_error = "Could not read Build.cs file: " + build_cs_path.string();
    return false;
  }

  // Find constructor opening brace: public <ClassName>(...) : base(...) {
  std::regex ctor_regex("(public\\s+[A-Za-z0-9_]+\\s*\\([^)]*\\)[^{]*\\{)");
  std::smatch match;
  if (!std::regex_search(content, match, ctor_regex)) {
    if (out_error) *out_error = "Could not locate ModuleRules constructor in " + build_cs_path.string();
    return false;
  }

  std::size_t insert_pos = match.position() + match.length();

  std::ostringstream injection;
  injection << "\n\t\t// RTPROTECT_BEGIN_INJECTION\n"
            << "\t\tPublicIncludePaths.Add(System.IO.Path.Combine(ModuleDirectory, \"" << relative_rtprotect_dir << "\"));\n"
            << "\t\tPublicDefinitions.Add(\"RTPROTECT_ENABLED=1\");\n"
            << "\t\t// RTPROTECT_END_INJECTION\n";

  content.insert(insert_pos, injection.str());

  if (!WriteStringToFile(build_cs_path, content)) {
    if (out_error) *out_error = "Failed to write patched Build.cs: " + build_cs_path.string();
    return false;
  }

  return true;
}

bool UnpatchUnrealBuildCs(const fs::path& build_cs_path, std::string* out_error) {
  std::string content = ReadFileToString(build_cs_path);
  if (content.empty()) {
    if (out_error) *out_error = "Could not read Build.cs file: " + build_cs_path.string();
    return false;
  }

  const std::string kBegin = "// RTPROTECT_BEGIN_INJECTION";
  const std::string kEnd = "// RTPROTECT_END_INJECTION";

  auto start_pos = content.find(kBegin);
  if (start_pos == std::string::npos) {
    return true;  // Not patched
  }

  auto end_pos = content.find(kEnd, start_pos);
  if (end_pos == std::string::npos) {
    if (out_error) *out_error = "Corrupted RTProtect marker in " + build_cs_path.string();
    return false;
  }
  end_pos += kEnd.length();
  // Strip trailing newline if present
  if (end_pos < content.length() && content[end_pos] == '\n') end_pos++;

  content.erase(start_pos, end_pos - start_pos);

  if (!WriteStringToFile(build_cs_path, content)) {
    if (out_error) *out_error = "Failed to write unpatched Build.cs: " + build_cs_path.string();
    return false;
  }

  return true;
}

ChangePlan PlanUnrealIntegration(const IntegrationOptions& options) {
  ChangePlan plan;
  auto info = InspectUnrealProject(options.target_project_path);
  if (!info.is_valid) {
    plan.is_supported = false;
    plan.explanation = info.error_message;
    return plan;
  }

  plan.detected_build_system = "UnrealBuildTool (UBT)";
  plan.detected_language = "C++";
  plan.is_supported = true;

  for (const auto& mod : info.modules) {
    plan.files_to_modify.push_back(mod.build_cs_path.string());
    for (const auto& src : mod.source_files) {
      plan.detected_sources.push_back(src.string());
    }

    // RTProtect module directory
    fs::path rt_dir = mod.module_dir / "RTProtect";
    plan.files_to_create.push_back((rt_dir / "rtprotect_config.h").string());
    plan.files_to_create.push_back((rt_dir / "rtprotect_unreal_runtime.h").string());
  }

  plan.files_to_create.push_back((info.project_root / "release.manifest").string());
  plan.files_to_create.push_back((info.project_root / "release.sig").string());
  plan.files_to_create.push_back((info.project_root / "client.license").string());

  return plan;
}

IntegrationReport ExecuteUnrealIntegration(const IntegrationOptions& options) {
  IntegrationReport report;
  auto plan = PlanUnrealIntegration(options);
  if (!plan.is_supported) {
    report.success = false;
    report.error_message = plan.explanation;
    return report;
  }

  auto info = InspectUnrealProject(options.target_project_path);
  report.target_name = info.project_name;

  // 1. Transactional Backup
  fs::path backup_base = options.backup_dir.empty() ?
      (info.project_root / "rtprotect_backup") : fs::path(options.backup_dir);
  std::error_code ec;
  fs::create_directories(backup_base, ec);
  report.backup_path = backup_base.string();

  for (const auto& mod : info.modules) {
    // Backup Build.cs
    fs::path bkp_file = backup_base / mod.build_cs_path.filename();
    fs::copy_file(mod.build_cs_path, bkp_file, fs::copy_options::overwrite_existing, ec);

    // Patch Build.cs
    std::string err;
    if (!PatchUnrealBuildCs(mod.build_cs_path, "RTProtect", &err)) {
      report.success = false;
      report.error_message = err;
      return report;
    }
    report.modified_files.push_back(mod.build_cs_path.string());

    // Create RTProtect folder
    fs::path rt_dir = mod.module_dir / "RTProtect";
    fs::create_directories(rt_dir, ec);

    // Create rtprotect_config.h
    fs::path config_path = rt_dir / "rtprotect_config.h";
    std::string config_content =
        "// RTProtect Unreal Configuration\n"
        "#pragma once\n"
        "#define RTPROTECT_UNREAL_BUILD 1\n"
        "#define RTPROTECT_PRODUCT_ID \"" + options.product_id + "\"\n"
        "#define RTPROTECT_VERSION \"" + options.release_version + "\"\n"
        "#define RTPROTECT_ACTIVATION_SERVER_URL \"" + options.activation_server_url + "\"\n";
    WriteStringToFile(config_path, config_content);
    report.generated_files.push_back(config_path.string());

    // Create rtprotect_unreal_runtime.h
    fs::path runtime_header = rt_dir / "rtprotect_unreal_runtime.h";
    std::string runtime_content =
        "// RTProtect Unreal Engine Runtime Integration\n"
        "#pragma once\n"
        "#include \"rtprotect_config.h\"\n"
        "#include <cstdint>\n"
        "namespace rtprotect::unreal {\n"
        "inline bool InitializeRTProtect() { return true; }\n"
        "}  // namespace rtprotect::unreal\n";
    WriteStringToFile(runtime_header, runtime_content);
    report.generated_files.push_back(runtime_header.string());

    // Record tagged functions found
    for (const auto& fn : mod.tagged_functions) {
      report.virtualized_functions.push_back(fn);
    }
  }

  report.success = true;
  report.state = IntegrationState::kIntegrated;
  return report;
}

}  // namespace rtprotect::tooling
