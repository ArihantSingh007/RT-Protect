// tests/test_unreal_integration.cpp

#include "tooling/unreal_integration.h"
#include "tests/micro_test.h"

#include <filesystem>
#include <fstream>
#include <string>

namespace fs = std::filesystem;
using namespace rtprotect::tooling;

namespace {

fs::path CreateTestDir(const std::string& name) {
  auto p = fs::temp_directory_path() / ("rtprotect_test_" + name + "_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()));
  fs::create_directories(p);
  return p;
}

void WriteFile(const fs::path& p, const std::string& content) {
  fs::create_directories(p.parent_path());
  std::ofstream f(p, std::ios::binary);
  f << content;
}

std::string ReadFile(const fs::path& p) {
  std::ifstream f(p, std::ios::binary);
  return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

}  // namespace

MT_TEST(UnrealIntegration_Detection_FindsUProject) {
  auto dir = CreateTestDir("uproject_detect");
  auto uproj = dir / "ShooterGame.uproject";
  WriteFile(uproj, "{\n  \"FileVersion\": 3,\n  \"EngineAssociation\": \"5.4\"\n}\n");

  MT_CHECK(IsUnrealProject(dir));
  auto found = FindUProjectFile(dir);
  MT_CHECK(found.has_value());
  MT_CHECK(found->filename() == "ShooterGame.uproject");

  fs::remove_all(dir);
}

MT_TEST(UnrealIntegration_InspectProject_ParsesModulesAndTaggedFunctions) {
  auto dir = CreateTestDir("uproject_inspect");
  WriteFile(dir / "ActionRPG.uproject", "{\n  \"FileVersion\": 3,\n  \"EngineAssociation\": \"5.3\"\n}\n");

  auto build_cs = dir / "Source" / "ActionRPG" / "ActionRPG.Build.cs";
  WriteFile(build_cs,
            "using UnrealBuildTool;\n"
            "public class ActionRPG : ModuleRules\n"
            "{\n"
            "    public ActionRPG(ReadOnlyTargetRules Target) : base(Target)\n"
            "    {\n"
            "        PCHUsage = PCHUsageMode.UseExplicitOrSharedPCHs;\n"
            "    }\n"
            "}\n");

  auto src = dir / "Source" / "ActionRPG" / "HeroCharacter.cpp";
  WriteFile(src,
            "#include \"HeroCharacter.h\"\n"
            "RTPROTECT_VIRTUALIZE int64_t ComputeDamage(int64_t base_atk, int64_t armor) {\n"
            "  return base_atk - armor;\n"
            "}\n");

  auto info = InspectUnrealProject(dir);
  MT_CHECK(info.is_valid);
  MT_CHECK(info.project_name == "ActionRPG");
  MT_CHECK(info.engine_association == "5.3");
  MT_CHECK(info.modules.size() == 1);
  MT_CHECK(info.modules[0].name == "ActionRPG");
  MT_CHECK(info.modules[0].source_files.size() >= 1);
  MT_CHECK(info.modules[0].tagged_functions.size() == 1);
  MT_CHECK(info.modules[0].tagged_functions[0] == "ComputeDamage");

  fs::remove_all(dir);
}

MT_TEST(UnrealIntegration_PatchBuildCs_IdempotentAndReversible) {
  auto dir = CreateTestDir("uproject_patch");
  auto build_cs = dir / "Source" / "RacingGame" / "RacingGame.Build.cs";
  const std::string original_content =
      "using UnrealBuildTool;\n"
      "public class RacingGame : ModuleRules\n"
      "{\n"
      "    public RacingGame(ReadOnlyTargetRules Target) : base(Target)\n"
      "    {\n"
      "        PublicDependencyModuleNames.AddRange(new string[] { \"Core\", \"Engine\" });\n"
      "    }\n"
      "}\n";

  WriteFile(build_cs, original_content);

  MT_CHECK(!IsUnrealBuildCsPatched(build_cs));

  // First patch
  std::string err;
  MT_CHECK(PatchUnrealBuildCs(build_cs, "RTProtect", &err));
  MT_CHECK(IsUnrealBuildCsPatched(build_cs));

  std::string patched = ReadFile(build_cs);
  MT_CHECK(patched.find("RTPROTECT_BEGIN_INJECTION") != std::string::npos);
  MT_CHECK(patched.find("PublicIncludePaths.Add") != std::string::npos);
  MT_CHECK(patched.find("RTPROTECT_ENABLED=1") != std::string::npos);

  // Idempotence test
  MT_CHECK(PatchUnrealBuildCs(build_cs, "RTProtect", &err));
  std::string patched2 = ReadFile(build_cs);
  MT_CHECK(patched == patched2);

  // Unpatch test
  MT_CHECK(UnpatchUnrealBuildCs(build_cs, &err));
  MT_CHECK(!IsUnrealBuildCsPatched(build_cs));

  fs::remove_all(dir);
}

MT_TEST(UnrealIntegration_Execution_CreatesBackupAndDeploysHeaders) {
  auto dir = CreateTestDir("uproject_exec");
  WriteFile(dir / "CyberGame.uproject", "{\n  \"FileVersion\": 3,\n  \"EngineAssociation\": \"5.4\"\n}\n");

  auto build_cs = dir / "Source" / "CyberGame" / "CyberGame.Build.cs";
  WriteFile(build_cs,
            "using UnrealBuildTool;\n"
            "public class CyberGame : ModuleRules\n"
            "{\n"
            "    public CyberGame(ReadOnlyTargetRules Target) : base(Target)\n"
            "    {\n"
            "    }\n"
            "}\n");

  WriteFile(dir / "Source" / "CyberGame" / "CyberGame.cpp",
            "RTPROTECT_VIRTUALIZE int64_t CalcScore(int64_t x) { return x * 10; }\n");

  IntegrationOptions opt;
  opt.target_project_path = dir.string();
  opt.product_id = "com.vendor.cybergame";
  opt.release_version = "2.0.0";

  auto plan = PlanUnrealIntegration(opt);
  MT_CHECK(plan.is_supported);
  MT_CHECK(plan.detected_build_system == "UnrealBuildTool (UBT)");

  auto report = ExecuteUnrealIntegration(opt);
  MT_CHECK(report.success);
  MT_CHECK(report.state == IntegrationState::kIntegrated);
  MT_CHECK(report.virtualized_functions.size() == 1);
  MT_CHECK(report.virtualized_functions[0] == "CalcScore");

  // Verify RTProtect headers deployed
  fs::path config_h = dir / "Source" / "CyberGame" / "RTProtect" / "rtprotect_config.h";
  MT_CHECK(fs::exists(config_h));
  std::string config_txt = ReadFile(config_h);
  MT_CHECK(config_txt.find("com.vendor.cybergame") != std::string::npos);

  // Verify Build.cs is patched
  MT_CHECK(IsUnrealBuildCsPatched(build_cs));

  // Verify backup exists
  MT_CHECK(fs::exists(report.backup_path));

  fs::remove_all(dir);
}

MT_MAIN()
