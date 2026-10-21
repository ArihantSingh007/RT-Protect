// tooling/unreal_integration.h
//
// Unreal Engine (UBT) Project Integration Module.
//
// Extends RTProtect build-system support to Unreal Engine projects (.uproject)
// and the UnrealBuildTool (UBT) build system.
//
// Features:
// 1. .uproject detection and module metadata parsing.
// 2. Automated Source/<Module>/<Module>.Build.cs dependency and include injection.
// 3. Source tree AST scanning for RTPROTECT_VIRTUALIZE routines in Unreal modules.
// 4. Automated deployment of RTProtect runtime glue and VM engine into Unreal modules.
// 5. Full transaction rollback and dry-run preview support.

#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "tooling/integration_engine.h"

namespace rtprotect::tooling {

struct UnrealModuleInfo {
  std::string name;
  std::string type = "Runtime";
  std::filesystem::path module_dir;
  std::filesystem::path build_cs_path;
  std::vector<std::filesystem::path> source_files;
  std::vector<std::string> tagged_functions;
};

struct UnrealProjectInfo {
  std::filesystem::path project_root;
  std::filesystem::path uproject_path;
  std::string project_name;
  std::string engine_association;
  std::vector<UnrealModuleInfo> modules;
  bool is_valid = false;
  std::string error_message;
};

// Checks whether the given directory contains an Unreal Engine project
bool IsUnrealProject(const std::filesystem::path& project_path);

// Finds the .uproject file in the specified directory
std::optional<std::filesystem::path> FindUProjectFile(const std::filesystem::path& project_path);

// Inspects and parses an Unreal Engine project structure
UnrealProjectInfo InspectUnrealProject(const std::filesystem::path& project_path);

// Injects RTProtect dependencies and include directories into an Unreal Module.Build.cs file
bool PatchUnrealBuildCs(const std::filesystem::path& build_cs_path,
                        const std::string& relative_rtprotect_dir = "RTProtect",
                        std::string* out_error = nullptr);

// Reverts RTProtect injections from a Module.Build.cs file
bool UnpatchUnrealBuildCs(const std::filesystem::path& build_cs_path,
                          std::string* out_error = nullptr);

// Checks if a Module.Build.cs file is already patched with RTProtect
bool IsUnrealBuildCsPatched(const std::filesystem::path& build_cs_path);

// Plans integration specifically for an Unreal Engine project
ChangePlan PlanUnrealIntegration(const IntegrationOptions& options);

// Executes integration on an Unreal Engine project
IntegrationReport ExecuteUnrealIntegration(const IntegrationOptions& options);

}  // namespace rtprotect::tooling
