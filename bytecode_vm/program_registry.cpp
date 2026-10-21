// bytecode_vm/program_registry.cpp

#include "bytecode_vm/program_registry.h"

namespace rtprotect::vm {

namespace {

std::mutex g_registry_mu;
std::unordered_map<std::uint16_t, Program> g_registry;

}  // namespace

void ProgramRegistry::Register(std::uint16_t id, Program program) {
  std::lock_guard<std::mutex> lock(g_registry_mu);
  g_registry[id] = std::move(program);
}

const Program* ProgramRegistry::Get(std::uint16_t id) {
  std::lock_guard<std::mutex> lock(g_registry_mu);
  auto it = g_registry.find(id);
  if (it == g_registry.end()) return nullptr;
  return &it->second;
}

void ProgramRegistry::Clear() {
  std::lock_guard<std::mutex> lock(g_registry_mu);
  g_registry.clear();
}

}  // namespace rtprotect::vm
