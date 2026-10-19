// tests/micro_test.h
//
// A deliberately tiny test harness: no external dependency, just enough to
// register named test cases, run them, and report pass/fail with a
// non-zero exit code on failure (so `ctest` / CI can key off it). This is
// not meant to grow into a general framework -- if the project later needs
// more, bring in Catch2 or GoogleTest rather than extending this file.

#pragma once

#include <cstdio>
#include <cstdlib>
#include <functional>
#include <string>
#include <vector>

namespace micro_test {

struct TestCase {
  std::string name;
  std::function<void()> fn;
};

inline std::vector<TestCase>& Registry() {
  static std::vector<TestCase> registry;
  return registry;
}

struct Registrar {
  Registrar(const std::string& name, std::function<void()> fn) {
    Registry().push_back({name, std::move(fn)});
  }
};

inline int failures = 0;
inline std::string current_test;

inline int RunAll() {
  int passed = 0;
  for (auto& tc : Registry()) {
    current_test = tc.name;
    int failures_before = failures;
    std::printf("[ RUN      ] %s\n", tc.name.c_str());
    std::fflush(stdout);
    tc.fn();
    if (failures == failures_before) {
      std::printf("[       OK ] %s\n", tc.name.c_str());
      ++passed;
    } else {
      std::printf("[  FAILED  ] %s\n", tc.name.c_str());
    }
  }
  std::printf("---- %d/%zu tests passed ----\n", passed, Registry().size());
  return failures == 0 ? 0 : 1;
}

}  // namespace micro_test

#define MT_TEST(name)                                                   \
  void name();                                                          \
  static micro_test::Registrar registrar_##name(#name, name);           \
  void name()

#define MT_CHECK(cond)                                                  \
  do {                                                                  \
    if (!(cond)) {                                                      \
      std::printf("  CHECK FAILED at %s:%d: %s\n", __FILE__, __LINE__,  \
                   #cond);                                              \
      ++micro_test::failures;                                           \
    }                                                                   \
  } while (0)

#define MT_MAIN()                                                       \
  int main() { return micro_test::RunAll(); }
