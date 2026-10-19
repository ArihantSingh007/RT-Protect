// obfuscation/demo/plain_secret_demo.cpp
//
// Control binary for docs/OBFUSCATION.md's empirical check: prints a
// marker string using an ordinary, un-obfuscated string literal. Compiled
// with the same flags as obfuscated_secret_demo.cpp so the two binaries
// are a fair comparison. This binary is EXPECTED to leak the marker string
// in its compiled output -- that's the baseline the obfuscated version is
// compared against.

#include <cstdio>

int main() {
  const char* secret = "RTPROTECT_DEMO_MARKER_PHRASE_f7a2c9";
  std::puts(secret);
  return 0;
}
