// obfuscation/demo/obfuscated_secret_demo.cpp
//
// Treatment binary for docs/OBFUSCATION.md's empirical check: prints the
// SAME marker string as plain_secret_demo.cpp, but via
// obfuscation/obfuscated_string.h. Compiled with identical flags to
// plain_secret_demo.cpp. docs/OBFUSCATION.md records the actual `strings`
// output comparing the two binaries -- see that doc for the real,
// as-run result rather than an assumed one.

#include <cstdio>

#include "obfuscation/obfuscated_string.h"

int main() {
  constexpr auto obf = RTPROTECT_OBFUSCATE("RTPROTECT_DEMO_MARKER_PHRASE_f7a2c9");
  rtprotect::obfuscation::RevealedString<obf.size()> revealed(obf);
  std::puts(revealed.c_str());
  return 0;
}
