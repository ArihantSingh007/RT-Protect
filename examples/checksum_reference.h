// examples/checksum_reference.h
//
// Native C++ implementation of the digit-based checksum used as Phase 3's
// demonstrative "protected function". This file exists ONLY so tests can
// assert the bytecode-VM version produces identical output to a trusted
// reference across many inputs -- it is NOT part of the protected runtime
// path and ships with no obfuscation or encryption. In a real deployment,
// only the bytecode form (examples/checksum_program.h) and its encrypted
// blob would ship; this native version would stay out of the distributed
// binary entirely once parity is established.
//
// What the function computes (deliberately simple, deliberately NOT a real
// cryptographic checksum -- see docs/THREAT_MODEL.md for why no amount of
// VM protection turns a weak checksum into a strong one):
//
//   acc = 0
//   while (x != 0) {
//     acc = (acc * 31 + (x % 10)) % 1000000007
//     x = x / 10
//   }
//   return acc

#pragma once

#include <cstdint>

namespace rtprotect::examples {

inline std::int64_t NativeChecksum(std::int64_t x) {
  std::int64_t acc = 0;
  while (x != 0) {
    std::int64_t digit = x % 10;
    acc = (acc * 31 + digit) % 1000000007;
    x = x / 10;
  }
  return acc;
}

}  // namespace rtprotect::examples
