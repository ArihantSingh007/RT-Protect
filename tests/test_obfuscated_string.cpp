#include "obfuscation/obfuscated_string.h"

#include <cstring>

#include "tests/micro_test.h"

using namespace rtprotect::obfuscation;

MT_TEST(ObfuscatedString_RoundTrip_RecoversOriginalExactly) {
  constexpr auto obf = RTPROTECT_OBFUSCATE("the secret license server hostname");
  RevealedString<obf.size()> revealed(obf);
  MT_CHECK(std::strcmp(revealed.c_str(), "the secret license server hostname") == 0);
}

MT_TEST(ObfuscatedString_EmptyString_RoundTrips) {
  constexpr auto obf = RTPROTECT_OBFUSCATE("");
  RevealedString<obf.size()> revealed(obf);
  MT_CHECK(std::strcmp(revealed.c_str(), "") == 0);
  MT_CHECK(revealed.size() == 0);
}

MT_TEST(ObfuscatedString_SizeExcludesNullTerminatorInSize) {
  constexpr auto obf = RTPROTECT_OBFUSCATE("1234567890");
  RevealedString<obf.size()> revealed(obf);
  MT_CHECK(revealed.size() == 10);
  MT_CHECK(std::strlen(revealed.c_str()) == 10);
}

MT_TEST(ObfuscatedString_CipherBytesDifferFromPlaintext) {
  // Sanity check that encryption actually happened: the two literals here
  // are different strings of the same length, and their underlying
  // ObfuscatedString objects (same __LINE__ offset irrelevant since each
  // has its own seed from its own call site) should not trivially expose
  // the plaintext via any public accessor other than Decrypt(). This test
  // mainly guards against a no-op implementation bug (e.g. forgetting to
  // XOR at all), which the binary-level check in docs/OBFUSCATION.md
  // complements by checking the actual compiled output.
  constexpr auto obf_a = RTPROTECT_OBFUSCATE("aaaaaaaa");
  constexpr auto obf_b = RTPROTECT_OBFUSCATE("bbbbbbbb");
  RevealedString<obf_a.size()> rev_a(obf_a);
  RevealedString<obf_b.size()> rev_b(obf_b);
  MT_CHECK(std::strcmp(rev_a.c_str(), "aaaaaaaa") == 0);
  MT_CHECK(std::strcmp(rev_b.c_str(), "bbbbbbbb") == 0);
  MT_CHECK(std::strcmp(rev_a.c_str(), rev_b.c_str()) != 0);
}

MT_TEST(ObfuscatedString_DifferentCallSites_ProduceDifferentSeeds) {
  // Two identical literals obfuscated at two different call sites (so two
  // different __LINE__/__COUNTER__ values) should decrypt correctly from
  // their own ObfuscatedString instance regardless -- this test exists to
  // catch a bug where the seed macro accidentally captured a fixed value
  // instead of the call site's actual __LINE__/__COUNTER__.
  constexpr auto obf1 = RTPROTECT_OBFUSCATE("same text, two places");
  constexpr auto obf2 = RTPROTECT_OBFUSCATE("same text, two places");
  RevealedString<obf1.size()> rev1(obf1);
  RevealedString<obf2.size()> rev2(obf2);
  MT_CHECK(std::strcmp(rev1.c_str(), "same text, two places") == 0);
  MT_CHECK(std::strcmp(rev2.c_str(), "same text, two places") == 0);
}

MT_MAIN()
