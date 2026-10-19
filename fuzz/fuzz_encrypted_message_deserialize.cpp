// fuzz/fuzz_encrypted_message_deserialize.cpp
//
// libFuzzer harness for crypto::EncryptedMessage::Deserialize() -- the
// entry point for untrusted bytes (any file claiming to be an rtprotect
// encrypted blob) becoming a structured EncryptedMessage, before any
// AEAD decryption is attempted. See this directory's README.md for build
// instructions and the standing gap in this environment.
//
// This harness deliberately does NOT also call crypto::Decrypt() on the
// result: Decrypt() requires a valid 32-byte key, which this harness has
// no way to supply meaningfully from a single untrusted byte stream
// without either fixing a key (testing nothing about key-dependent
// behavior) or implausibly trying to carve a key out of the fuzzer's
// input (testing a key-selection harness bug, not Decrypt() itself).
// Deserialize()'s own parsing -- length handling, the nonce/tag/
// ciphertext split -- is what this harness exercises; crypto/aead.cpp's
// Encrypt/Decrypt functions are already covered by tests/test_aead.cpp's
// extensive hand-written boundary cases (empty inputs, oversized lengths,
// tampered ciphertext/tag, wrong key) rather than needing a fuzz harness
// of their own to get meaningful coverage of a much smaller, better-
// understood input space (a fixed-format AEAD call, not a
// variable-length untrusted parser).

#include <cstdint>
#include <cstddef>

#include "crypto/aead.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  auto result = rtprotect::crypto::EncryptedMessage::Deserialize(data, size);
  (void)result;
  return 0;
}
