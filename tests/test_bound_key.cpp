// tests/test_bound_key.cpp
//
// Proves the fix described in integrity/bound_key.h actually closes the
// bypass scenario it claims to: swapping in a different, validly-encrypted
// resource (e.g. an older release's blob) fails via AEAD authentication
// alone -- with NO separate hash-comparison function called anywhere in
// this test. If someone reintroduced a boolean "if hash mismatch, reject"
// gate as the only protection (the pattern this fix replaces), a test
// shaped like this would need to call that function to catch the
// substitution; this test deliberately never does, so it only passes if
// the cryptographic binding itself is doing the work.

#include "integrity/bound_key.h"

#include <string>

#include "tests/micro_test.h"

using namespace rtprotect;

MT_TEST(BoundKey_CorrectManifestAndResource_RoundTrips) {
  auto master = crypto::Aes256Key::Generate();
  std::string plaintext = "release A's actual payload bytes";
  auto hash = integrity::Sha256(reinterpret_cast<const std::uint8_t*>(plaintext.data()),
                                 plaintext.size());
  MT_CHECK(hash.has_value());
  if (!hash) return;

  auto key = integrity::DeriveBoundResourceKey(master, *hash, "payload");
  auto enc = crypto::Encrypt(key, reinterpret_cast<const std::uint8_t*>(plaintext.data()),
                              plaintext.size());
  MT_CHECK(enc.has_value());
  if (!enc) return;

  // Re-derive independently (simulating a fresh runtime call, not reusing
  // the `key` variable) -- this is the actual call pattern a caller uses.
  auto key_again = integrity::DeriveBoundResourceKey(master, *hash, "payload");
  crypto::AeadError err = crypto::AeadError::kNone;
  auto dec = crypto::Decrypt(key_again, *enc, nullptr, 0, &err);
  MT_CHECK(dec.has_value());
  MT_CHECK(err == crypto::AeadError::kNone);
  if (dec) {
    std::string result(dec->begin(), dec->end());
    MT_CHECK(result == plaintext);
  }
}

MT_TEST(BoundKey_SwappedOlderRelease_FailsViaAeadAlone_NoHashCheckCalled) {
  // THE actual bypass scenario from the reported vulnerability: an
  // attacker has release A's signed manifest (unmodified, still claims
  // release A's hash) but swaps in release B's blob -- itself perfectly
  // validly AEAD-encrypted, just under a different key, because it's a
  // different release's content.
  auto master = crypto::Aes256Key::Generate();

  std::string plaintext_a = "release A payload";
  std::string plaintext_b = "release B payload (different content)";

  auto hash_a = integrity::Sha256(reinterpret_cast<const std::uint8_t*>(plaintext_a.data()),
                                   plaintext_a.size());
  auto hash_b = integrity::Sha256(reinterpret_cast<const std::uint8_t*>(plaintext_b.data()),
                                   plaintext_b.size());
  MT_CHECK(hash_a.has_value() && hash_b.has_value());
  if (!hash_a || !hash_b) return;

  auto key_a = integrity::DeriveBoundResourceKey(master, *hash_a, "payload");
  auto key_b = integrity::DeriveBoundResourceKey(master, *hash_b, "payload");

  auto enc_b = crypto::Encrypt(key_b, reinterpret_cast<const std::uint8_t*>(plaintext_b.data()),
                                plaintext_b.size());
  MT_CHECK(enc_b.has_value());
  if (!enc_b) return;

  // The runtime trusts release A's (correctly signed, unmodified) manifest,
  // derives key_a from IT, and attempts to decrypt whatever blob is
  // actually present on disk -- which an attacker has swapped for
  // release B's blob. No hash-comparison function is called anywhere in
  // this test -- key derivation alone must be what causes this to fail.
  crypto::AeadError err = crypto::AeadError::kNone;
  auto dec = crypto::Decrypt(key_a, *enc_b, nullptr, 0, &err);
  MT_CHECK(!dec.has_value());
  MT_CHECK(err == crypto::AeadError::kAuthenticationFailed);
}

MT_TEST(BoundKey_DifferentResourceNames_ProduceDifferentKeys) {
  auto master = crypto::Aes256Key::Generate();
  std::string plaintext = "shared content, different manifest entries";
  auto hash = integrity::Sha256(reinterpret_cast<const std::uint8_t*>(plaintext.data()),
                                 plaintext.size());
  MT_CHECK(hash.has_value());
  if (!hash) return;

  auto key_cfg = integrity::DeriveBoundResourceKey(master, *hash, "config.bin");
  auto key_lic = integrity::DeriveBoundResourceKey(master, *hash, "license.bin");

  // Same master secret, same hash, different resource name -> different
  // keys. Proven by cross-decryption failing: content encrypted for
  // "config.bin" must not decrypt under "license.bin"'s derived key.
  auto enc = crypto::Encrypt(key_cfg, reinterpret_cast<const std::uint8_t*>(plaintext.data()),
                              plaintext.size());
  MT_CHECK(enc.has_value());
  if (!enc) return;

  crypto::AeadError err = crypto::AeadError::kNone;
  auto dec = crypto::Decrypt(key_lic, *enc, nullptr, 0, &err);
  MT_CHECK(!dec.has_value());
  MT_CHECK(err == crypto::AeadError::kAuthenticationFailed);
}

MT_TEST(BoundKey_DifferentMasterSecrets_ProduceDifferentKeys) {
  auto master_1 = crypto::Aes256Key::Generate();
  auto master_2 = crypto::Aes256Key::Generate();
  std::string plaintext = "x";
  auto hash =
      integrity::Sha256(reinterpret_cast<const std::uint8_t*>(plaintext.data()), plaintext.size());
  MT_CHECK(hash.has_value());
  if (!hash) return;

  auto key_1 = integrity::DeriveBoundResourceKey(master_1, *hash, "r");
  auto key_2 = integrity::DeriveBoundResourceKey(master_2, *hash, "r");

  auto enc = crypto::Encrypt(key_1, reinterpret_cast<const std::uint8_t*>(plaintext.data()),
                              plaintext.size());
  MT_CHECK(enc.has_value());
  if (!enc) return;

  crypto::AeadError err = crypto::AeadError::kNone;
  auto dec = crypto::Decrypt(key_2, *enc, nullptr, 0, &err);
  MT_CHECK(!dec.has_value());
  MT_CHECK(err == crypto::AeadError::kAuthenticationFailed);
}

MT_MAIN()
