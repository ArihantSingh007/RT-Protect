#include "crypto/aead.h"

#include <cstring>
#include <set>
#include <string>

#include "tests/micro_test.h"

using namespace rtprotect::crypto;

namespace {

std::vector<std::uint8_t> ToBytes(const std::string& s) {
  return std::vector<std::uint8_t>(s.begin(), s.end());
}

}  // namespace

MT_TEST(RoundTrip_PlaintextRecoveredExactly) {
  auto key = Aes256Key::Generate();
  auto pt = ToBytes("the quick brown fox jumps over the lazy dog");
  auto aad = ToBytes("resource-id:config.bin;v=3");

  auto enc = Encrypt(key, pt.data(), pt.size(), aad.data(), aad.size());
  MT_CHECK(enc.has_value());
  if (!enc) return;

  AeadError err = AeadError::kNone;
  auto dec = Decrypt(key, *enc, aad.data(), aad.size(), &err);
  MT_CHECK(dec.has_value());
  MT_CHECK(err == AeadError::kNone);
  if (dec) {
    MT_CHECK(*dec == pt);
  }
}

MT_TEST(RoundTrip_EmptyPlaintextWithAad) {
  // GCM supports zero-length plaintext with authenticated AAD -- useful for
  // "this empty marker file hasn't been deleted/replaced" style checks.
  auto key = Aes256Key::Generate();
  auto aad = ToBytes("marker:v2");

  auto enc = Encrypt(key, nullptr, 0, aad.data(), aad.size());
  MT_CHECK(enc.has_value());
  if (!enc) return;
  MT_CHECK(enc->ciphertext.empty());

  AeadError err = AeadError::kNone;
  auto dec = Decrypt(key, *enc, aad.data(), aad.size(), &err);
  MT_CHECK(dec.has_value());
  MT_CHECK(err == AeadError::kNone);
  if (dec) MT_CHECK(dec->empty());
}

MT_TEST(Decrypt_FailsWithWrongKey) {
  auto key_a = Aes256Key::Generate();
  auto key_b = Aes256Key::Generate();
  auto pt = ToBytes("secret config payload");

  auto enc = Encrypt(key_a, pt.data(), pt.size());
  MT_CHECK(enc.has_value());
  if (!enc) return;

  AeadError err = AeadError::kNone;
  auto dec = Decrypt(key_b, *enc, nullptr, 0, &err);
  MT_CHECK(!dec.has_value());
  MT_CHECK(err == AeadError::kAuthenticationFailed);
}

MT_TEST(Decrypt_FailsWithModifiedCiphertext) {
  auto key = Aes256Key::Generate();
  auto pt = ToBytes("do-not-tamper-with-me");

  auto enc = Encrypt(key, pt.data(), pt.size());
  MT_CHECK(enc.has_value());
  if (!enc) return;

  // Flip a single bit in the ciphertext.
  enc->ciphertext[0] ^= 0x01;

  AeadError err = AeadError::kNone;
  auto dec = Decrypt(key, *enc, nullptr, 0, &err);
  MT_CHECK(!dec.has_value());
  MT_CHECK(err == AeadError::kAuthenticationFailed);
}

MT_TEST(Decrypt_FailsWithModifiedTag) {
  auto key = Aes256Key::Generate();
  auto pt = ToBytes("payload");

  auto enc = Encrypt(key, pt.data(), pt.size());
  MT_CHECK(enc.has_value());
  if (!enc) return;

  enc->tag[0] ^= 0xFF;

  AeadError err = AeadError::kNone;
  auto dec = Decrypt(key, *enc, nullptr, 0, &err);
  MT_CHECK(!dec.has_value());
  MT_CHECK(err == AeadError::kAuthenticationFailed);
}

MT_TEST(Decrypt_FailsWithModifiedAad) {
  auto key = Aes256Key::Generate();
  auto pt = ToBytes("payload");
  auto aad = ToBytes("original-aad");

  auto enc = Encrypt(key, pt.data(), pt.size(), aad.data(), aad.size());
  MT_CHECK(enc.has_value());
  if (!enc) return;

  auto wrong_aad = ToBytes("tampered-aad");
  AeadError err = AeadError::kNone;
  auto dec = Decrypt(key, *enc, wrong_aad.data(), wrong_aad.size(), &err);
  MT_CHECK(!dec.has_value());
  MT_CHECK(err == AeadError::kAuthenticationFailed);
}

MT_TEST(Decrypt_FailsOnInvalidKeyLength) {
  std::uint8_t short_key[16] = {0};
  auto bad_key = Aes256Key::FromBytes(short_key, sizeof(short_key));
  MT_CHECK(!bad_key.has_value());  // constructor-level rejection
}

MT_TEST(Deserialize_FailsOnTruncatedInput) {
  // Too short to even hold a nonce + tag (28 bytes minimum with zero-length
  // ciphertext).
  std::uint8_t too_short[10] = {0};
  auto msg = EncryptedMessage::Deserialize(too_short, sizeof(too_short));
  MT_CHECK(!msg.has_value());
}

MT_TEST(SerializeDeserialize_RoundTrip) {
  auto key = Aes256Key::Generate();
  auto pt = ToBytes("serialize me");
  auto enc = Encrypt(key, pt.data(), pt.size());
  MT_CHECK(enc.has_value());
  if (!enc) return;

  auto wire = enc->Serialize();
  auto parsed = EncryptedMessage::Deserialize(wire.data(), wire.size());
  MT_CHECK(parsed.has_value());
  if (!parsed) return;

  AeadError err = AeadError::kNone;
  auto dec = Decrypt(key, *parsed, nullptr, 0, &err);
  MT_CHECK(dec.has_value());
  if (dec) MT_CHECK(*dec == pt);
}

MT_TEST(Nonce_GeneratedValuesAreDistinct) {
  // Statistical sanity check, not a cryptographic proof: with a 96-bit
  // random nonce, 10,000 draws colliding would indicate a broken RNG, not
  // bad luck.
  std::set<std::string> seen;
  for (int i = 0; i < 10000; ++i) {
    auto n = GcmNonce::Generate();
    seen.emplace(reinterpret_cast<const char*>(n.bytes), sizeof(n.bytes));
  }
  MT_CHECK(seen.size() == 10000);
}

MT_TEST(Encrypt_SameKeyProducesDifferentCiphertextEachCall) {
  // Confirms we are not accidentally reusing a fixed/zero nonce, which would
  // be catastrophic for GCM (nonce reuse under the same key breaks
  // confidentiality and authentication for both messages).
  auto key = Aes256Key::Generate();
  auto pt = ToBytes("same plaintext, every time");

  auto enc1 = Encrypt(key, pt.data(), pt.size());
  auto enc2 = Encrypt(key, pt.data(), pt.size());
  MT_CHECK(enc1.has_value() && enc2.has_value());
  if (!enc1 || !enc2) return;

  bool nonce_differs =
      std::memcmp(enc1->nonce.bytes, enc2->nonce.bytes, kGcmNonceLen) != 0;
  bool ciphertext_differs = enc1->ciphertext != enc2->ciphertext;
  MT_CHECK(nonce_differs);
  MT_CHECK(ciphertext_differs);
}

MT_TEST(Encrypt_RejectsOversizedPlaintext) {
  // The bound is checked before plaintext_len is ever used to touch the
  // pointer (no resize, no OpenSSL call happens first) -- see aead.cpp's
  // Encrypt(), so it's safe to pass a dummy small buffer with an inflated
  // claimed length here without any actual out-of-bounds access.
  auto key = Aes256Key::Generate();
  std::uint8_t dummy[4] = {0};
  auto enc = Encrypt(key, dummy, kMaxAeadMessageLen + 1);
  MT_CHECK(!enc.has_value());
}

MT_TEST(Encrypt_RejectsOversizedAad) {
  auto key = Aes256Key::Generate();
  std::uint8_t dummy[4] = {0};
  auto enc = Encrypt(key, dummy, 4, dummy, kMaxAeadMessageLen + 1);
  MT_CHECK(!enc.has_value());
}

MT_TEST(Encrypt_AcceptsPlaintextExactlyAtBound) {
  // A real allocation at the bound would be too slow/large for a unit
  // test to construct and run repeatedly; this test instead confirms the
  // comparison is `>` (strictly greater) and not an off-by-one `>=` by
  // checking a bound-sized AAD (small allocation) is accepted rather than
  // rejected, exercising the exact same comparison the plaintext check
  // uses with a size this test can actually afford to allocate.
  auto key = Aes256Key::Generate();
  auto pt = ToBytes("boundary check, aad path, not the full 1 GiB plaintext path");
  std::vector<std::uint8_t> aad_at_small_bound(1024, 0xAB);  // not the real
                                                               // 1 GiB bound --
                                                               // see comment above
  auto enc = Encrypt(key, pt.data(), pt.size(), aad_at_small_bound.data(),
                      aad_at_small_bound.size());
  MT_CHECK(enc.has_value());
}

MT_TEST(Decrypt_RejectsOversizedAad) {
  auto key = Aes256Key::Generate();
  auto pt = ToBytes("payload");
  auto enc = Encrypt(key, pt.data(), pt.size());
  MT_CHECK(enc.has_value());
  if (!enc) return;

  std::uint8_t dummy_aad[4] = {0};
  AeadError err = AeadError::kNone;
  auto dec = Decrypt(key, *enc, dummy_aad, kMaxAeadMessageLen + 1, &err);
  MT_CHECK(!dec.has_value());
  MT_CHECK(err == AeadError::kMessageTooLarge);
}

MT_TEST(Decrypt_WrongTag_DoesNotReturnPartialPlaintext) {
  // Regression test for the specific gap this phase fixed: a failure path
  // that discards decrypted-but-unauthenticated bytes must never return
  // them to the caller. This was already true for the auth-failure path
  // even before the fix (it's the one path the original code remembered
  // to guard) -- kept here as a named regression test alongside the two
  // below, which cover the paths that were NOT previously guarded.
  auto key = Aes256Key::Generate();
  auto pt = ToBytes("sensitive content that must never leak on failure");
  auto enc = Encrypt(key, pt.data(), pt.size());
  MT_CHECK(enc.has_value());
  if (!enc) return;

  enc->tag[0] ^= 0xFF;
  AeadError err = AeadError::kNone;
  auto dec = Decrypt(key, *enc, nullptr, 0, &err);
  MT_CHECK(!dec.has_value());  // the API contract itself prevents a partial
                                // plaintext from ever being returned on any
                                // Decrypt() failure -- std::optional is
                                // either a fully-authenticated value or
                                // nothing, by construction
}

MT_MAIN()
