#include "runtime/reconstructed_function.h"

#include "tests/micro_test.h"

using namespace rtprotect;

MT_TEST(Reconstructed_EncryptedRoundTrip_CorrectValueForValidKey) {
  auto key = crypto::Aes256Key::Generate();
  auto blob = runtime::BuildEncryptedPayloadBlob(key);

  std::int64_t inputs[] = {-1000, -1, 0, 1, 7, 42, 1000000};
  for (std::int64_t x : inputs) {
    auto result = runtime::CallReconstructedFunction(key, blob, x);
    MT_CHECK(result.error == runtime::ReconstructedCallError::kNone);
    MT_CHECK(result.value == runtime::NativeReference(x));
  }
}

MT_TEST(Reconstructed_RejectsWrongKey) {
  auto key_a = crypto::Aes256Key::Generate();
  auto key_b = crypto::Aes256Key::Generate();
  auto blob = runtime::BuildEncryptedPayloadBlob(key_a);

  auto result = runtime::CallReconstructedFunction(key_b, blob, 10);
  MT_CHECK(result.error == runtime::ReconstructedCallError::kDecryptionFailed);
}

MT_TEST(Reconstructed_RejectsTamperedCiphertext) {
  auto key = crypto::Aes256Key::Generate();
  auto blob = runtime::BuildEncryptedPayloadBlob(key);

  MT_CHECK(blob.size() > crypto::kGcmNonceLen + crypto::kGcmTagLen);
  std::size_t mid = blob.size() / 2;
  blob[mid] ^= 0x01;

  auto result = runtime::CallReconstructedFunction(key, blob, 10);
  MT_CHECK(result.error == runtime::ReconstructedCallError::kDecryptionFailed);
}

MT_TEST(Reconstructed_RejectsTruncatedBlob) {
  auto key = crypto::Aes256Key::Generate();
  auto blob = runtime::BuildEncryptedPayloadBlob(key);
  blob.resize(4);

  auto result = runtime::CallReconstructedFunction(key, blob, 10);
  MT_CHECK(result.error == runtime::ReconstructedCallError::kDecryptionFailed);
}

MT_TEST(Reconstructed_RejectsCorrectlyAuthenticatedButWrongSizedPayload) {
  // Builds a blob the SAME key correctly authenticates (it's not forged or
  // tampered -- AEAD authentication succeeds), but containing bytes of the
  // wrong length to be native_payload.h's payload. This is the specific
  // defense-in-depth check reconstructed_function.h's header describes:
  // "authenticated" must not be treated as a substitute for "is the one
  // reviewed payload," and this test is what proves that check actually
  // fires rather than just being asserted in a comment.
  auto key = crypto::Aes256Key::Generate();
  std::vector<std::uint8_t> wrong_size_payload = {0xC3, 0xC3, 0xC3};  // 3 bytes,
                                                                        // not 6
  auto enc = crypto::Encrypt(key, wrong_size_payload.data(), wrong_size_payload.size());
  MT_CHECK(enc.has_value());
  if (!enc) return;
  auto blob = enc->Serialize();

  auto result = runtime::CallReconstructedFunction(key, blob, 10);
  MT_CHECK(result.error == runtime::ReconstructedCallError::kUnexpectedPayloadSize);
}

MT_MAIN()
