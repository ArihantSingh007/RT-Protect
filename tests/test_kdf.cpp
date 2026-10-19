#include "crypto/kdf.h"

#include <cstring>
#include <vector>

#include "tests/micro_test.h"

using namespace rtprotect::crypto;

namespace {

std::vector<std::uint8_t> HexToBytes(const std::string& hex) {
  std::vector<std::uint8_t> out;
  out.reserve(hex.size() / 2);
  for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
    out.push_back(static_cast<std::uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
  }
  return out;
}

std::string BytesToHex(const std::uint8_t* data, std::size_t len) {
  static const char* kHex = "0123456789abcdef";
  std::string out;
  out.reserve(len * 2);
  for (std::size_t i = 0; i < len; ++i) {
    out.push_back(kHex[(data[i] >> 4) & 0xF]);
    out.push_back(kHex[data[i] & 0xF]);
  }
  return out;
}

}  // namespace

// ---------------------------------------------------------------------
// RFC 5869 HKDF-SHA256 known-answer tests (Appendix A, Test Cases 1 and
// 3). These exact IKM/salt/info/L inputs and expected OKM outputs are
// taken from the published RFC text
// (https://www.rfc-editor.org/rfc/rfc5869, fetched and cross-checked
// directly against this project's Hkdf::DeriveKey before being written
// here as permanent tests -- not transcribed from memory and trusted).
// Test Case 3 specifically exercises empty salt AND empty info together,
// which is the exact input shape a prior review flagged as a possible
// empty-container-handling risk (see kdf.cpp's kEmptyOctetStringSentinel)
// -- this is the test that would catch a regression there, not merely a
// generic "empty salt is accepted" smoke test.
// ---------------------------------------------------------------------

MT_TEST(Hkdf_RFC5869_TestCase1_BasicWithSaltAndInfo) {
  auto ikm = HexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
  SecureBuffer secret(ikm.data(), ikm.size());
  auto salt = HexToBytes("000102030405060708090a0b0c");
  auto info_bytes = HexToBytes("f0f1f2f3f4f5f6f7f8f9");
  std::string info(reinterpret_cast<char*>(info_bytes.data()), info_bytes.size());

  auto okm = Hkdf::DeriveKey(secret, salt, info, 42);
  MT_CHECK(okm.has_value());
  if (!okm) return;
  MT_CHECK(okm->size() == 42);

  std::string expected =
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
  MT_CHECK(BytesToHex(okm->data(), okm->size()) == expected);
}

MT_TEST(Hkdf_RFC5869_TestCase3_EmptySaltAndEmptyInfo) {
  auto ikm = HexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
  SecureBuffer secret(ikm.data(), ikm.size());
  std::vector<std::uint8_t> empty_salt;
  std::string empty_info;

  auto okm = Hkdf::DeriveKey(secret, empty_salt, empty_info, 42);
  MT_CHECK(okm.has_value());
  if (!okm) return;
  MT_CHECK(okm->size() == 42);

  std::string expected =
      "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8";
  MT_CHECK(BytesToHex(okm->data(), okm->size()) == expected);
}

MT_TEST(Hkdf_DeterministicForSameInputs) {
  SecureBuffer secret(reinterpret_cast<const std::uint8_t*>("master-secret-material"), 23);
  std::vector<std::uint8_t> salt = {1, 2, 3, 4};

  auto k1 = Hkdf::DeriveKey(secret, salt, "rtprotect/test/v1", 32);
  auto k2 = Hkdf::DeriveKey(secret, salt, "rtprotect/test/v1", 32);
  MT_CHECK(k1.has_value() && k2.has_value());
  if (!k1 || !k2) return;

  MT_CHECK(k1->size() == 32 && k2->size() == 32);
  MT_CHECK(std::equal(k1->data(), k1->data() + 32, k2->data()));
}

MT_TEST(Hkdf_DifferentInfoProducesDifferentKeys) {
  // This is the whole point of the `info` parameter: one master secret must
  // be safely usable to derive many independent-looking keys.
  SecureBuffer secret(reinterpret_cast<const std::uint8_t*>("master-secret-material"), 23);
  std::vector<std::uint8_t> salt = {1, 2, 3, 4};

  auto k_resource = Hkdf::DeriveKey(secret, salt, "rtprotect/resource-key/v1", 32);
  auto k_session = Hkdf::DeriveKey(secret, salt, "rtprotect/session-key/v1", 32);
  MT_CHECK(k_resource.has_value() && k_session.has_value());
  if (!k_resource || !k_session) return;

  MT_CHECK(!std::equal(k_resource->data(), k_resource->data() + 32, k_session->data()));
}

MT_TEST(Hkdf_DifferentSaltProducesDifferentKeys) {
  SecureBuffer secret(reinterpret_cast<const std::uint8_t*>("master-secret-material"), 23);

  auto k1 = Hkdf::DeriveKey(secret, {1, 2, 3}, "rtprotect/test/v1", 32);
  auto k2 = Hkdf::DeriveKey(secret, {9, 9, 9}, "rtprotect/test/v1", 32);
  MT_CHECK(k1.has_value() && k2.has_value());
  if (!k1 || !k2) return;

  MT_CHECK(!std::equal(k1->data(), k1->data() + 32, k2->data()));
}

MT_TEST(Hkdf_SupportsArbitraryOutputLength) {
  SecureBuffer secret(reinterpret_cast<const std::uint8_t*>("secret"), 6);
  auto k16 = Hkdf::DeriveKey(secret, {}, "info", 16);
  auto k64 = Hkdf::DeriveKey(secret, {}, "info", 64);
  MT_CHECK(k16.has_value() && k16->size() == 16);
  MT_CHECK(k64.has_value() && k64->size() == 64);
}

// ---------------------------------------------------------------------
// Invalid-input handling
// ---------------------------------------------------------------------

MT_TEST(Hkdf_RejectsZeroOutputLength) {
  SecureBuffer secret(reinterpret_cast<const std::uint8_t*>("secret"), 6);
  auto result = Hkdf::DeriveKey(secret, {}, "info", 0);
  MT_CHECK(!result.has_value());
}

MT_TEST(Hkdf_AcceptsOutputLengthExactlyAtMaximum) {
  SecureBuffer secret(reinterpret_cast<const std::uint8_t*>("secret"), 6);
  auto result = Hkdf::DeriveKey(secret, {}, "info", kMaxHkdfOutputLen);
  MT_CHECK(result.has_value());
  if (result) MT_CHECK(result->size() == kMaxHkdfOutputLen);
}

MT_TEST(Hkdf_RejectsOutputLengthOneOverMaximum) {
  // RFC 5869 Sec. 2.3's documented HKDF-SHA256 maximum is 255 * 32 = 8160
  // bytes -- requesting one byte more must fail, not silently truncate or
  // succeed with a shorter-than-requested key.
  SecureBuffer secret(reinterpret_cast<const std::uint8_t*>("secret"), 6);
  auto result = Hkdf::DeriveKey(secret, {}, "info", kMaxHkdfOutputLen + 1);
  MT_CHECK(!result.has_value());
}

MT_TEST(Hkdf_EmptySecret_HandledWithoutCrash) {
  // An empty IKM is unusual but not forbidden by RFC 5869 (the extract
  // step just HMACs zero bytes) -- this must not crash or misbehave, even
  // if it's not a pattern this project's own callers are expected to use.
  SecureBuffer empty_secret(static_cast<std::size_t>(0));
  auto result = Hkdf::DeriveKey(empty_secret, {1, 2, 3}, "info", 32);
  MT_CHECK(result.has_value());  // RFC 5869 permits this; OpenSSL's HKDF
                                  // accepts a zero-length IKM
}

MT_MAIN()
