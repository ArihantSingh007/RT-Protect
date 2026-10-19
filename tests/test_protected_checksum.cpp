#include "examples/checksum_program.h"
#include "examples/checksum_reference.h"
#include "examples/protected_checksum.h"

#include "tests/micro_test.h"

using namespace rtprotect;

MT_TEST(Checksum_VmMatchesNativeReference_UnencryptedBytecode) {
  // Direct VM execution (no encryption layer) against the native reference,
  // across a range of inputs including edge cases.
  auto program = examples::BuildChecksumProgram();

  std::vector<std::int64_t> inputs = {
      0, 1, 9, 10, 123, 999999999, 1000000000, 7, 42, 2147483647,
  };

  for (std::int64_t x : inputs) {
    auto run = vm::Run(program, {x});
    MT_CHECK(run.error == vm::VmError::kNone);
    std::int64_t expected = examples::NativeChecksum(x);
    MT_CHECK(run.value == expected);
  }
}

MT_TEST(Checksum_EncryptedRoundTrip_CorrectValueForValidKey) {
  auto key = crypto::Aes256Key::Generate();
  auto blob = examples::BuildEncryptedChecksumBlob(key);

  std::vector<std::int64_t> inputs = {0, 5, 123456789, 987654321};
  for (std::int64_t x : inputs) {
    auto result = examples::CallProtectedChecksum(key, blob, x);
    MT_CHECK(result.error == examples::ProtectedCallError::kNone);
    MT_CHECK(result.value == examples::NativeChecksum(x));
  }
}

MT_TEST(Checksum_EncryptedBlob_RejectsWrongKey) {
  auto key_a = crypto::Aes256Key::Generate();
  auto key_b = crypto::Aes256Key::Generate();
  auto blob = examples::BuildEncryptedChecksumBlob(key_a);

  auto result = examples::CallProtectedChecksum(key_b, blob, 42);
  MT_CHECK(result.error == examples::ProtectedCallError::kDecryptionFailed);
}

MT_TEST(Checksum_EncryptedBlob_RejectsTamperedCiphertext) {
  auto key = crypto::Aes256Key::Generate();
  auto blob = examples::BuildEncryptedChecksumBlob(key);

  // Flip a byte somewhere in the middle of the ciphertext (past the 12-byte
  // nonce prefix, before the final 16-byte tag).
  MT_CHECK(blob.size() > crypto::kGcmNonceLen + crypto::kGcmTagLen + 1);
  std::size_t mid = blob.size() / 2;
  blob[mid] ^= 0x01;

  auto result = examples::CallProtectedChecksum(key, blob, 42);
  MT_CHECK(result.error == examples::ProtectedCallError::kDecryptionFailed);
}

MT_TEST(Checksum_EncryptedBlob_RejectsTruncatedBlob) {
  auto key = crypto::Aes256Key::Generate();
  auto blob = examples::BuildEncryptedChecksumBlob(key);
  blob.resize(5);  // nowhere near enough for nonce + tag

  auto result = examples::CallProtectedChecksum(key, blob, 42);
  MT_CHECK(result.error == examples::ProtectedCallError::kDecryptionFailed);
}

// ---------------------------------------------------------------------
// Fully-integrated pipeline (CallProtectedChecksumVerified): signed
// manifest + bound-key encryption, closing the wholesale-blob-substitution
// gap the original CallProtectedChecksum() pipeline left open. See
// examples/protected_checksum.h's header comment and
// integrity/bound_key.h for the design.
// ---------------------------------------------------------------------

MT_TEST(VerifiedChecksum_FullPipeline_CorrectValueForValidEverything) {
  auto master_secret = crypto::Aes256Key::Generate();
  auto signing_keypair = integrity::GenerateEd25519KeyPair();
  MT_CHECK(signing_keypair.has_value());
  if (!signing_keypair) return;

  auto release = examples::BuildVerifiedChecksumRelease(master_secret, signing_keypair->private_key,
                                                          "1.0.0");

  std::vector<std::int64_t> inputs = {0, 5, 123456789, 987654321};
  for (std::int64_t x : inputs) {
    auto result = examples::CallProtectedChecksumVerified(
        release.manifest_bytes, release.signature, signing_keypair->public_key, master_secret,
        release.encrypted_blob, x);
    MT_CHECK(result.error == examples::VerifiedCallError::kNone);
    MT_CHECK(result.value == examples::NativeChecksum(x));
  }
}

MT_TEST(VerifiedChecksum_RejectsUntrustedPublicKey) {
  // The core property this test is for: a DIFFERENT, attacker-controlled
  // keypair cannot forge a signature the trusted public key will accept --
  // the manifest signature check happens against trusted_public_key, which
  // the caller supplies from its own trusted source, never from anything
  // bundled alongside the manifest/blob under test.
  auto master_secret = crypto::Aes256Key::Generate();
  auto legit_keypair = integrity::GenerateEd25519KeyPair();
  auto attacker_keypair = integrity::GenerateEd25519KeyPair();
  MT_CHECK(legit_keypair.has_value() && attacker_keypair.has_value());
  if (!legit_keypair || !attacker_keypair) return;

  // Attacker signs their OWN manifest/blob with their OWN key.
  auto attacker_release = examples::BuildVerifiedChecksumRelease(
      master_secret, attacker_keypair->private_key, "1.0.0-attacker");

  // Verified against the LEGITIMATE public key, not the attacker's.
  auto result = examples::CallProtectedChecksumVerified(
      attacker_release.manifest_bytes, attacker_release.signature, legit_keypair->public_key,
      master_secret, attacker_release.encrypted_blob, 42);
  MT_CHECK(result.error == examples::VerifiedCallError::kManifestSignatureInvalid);
}

MT_TEST(VerifiedChecksum_RejectsWholesaleBlobSubstitutionFromAnotherRelease) {
  // THE scenario integrity/bound_key.h's design exists for: a DIFFERENT
  // release's encrypted blob -- itself perfectly validly encrypted and
  // internally consistent -- substituted in place of the current
  // release's blob, while the CURRENT release's signed manifest is left
  // in place.
  //
  // This test's first version used examples::BuildVerifiedChecksumRelease()
  // for BOTH "releases" and found they didn't trigger the rejection --
  // investigated rather than assumed a bug in the implementation, and
  // found the real reason: BuildChecksumProgram() is a parameterless,
  // deterministic function, so both calls produced byte-IDENTICAL
  // plaintext bytecode, hence an identical manifest-pinned hash, hence an
  // identical derived key for both "releases." Swapping between two
  // blobs that are both validly encrypted under the SAME derived key
  // isn't actually a meaningful substitution in the first place (the
  // client would run the exact same program either way) -- so the original
  // test's premise was wrong, not the fix. This version constructs a
  // second "release" with genuinely DIFFERENT resource content by hand
  // (not through BuildVerifiedChecksumRelease, which always uses the one
  // fixed checksum program), so the two releases' pinned hashes --and
  // therefore their derived keys -- actually differ, which is what makes
  // this a real test of cross-release substitution rejection rather than
  // an accidentally-vacuous one.
  auto master_secret = crypto::Aes256Key::Generate();
  auto signing_keypair = integrity::GenerateEd25519KeyPair();
  MT_CHECK(signing_keypair.has_value());
  if (!signing_keypair) return;

  // Release A: the real pipeline, via BuildVerifiedChecksumRelease.
  auto release_a = examples::BuildVerifiedChecksumRelease(master_secret, signing_keypair->private_key,
                                                            "1.0.0");

  // Release B: a DIFFERENT resource, built by hand to guarantee different
  // content (and therefore a different pinned hash and derived key) from
  // release A -- simulating "a different release's own, otherwise valid,
  // bound-key-encrypted blob."
  std::string different_content = "a completely different resource's plaintext bytes";
  integrity::Manifest manifest_b;
  manifest_b.release_version = "2.0.0";
  MT_CHECK(manifest_b.AddResource(examples::kChecksumResourceName,
                                   reinterpret_cast<const std::uint8_t*>(different_content.data()),
                                   different_content.size()));
  const integrity::ResourceEntry* entry_b = manifest_b.Find(examples::kChecksumResourceName);
  MT_CHECK(entry_b != nullptr);
  if (!entry_b) return;
  auto key_b = integrity::DeriveBoundResourceKey(master_secret, entry_b->sha256,
                                                  examples::kChecksumResourceName);
  auto enc_b = crypto::Encrypt(key_b, reinterpret_cast<const std::uint8_t*>(different_content.data()),
                                different_content.size());
  MT_CHECK(enc_b.has_value());
  if (!enc_b) return;
  auto blob_b = enc_b->Serialize();

  // Confirm the premise this test actually depends on: release A's pinned
  // hash and release B's pinned hash are genuinely different (unlike the
  // first version of this test, see the comment above).
  //
  // The deserialized Manifest is bound to a named local here, not used as
  // a temporary with Find() chained directly off it -- an earlier version
  // of this test did exactly that (`DeserializeManifest(...)->Find(...)`)
  // and got a dangling pointer into the temporary std::optional<Manifest>,
  // which is destroyed at the end of that full expression: entry_a would
  // point into already-freed memory for every line after it. Caught by
  // AddressSanitizer (a real heap-use-after-free, not a hypothetical one)
  // when this test was run under the project's sanitizer build -- exactly
  // what that build configuration exists to catch, including in test code
  // itself, not only in the library being tested.
  auto manifest_a =
      integrity::DeserializeManifest(release_a.manifest_bytes.data(), release_a.manifest_bytes.size());
  MT_CHECK(manifest_a.has_value());
  if (!manifest_a) return;
  const integrity::ResourceEntry* entry_a = manifest_a->Find(examples::kChecksumResourceName);
  MT_CHECK(entry_a != nullptr);
  if (entry_a) MT_CHECK(entry_a->sha256 != entry_b->sha256);

  // Use release A's manifest/signature (pinning release A's hash), but
  // substitute release B's encrypted blob.
  auto result = examples::CallProtectedChecksumVerified(
      release_a.manifest_bytes, release_a.signature, signing_keypair->public_key, master_secret,
      blob_b, 42);
  MT_CHECK(result.error == examples::VerifiedCallError::kDecryptionFailed);
}

MT_TEST(VerifiedChecksum_RejectsTamperedManifest) {
  auto master_secret = crypto::Aes256Key::Generate();
  auto signing_keypair = integrity::GenerateEd25519KeyPair();
  MT_CHECK(signing_keypair.has_value());
  if (!signing_keypair) return;

  auto release = examples::BuildVerifiedChecksumRelease(master_secret, signing_keypair->private_key,
                                                          "1.0.0");
  auto tampered_manifest = release.manifest_bytes;
  tampered_manifest[tampered_manifest.size() / 2] ^= 0x01;

  auto result = examples::CallProtectedChecksumVerified(
      tampered_manifest, release.signature, signing_keypair->public_key, master_secret,
      release.encrypted_blob, 42);
  MT_CHECK(result.error == examples::VerifiedCallError::kManifestSignatureInvalid);
}

MT_TEST(VerifiedChecksum_RejectsWrongMasterSecret) {
  // A master_secret that doesn't match the one the release was built with
  // derives a different bound key, which fails AEAD authentication
  // against the actual blob -- the same failure mode as a tampered
  // ciphertext, correctly, since from the verifier's perspective the two
  // are indistinguishable (both mean "this isn't decryptable with the key
  // this context implies").
  auto master_secret_a = crypto::Aes256Key::Generate();
  auto master_secret_b = crypto::Aes256Key::Generate();
  auto signing_keypair = integrity::GenerateEd25519KeyPair();
  MT_CHECK(signing_keypair.has_value());
  if (!signing_keypair) return;

  auto release = examples::BuildVerifiedChecksumRelease(master_secret_a,
                                                          signing_keypair->private_key, "1.0.0");
  auto result = examples::CallProtectedChecksumVerified(
      release.manifest_bytes, release.signature, signing_keypair->public_key, master_secret_b,
      release.encrypted_blob, 42);
  MT_CHECK(result.error == examples::VerifiedCallError::kDecryptionFailed);
}

MT_MAIN()
