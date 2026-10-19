// NOTE on linking: this test links rtprotect_integrity_buildtools because,
// unlike the shipped client, a test needs to be able to PRODUCE a validly
// signed manifest in order to test verification against it. See
// integrity/CMakeLists.txt's header comment for why that target must never
// be linked into anything that actually ships.

#include "integrity/keys.h"
#include "integrity/manifest.h"
#include "integrity/signer.h"
#include "integrity/verifier.h"

#include "tests/micro_test.h"

using namespace rtprotect::integrity;

namespace {

Manifest MakeTestManifest() {
  Manifest m;
  m.release_version = "9.9.9";
  std::string data = "signed resource contents";
  m.AddResource("resource.bin", reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
  return m;
}

}  // namespace

MT_TEST(Signing_ValidSignature_Verifies) {
  auto kp = GenerateEd25519KeyPair();
  MT_CHECK(kp.has_value());
  if (!kp) return;

  auto manifest = MakeTestManifest();
  auto wire = SerializeManifest(manifest);

  auto sig = SignManifestBytes(wire, kp->private_key);
  MT_CHECK(sig.has_value());
  if (!sig) return;

  bool ok = VerifyManifestSignature(wire, *sig, kp->public_key);
  MT_CHECK(ok);
}

MT_TEST(Signing_RejectsWrongPublicKey) {
  auto kp_a = GenerateEd25519KeyPair();
  auto kp_b = GenerateEd25519KeyPair();
  MT_CHECK(kp_a.has_value() && kp_b.has_value());
  if (!kp_a || !kp_b) return;

  auto wire = SerializeManifest(MakeTestManifest());
  auto sig = SignManifestBytes(wire, kp_a->private_key);
  MT_CHECK(sig.has_value());
  if (!sig) return;

  bool ok = VerifyManifestSignature(wire, *sig, kp_b->public_key);
  MT_CHECK(!ok);
}

MT_TEST(Signing_RejectsModifiedManifestBytes) {
  auto kp = GenerateEd25519KeyPair();
  MT_CHECK(kp.has_value());
  if (!kp) return;

  auto wire = SerializeManifest(MakeTestManifest());
  auto sig = SignManifestBytes(wire, kp->private_key);
  MT_CHECK(sig.has_value());
  if (!sig) return;

  wire[wire.size() / 2] ^= 0x01;  // flip one bit somewhere in the middle
  bool ok = VerifyManifestSignature(wire, *sig, kp->public_key);
  MT_CHECK(!ok);
}

MT_TEST(Signing_RejectsModifiedSignature) {
  auto kp = GenerateEd25519KeyPair();
  MT_CHECK(kp.has_value());
  if (!kp) return;

  auto wire = SerializeManifest(MakeTestManifest());
  auto sig = SignManifestBytes(wire, kp->private_key);
  MT_CHECK(sig.has_value());
  if (!sig) return;

  (*sig)[0] ^= 0xFF;
  bool ok = VerifyManifestSignature(wire, *sig, kp->public_key);
  MT_CHECK(!ok);
}

MT_TEST(Signing_DifferentManifestsProduceDifferentSignatures) {
  auto kp = GenerateEd25519KeyPair();
  MT_CHECK(kp.has_value());
  if (!kp) return;

  Manifest m1 = MakeTestManifest();
  Manifest m2 = MakeTestManifest();
  m2.release_version = "9.9.10";  // one field different

  auto sig1 = SignManifestBytes(SerializeManifest(m1), kp->private_key);
  auto sig2 = SignManifestBytes(SerializeManifest(m2), kp->private_key);
  MT_CHECK(sig1.has_value() && sig2.has_value());
  if (sig1 && sig2) MT_CHECK(*sig1 != *sig2);
}

// ---------------------------------------------------------------------
// Full pipeline: signature + per-resource hash check, fail-closed ordering
// ---------------------------------------------------------------------

MT_TEST(VerifyAndCheckResource_ValidEverything_Succeeds) {
  auto kp = GenerateEd25519KeyPair();
  MT_CHECK(kp.has_value());
  if (!kp) return;

  Manifest m;
  m.release_version = "1.0.0";
  std::string resource = "the actual shipped bytes";
  m.AddResource("payload.bin", reinterpret_cast<const std::uint8_t*>(resource.data()),
                resource.size());

  auto wire = SerializeManifest(m);
  auto sig = SignManifestBytes(wire, kp->private_key);
  MT_CHECK(sig.has_value());
  if (!sig) return;

  auto err = VerifyAndCheckResource(wire, *sig, kp->public_key, "payload.bin",
                                     reinterpret_cast<const std::uint8_t*>(resource.data()),
                                     resource.size());
  MT_CHECK(err == IntegrityError::kNone);
}

MT_TEST(VerifyAndCheckResource_TamperedResource_FailsHashCheck) {
  auto kp = GenerateEd25519KeyPair();
  MT_CHECK(kp.has_value());
  if (!kp) return;

  Manifest m;
  m.release_version = "1.0.0";
  std::string original = "original shipped bytes";
  m.AddResource("payload.bin", reinterpret_cast<const std::uint8_t*>(original.data()),
                original.size());
  auto wire = SerializeManifest(m);
  auto sig = SignManifestBytes(wire, kp->private_key);
  MT_CHECK(sig.has_value());
  if (!sig) return;

  // The manifest is untouched and validly signed -- but the resource on
  // disk has been swapped for something else entirely (same length, to
  // show the hash check -- not just the cheap size check -- is doing real
  // work here).
  std::string tampered = "tampered shipped bytes";
  MT_CHECK(tampered.size() == original.size());

  auto err = VerifyAndCheckResource(wire, *sig, kp->public_key, "payload.bin",
                                     reinterpret_cast<const std::uint8_t*>(tampered.data()),
                                     tampered.size());
  MT_CHECK(err == IntegrityError::kResourceHashMismatch);
}

MT_TEST(VerifyAndCheckResource_WholesaleBlobSubstitution_Detected) {
  // This is the scenario integrity/manifest.h's header comment describes:
  // an attacker substitutes a DIFFERENT, validly-structured resource from
  // another release entirely (e.g. an older build's blob, itself
  // internally self-consistent) in place of the current one. A per-blob
  // check alone (like AEAD) can't catch this if the attacker also has a
  // validly-encrypted-under-the-same-key blob from elsewhere; the manifest
  // hash catches it because it's bound to THIS release's exact bytes.
  auto kp = GenerateEd25519KeyPair();
  MT_CHECK(kp.has_value());
  if (!kp) return;

  Manifest m;
  m.release_version = "2.0.0";
  std::string current_release_blob = "release-2.0.0-blob-xyz";
  m.AddResource("checksum_blob.bin",
                reinterpret_cast<const std::uint8_t*>(current_release_blob.data()),
                current_release_blob.size());
  auto wire = SerializeManifest(m);
  auto sig = SignManifestBytes(wire, kp->private_key);
  MT_CHECK(sig.has_value());
  if (!sig) return;

  std::string older_release_blob = "release-1.0.0-blob-abc";  // a real, validly-formed
                                                                // artifact -- just not THIS one
  auto err = VerifyAndCheckResource(
      wire, *sig, kp->public_key, "checksum_blob.bin",
      reinterpret_cast<const std::uint8_t*>(older_release_blob.data()), older_release_blob.size());
  MT_CHECK(err == IntegrityError::kResourceSizeMismatch ||
           err == IntegrityError::kResourceHashMismatch);
}

MT_TEST(VerifyAndCheckResource_SignatureCheckedBeforeResourceLookup) {
  // An invalid signature must short-circuit before CheckResource ever runs
  // -- verified by using a manifest/signature pair that's invalid AND
  // asking about a resource name that isn't even in the manifest. If
  // resource lookup happened first we'd see kResourceNotInManifest; the
  // correct fail-closed order means we see kSignatureInvalid instead.
  auto kp_a = GenerateEd25519KeyPair();
  auto kp_b = GenerateEd25519KeyPair();
  MT_CHECK(kp_a.has_value() && kp_b.has_value());
  if (!kp_a || !kp_b) return;

  Manifest m;
  m.release_version = "1.0.0";
  std::string data = "x";
  m.AddResource("real.bin", reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
  auto wire = SerializeManifest(m);
  auto sig = SignManifestBytes(wire, kp_a->private_key);  // signed with key A
  MT_CHECK(sig.has_value());
  if (!sig) return;

  auto err = VerifyAndCheckResource(wire, *sig, kp_b->public_key,  // verified with key B
                                     "nonexistent.bin", reinterpret_cast<const std::uint8_t*>("x"),
                                     1);
  MT_CHECK(err == IntegrityError::kSignatureInvalid);
}

MT_TEST(VerifyAndCheckResource_ResourceNotListed_Rejected) {
  auto kp = GenerateEd25519KeyPair();
  MT_CHECK(kp.has_value());
  if (!kp) return;

  Manifest m;
  m.release_version = "1.0.0";
  std::string data = "listed resource";
  m.AddResource("listed.bin", reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
  auto wire = SerializeManifest(m);
  auto sig = SignManifestBytes(wire, kp->private_key);
  MT_CHECK(sig.has_value());
  if (!sig) return;

  std::string other = "some other resource entirely";
  auto err =
      VerifyAndCheckResource(wire, *sig, kp->public_key, "not_listed.bin",
                              reinterpret_cast<const std::uint8_t*>(other.data()), other.size());
  MT_CHECK(err == IntegrityError::kResourceNotInManifest);
}

MT_MAIN()
