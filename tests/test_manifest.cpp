#include "integrity/manifest.h"

#include <string>
#include <vector>

#include "tests/micro_test.h"

using namespace rtprotect::integrity;

MT_TEST(Manifest_AddResource_ComputesCorrectHashAndSize) {
  Manifest m;
  std::string data = "hello, manifest";
  bool ok = m.AddResource("greeting.txt", reinterpret_cast<const std::uint8_t*>(data.data()),
                           data.size());
  MT_CHECK(ok);
  const ResourceEntry* e = m.Find("greeting.txt");
  MT_CHECK(e != nullptr);
  if (!e) return;
  MT_CHECK(e->size == data.size());

  auto expected = Sha256(reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
  MT_CHECK(expected.has_value());
  if (expected) MT_CHECK(e->sha256 == *expected);
}

MT_TEST(Manifest_Find_ReturnsNullForUnknownName) {
  Manifest m;
  std::string data = "x";
  m.AddResource("known.bin", reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
  MT_CHECK(m.Find("unknown.bin") == nullptr);
}

MT_TEST(Manifest_SerializeDeserialize_RoundTrip) {
  Manifest m;
  m.release_version = "2.1.0-rc3";
  std::string a = "resource A contents";
  std::string b = "resource B, different contents, different length";
  m.AddResource("a.bin", reinterpret_cast<const std::uint8_t*>(a.data()), a.size());
  m.AddResource("b.bin", reinterpret_cast<const std::uint8_t*>(b.data()), b.size());

  auto wire = SerializeManifest(m);
  auto parsed = DeserializeManifest(wire.data(), wire.size());
  MT_CHECK(parsed.has_value());
  if (!parsed) return;

  MT_CHECK(parsed->release_version == m.release_version);
  MT_CHECK(parsed->resources.size() == 2);
  const ResourceEntry* pa = parsed->Find("a.bin");
  const ResourceEntry* pb = parsed->Find("b.bin");
  MT_CHECK(pa != nullptr && pb != nullptr);
  if (pa) {
    MT_CHECK(pa->size == a.size());
    MT_CHECK(pa->sha256 == m.Find("a.bin")->sha256);
  }
  if (pb) {
    MT_CHECK(pb->size == b.size());
  }
}

MT_TEST(Manifest_Serialize_IsDeterministic) {
  // Same content, built twice, must serialize to byte-identical output --
  // this is what makes signing meaningful (sign once, verify against
  // independently-reconstructed bytes).
  auto build = []() {
    Manifest m;
    m.release_version = "1.0.0";
    std::string data = "deterministic content";
    m.AddResource("r.bin", reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
    return SerializeManifest(m);
  };
  auto wire1 = build();
  auto wire2 = build();
  MT_CHECK(wire1 == wire2);
}

MT_TEST(Manifest_Deserialize_RejectsTruncatedInput) {
  std::vector<std::uint8_t> truncated = {0x05, 0x00, 0x00, 0x00, 'h', 'e'};  // claims 5-byte
                                                                              // version, gives 2
  auto parsed = DeserializeManifest(truncated.data(), truncated.size());
  MT_CHECK(!parsed.has_value());
}

MT_TEST(Manifest_Deserialize_RejectsTrailingGarbage) {
  Manifest m;
  m.release_version = "1.0.0";
  auto wire = SerializeManifest(m);
  wire.push_back(0xFF);  // append one unexplained trailing byte
  auto parsed = DeserializeManifest(wire.data(), wire.size());
  MT_CHECK(!parsed.has_value());
}

MT_TEST(Sha256_SameInputSameOutput_DifferentInputDifferentOutput) {
  std::string a = "content A";
  std::string b = "content B";
  auto ha1 = Sha256(reinterpret_cast<const std::uint8_t*>(a.data()), a.size());
  auto ha2 = Sha256(reinterpret_cast<const std::uint8_t*>(a.data()), a.size());
  auto hb = Sha256(reinterpret_cast<const std::uint8_t*>(b.data()), b.size());
  MT_CHECK(ha1.has_value() && ha2.has_value() && hb.has_value());
  if (ha1 && ha2) MT_CHECK(*ha1 == *ha2);
  if (ha1 && hb) MT_CHECK(*ha1 != *hb);
}

// ---------------------------------------------------------------------
// Duplicate and empty resource-name rejection. Before this hardening
// pass, AddResource() had no duplicate check at all, and Find()'s
// first-match linear scan meant a manifest with two entries sharing a
// name had no well-defined "authoritative" entry -- these tests exist to
// prove that ambiguity can no longer be constructed, via either entry
// point (AddResource() for programmatic construction, DeserializeManifest()
// for untrusted bytes).
// ---------------------------------------------------------------------

MT_TEST(Manifest_AddResource_RejectsDuplicateName) {
  Manifest m;
  std::string a = "first version of the content";
  std::string b = "different content, same name";
  MT_CHECK(m.AddResource("dup.bin", reinterpret_cast<const std::uint8_t*>(a.data()), a.size()));
  bool second = m.AddResource("dup.bin", reinterpret_cast<const std::uint8_t*>(b.data()), b.size());
  MT_CHECK(!second);
  MT_CHECK(m.resources.size() == 1);  // the rejected call must not have
                                       // appended anything
  // The one entry present must still be the FIRST (only) one added.
  auto expected_hash = Sha256(reinterpret_cast<const std::uint8_t*>(a.data()), a.size());
  MT_CHECK(expected_hash.has_value());
  if (expected_hash) MT_CHECK(m.Find("dup.bin")->sha256 == *expected_hash);
}

MT_TEST(Manifest_AddResource_RejectsEmptyName) {
  Manifest m;
  std::string data = "content";
  bool ok = m.AddResource("", reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
  MT_CHECK(!ok);
  MT_CHECK(m.resources.empty());
}

MT_TEST(Manifest_Deserialize_RejectsSerializedDuplicateNames) {
  // Hand-crafts a manifest wire blob with two resource entries sharing
  // the same name -- something AddResource() now refuses to construct,
  // but DeserializeManifest() must ALSO refuse, since it builds entries
  // directly rather than going through AddResource(). This is the
  // specific "untrusted bytes bypass the programmatic-construction
  // safety check" scenario this phase's hardening review was asked to
  // close.
  auto put_u32 = [](std::vector<std::uint8_t>& out, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
  };
  auto put_u64 = [](std::vector<std::uint8_t>& out, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
  };

  std::vector<std::uint8_t> wire;
  std::string version = "1.0.0";
  put_u32(wire, static_cast<std::uint32_t>(version.size()));
  wire.insert(wire.end(), version.begin(), version.end());

  put_u32(wire, 2);  // resource count = 2, both named "same.bin"
  for (int i = 0; i < 2; ++i) {
    std::string name = "same.bin";
    put_u32(wire, static_cast<std::uint32_t>(name.size()));
    wire.insert(wire.end(), name.begin(), name.end());
    put_u64(wire, 4);  // claimed size
    for (int b = 0; b < 32; ++b) wire.push_back(static_cast<std::uint8_t>(i));  // dummy hash
  }

  auto parsed = DeserializeManifest(wire.data(), wire.size());
  MT_CHECK(!parsed.has_value());
}

MT_TEST(Manifest_Deserialize_RejectsSerializedEmptyName) {
  auto put_u32 = [](std::vector<std::uint8_t>& out, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
  };
  auto put_u64 = [](std::vector<std::uint8_t>& out, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
  };

  std::vector<std::uint8_t> wire;
  std::string version = "1.0.0";
  put_u32(wire, static_cast<std::uint32_t>(version.size()));
  wire.insert(wire.end(), version.begin(), version.end());

  put_u32(wire, 1);
  put_u32(wire, 0);  // name_len = 0 -- empty name
  put_u64(wire, 4);
  for (int b = 0; b < 32; ++b) wire.push_back(0);

  auto parsed = DeserializeManifest(wire.data(), wire.size());
  MT_CHECK(!parsed.has_value());
}

MT_TEST(Manifest_Deserialize_RejectsExcessiveResourceCount) {
  // count > kMaxResourcesPerManifest must be rejected before any
  // per-entry parsing (and well before any allocation sized from that
  // count) is attempted.
  auto put_u32 = [](std::vector<std::uint8_t>& out, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
  };
  std::vector<std::uint8_t> wire;
  put_u32(wire, 0);  // empty version
  put_u32(wire, static_cast<std::uint32_t>(kMaxResourcesPerManifest) + 1);
  // No actual entry bytes follow -- the count check must reject this
  // before attempting to read entries that aren't there.
  auto parsed = DeserializeManifest(wire.data(), wire.size());
  MT_CHECK(!parsed.has_value());
}

// ---------------------------------------------------------------------
// Rollback sequence field and CheckRollback(). See manifest.h's
// CheckRollback() comment for this mechanism's real, narrow scope: it is
// a comparison, not a rollback-resistance guarantee on its own -- these
// tests verify the comparison and the field's serialization, not
// "rollback resistance" as a security property (which depends entirely on
// something outside this module's control; see that comment).
// ---------------------------------------------------------------------

MT_TEST(Manifest_ReleaseSequence_RoundTripsThroughSerialization) {
  Manifest m;
  m.release_version = "3.1.4";
  m.release_sequence = 42;
  std::string data = "resource";
  m.AddResource("r.bin", reinterpret_cast<const std::uint8_t*>(data.data()), data.size());

  auto wire = SerializeManifest(m);
  auto parsed = DeserializeManifest(wire.data(), wire.size());
  MT_CHECK(parsed.has_value());
  if (parsed) MT_CHECK(parsed->release_sequence == 42);
}

MT_TEST(Manifest_ReleaseSequence_DefaultsToZero) {
  Manifest m;
  m.release_version = "1.0.0";
  MT_CHECK(m.release_sequence == 0);
}

MT_TEST(CheckRollback_AcceptsSequenceAtOrAboveMinimum) {
  Manifest m;
  m.release_sequence = 10;
  MT_CHECK(CheckRollback(m, 10));   // exactly at minimum
  MT_CHECK(CheckRollback(m, 5));    // above minimum
  MT_CHECK(CheckRollback(m, 0));    // default minimum (nothing required)
}

MT_TEST(CheckRollback_RejectsSequenceBelowMinimum) {
  Manifest m;
  m.release_sequence = 5;
  MT_CHECK(!CheckRollback(m, 10));  // this manifest is OLDER than what's required
}

MT_MAIN()
