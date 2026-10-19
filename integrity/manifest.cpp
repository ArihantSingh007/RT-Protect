#include "integrity/manifest.h"

#include <cstring>

namespace rtprotect::integrity {

namespace {

void PutU32(std::vector<std::uint8_t>& out, std::uint32_t v) {
  for (int i = 0; i < 4; ++i) out.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
}

bool GetU32(const std::uint8_t* p, std::size_t remaining, std::uint32_t* out) {
  if (remaining < 4) return false;
  *out = 0;
  for (int i = 0; i < 4; ++i) *out |= static_cast<std::uint32_t>(p[i]) << (8 * i);
  return true;
}

void PutU64(std::vector<std::uint8_t>& out, std::uint64_t v) {
  for (int i = 0; i < 8; ++i) out.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
}

bool GetU64(const std::uint8_t* p, std::size_t remaining, std::uint64_t* out) {
  if (remaining < 8) return false;
  *out = 0;
  for (int i = 0; i < 8; ++i) *out |= static_cast<std::uint64_t>(p[i]) << (8 * i);
  return true;
}

}  // namespace

bool Manifest::AddResource(const std::string& name, const std::uint8_t* data, std::size_t len) {
  // Empty names are rejected: a resource identity must be a non-empty,
  // logical identifier (see manifest.h's ResourceEntry::name comment for
  // "logical identifier, not a filesystem path"), and an empty string as
  // that identifier is never meaningful -- it also collides trivially
  // with itself (two resources both named "" would be indistinguishable
  // duplicates, which the check immediately below already has to handle
  // for non-empty names; rejecting empty up front is simpler than folding
  // it into that general case).
  if (name.empty()) return false;
  if (name.size() > kMaxResourceNameLen) return false;
  if (resources.size() >= kMaxResourcesPerManifest) return false;

  // Reject a duplicate resource identity outright, rather than silently
  // allowing two entries to share a name. Before this check, AddResource
  // would happily append a second entry for an already-used name, while
  // Find() (a linear scan returning the FIRST match) would silently
  // disagree with "the last one added" or "all of them" about which
  // entry is authoritative for that name -- exactly the kind of
  // AddResource/Find/Deserialize disagreement this project's hardening
  // review was asked to close. A manifest either has one entry per
  // logical resource identity, or it's rejected at the point of
  // construction, not discovered as an ambiguity later during lookup.
  if (Find(name) != nullptr) return false;

  auto digest = Sha256(data, len);
  if (!digest.has_value()) return false;

  ResourceEntry entry;
  entry.name = name;
  entry.sha256 = *digest;
  entry.size = static_cast<std::uint64_t>(len);
  resources.push_back(std::move(entry));
  return true;
}

const ResourceEntry* Manifest::Find(const std::string& name) const {
  for (const auto& r : resources) {
    if (r.name == name) return &r;
  }
  return nullptr;
}

// Wire format: version_len(u32) | version_bytes | release_sequence(u64) |
//              resource_count(u32) |
//              [ name_len(u32) | name_bytes | size(u64) | sha256(32) ] *count
//
// release_sequence was added to this format by this project's hardening
// pass -- see manifest.h's "FORMAT NOTE" above this struct's
// CheckRollback() declaration for why this is a deliberate breaking
// change rather than a backward-compatible extension.
std::vector<std::uint8_t> SerializeManifest(const Manifest& manifest) {
  std::vector<std::uint8_t> out;

  PutU32(out, static_cast<std::uint32_t>(manifest.release_version.size()));
  out.insert(out.end(), manifest.release_version.begin(), manifest.release_version.end());

  PutU64(out, manifest.release_sequence);

  PutU32(out, static_cast<std::uint32_t>(manifest.resources.size()));
  for (const auto& r : manifest.resources) {
    PutU32(out, static_cast<std::uint32_t>(r.name.size()));
    out.insert(out.end(), r.name.begin(), r.name.end());
    PutU64(out, r.size);
    out.insert(out.end(), r.sha256.begin(), r.sha256.end());
  }

  return out;
}

namespace {

// `remaining` bytes available starting at `pos` within a buffer of total
// length `len`. Every bounds check below is written as "does the needed
// amount exceed what's remaining" (subtraction, on values already proven
// pos <= len) rather than "does pos + needed exceed len" (addition, which
// could in principle overflow on a platform where std::size_t is narrower
// than this project's primary 64-bit target -- see docs/ARCHITECTURE.md's
// toolchain notes). pos is always <= len at the point this is called
// (every advance of pos is itself checked against remaining space before
// being applied), so `len - pos` never underflows.
inline std::size_t Remaining(std::size_t pos, std::size_t len) { return len - pos; }

}  // namespace

std::optional<Manifest> DeserializeManifest(const std::uint8_t* data, std::size_t len) {
  std::size_t pos = 0;
  Manifest m;

  std::uint32_t version_len = 0;
  if (Remaining(pos, len) < 4 || !GetU32(data + pos, Remaining(pos, len), &version_len)) {
    return std::nullopt;
  }
  pos += 4;
  if (version_len > Remaining(pos, len)) return std::nullopt;
  m.release_version.assign(reinterpret_cast<const char*>(data + pos), version_len);
  pos += version_len;

  if (Remaining(pos, len) < 8 || !GetU64(data + pos, Remaining(pos, len), &m.release_sequence)) {
    return std::nullopt;
  }
  pos += 8;

  std::uint32_t count = 0;
  if (Remaining(pos, len) < 4 || !GetU32(data + pos, Remaining(pos, len), &count)) {
    return std::nullopt;
  }
  pos += 4;
  if (count > kMaxResourcesPerManifest) return std::nullopt;

  m.resources.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    std::uint32_t name_len = 0;
    if (Remaining(pos, len) < 4 || !GetU32(data + pos, Remaining(pos, len), &name_len)) {
      return std::nullopt;
    }
    pos += 4;
    if (name_len == 0 || name_len > kMaxResourceNameLen || name_len > Remaining(pos, len)) {
      return std::nullopt;  // empty names rejected here too -- see
                             // AddResource's comment on why; a
                             // deserialized manifest must satisfy the same
                             // identity rules a programmatically-built one
                             // does, not a looser set just because it came
                             // from bytes instead of AddResource() calls
    }

    ResourceEntry entry;
    entry.name.assign(reinterpret_cast<const char*>(data + pos), name_len);
    pos += name_len;

    // Reject a duplicate resource identity -- same reasoning as
    // AddResource()'s check (see that function's comment): a manifest
    // with two entries sharing a name is rejected outright rather than
    // silently accepted with an ambiguous "which one is authoritative"
    // left for Find() to arbitrarily resolve via first-match. Checked
    // here (not deferred to a post-loop pass) so the specific malformed
    // entry is caught at the point it's parsed, consistent with every
    // other per-entry validation in this loop.
    if (m.Find(entry.name) != nullptr) return std::nullopt;

    std::uint64_t size = 0;
    if (Remaining(pos, len) < 8 || !GetU64(data + pos, Remaining(pos, len), &size)) {
      return std::nullopt;
    }
    pos += 8;
    entry.size = size;

    if (kSha256DigestLen > Remaining(pos, len)) return std::nullopt;
    std::memcpy(entry.sha256.data(), data + pos, kSha256DigestLen);
    pos += kSha256DigestLen;

    m.resources.push_back(std::move(entry));
  }

  if (pos != len) return std::nullopt;  // reject trailing garbage, as in bytecode_vm::Deserialize
  return m;
}

}  // namespace rtprotect::integrity
