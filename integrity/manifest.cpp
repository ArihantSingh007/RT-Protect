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

bool IsValidResourceIdentifier(const std::string& name) {
  if (name.empty() || name.size() > kMaxResourceNameLen) return false;
  // Cannot start with '/' or '\' or have drive letter like 'C:'
  if (name[0] == '/' || name[0] == '\\') return false;
  if (name.find(':') != std::string::npos) return false;
  // Cannot contain ".." traversal segments
  if (name == ".." || name.find("/../") != std::string::npos ||
      name.find("\\..\\") != std::string::npos ||
      name.find("/..\\") != std::string::npos ||
      name.find("\\../") != std::string::npos ||
      name.find("../") == 0 || name.find("..\\") == 0) {
    return false;
  }
  if (name.size() >= 3 && (name.substr(name.size() - 3) == "/.." || name.substr(name.size() - 3) == "\\..")) {
    return false;
  }
  // Safe character set: letters, digits, '.', '_', '-', '/', '\'
  for (char c : name) {
    if (!std::isalnum(static_cast<unsigned char>(c)) &&
        c != '.' && c != '_' && c != '-' && c != '/' && c != '\\') {
      return false;
    }
  }
  return true;
}

bool Manifest::AddResource(const std::string& name, const std::uint8_t* data, std::size_t len) {
  if (!IsValidResourceIdentifier(name)) return false;
  if (len > 0 && data == nullptr) return false;
  if (resources.size() >= kMaxResourcesPerManifest) return false;

  // Reject a duplicate resource identity outright
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

bool Manifest::AddResourceWithHash(const std::string& name, const Sha256Digest& sha, std::uint64_t size) {
  if (!IsValidResourceIdentifier(name)) return false;
  if (resources.size() >= kMaxResourcesPerManifest) return false;
  if (Find(name) != nullptr) return false;

  ResourceEntry entry;
  entry.name = name;
  entry.sha256 = sha;
  entry.size = size;
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
  if (data == nullptr || len < 4) return std::nullopt;
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
      return std::nullopt;
    }

    ResourceEntry entry;
    entry.name.assign(reinterpret_cast<const char*>(data + pos), name_len);
    pos += name_len;

    if (!IsValidResourceIdentifier(entry.name)) {
      return std::nullopt;
    }

    // Reject a duplicate resource identity
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
