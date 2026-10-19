// licensing/update_manifest.cpp

#include "licensing/update_manifest.h"

#include <cstring>
#include <algorithm>

#include "integrity/signer.h"
#include "integrity/verifier.h"

namespace rtprotect::licensing {

const char* ToString(UpdateStatus status) {
  switch (status) {
    case UpdateStatus::kValid: return "valid update package";
    case UpdateStatus::kInvalidSignature: return "invalid update signature";
    case UpdateStatus::kDowngradeDetected: return "downgrade attack detected (stale sequence number)";
    case UpdateStatus::kProductMismatch: return "target product mismatch";
    case UpdateStatus::kPayloadHashMismatch: return "update payload file hash mismatch";
    case UpdateStatus::kMalformedManifest: return "malformed update manifest";
    case UpdateStatus::kFileNotFound: return "update payload file not found";
  }
  return "unknown UpdateStatus";
}

namespace {

void WriteU16(std::vector<std::uint8_t>& buf, std::uint16_t v) {
  buf.push_back(static_cast<std::uint8_t>(v & 0xFF));
  buf.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
}

void WriteU64(std::vector<std::uint8_t>& buf, std::uint64_t v) {
  for (int i = 0; i < 8; ++i) buf.push_back(static_cast<std::uint8_t>((v >> (i * 8)) & 0xFF));
}

void WriteString(std::vector<std::uint8_t>& buf, const std::string& str) {
  std::uint16_t len = static_cast<std::uint16_t>(std::min(str.size(), static_cast<std::size_t>(0xFFFF)));
  WriteU16(buf, len);
  buf.insert(buf.end(), str.data(), str.data() + len);
}

bool ReadU16(const std::uint8_t*& p, const std::uint8_t* end, std::uint16_t& out) {
  if (end - p < 2) return false;
  out = static_cast<std::uint16_t>(p[0]) | (static_cast<std::uint16_t>(p[1]) << 8);
  p += 2;
  return true;
}

bool ReadU64(const std::uint8_t*& p, const std::uint8_t* end, std::uint64_t& out) {
  if (end - p < 8) return false;
  out = 0;
  for (int i = 0; i < 8; ++i) out |= (static_cast<std::uint64_t>(p[i]) << (i * 8));
  p += 8;
  return true;
}

bool ReadString(const std::uint8_t*& p, const std::uint8_t* end, std::string& out) {
  std::uint16_t len = 0;
  if (!ReadU16(p, end, len)) return false;
  if (end - p < len) return false;
  out.assign(reinterpret_cast<const char*>(p), len);
  p += len;
  return true;
}

}  // namespace

std::vector<std::uint8_t> SerializeUpdateForSigning(const UpdatePackage& pkg) {
  std::vector<std::uint8_t> buf;
  buf.reserve(512);

  WriteString(buf, "RTPROTECT-UPDATE-V1");
  WriteString(buf, pkg.target_product);
  WriteString(buf, pkg.target_version);
  WriteU64(buf, pkg.sequence_number);
  WriteU64(buf, pkg.timestamp);

  std::uint16_t file_count = static_cast<std::uint16_t>(std::min(pkg.files.size(), static_cast<std::size_t>(0xFFFF)));
  WriteU16(buf, file_count);
  for (std::size_t i = 0; i < file_count; ++i) {
    const auto& f = pkg.files[i];
    WriteString(buf, f.name);
    WriteU64(buf, f.size);
    buf.insert(buf.end(), f.sha256.data(), f.sha256.data() + f.sha256.size());
  }

  return buf;
}

bool SignUpdatePackage(UpdatePackage& pkg, const integrity::Ed25519PrivateKey& privkey) {
  auto bytes_to_sign = SerializeUpdateForSigning(pkg);
  auto sig = integrity::SignManifestBytes(bytes_to_sign, privkey);
  if (!sig.has_value()) return false;
  pkg.signature = *sig;
  return true;
}

std::vector<std::uint8_t> SerializeUpdatePackage(const UpdatePackage& pkg) {
  std::vector<std::uint8_t> buf = SerializeUpdateForSigning(pkg);
  buf.insert(buf.end(), pkg.signature.data(), pkg.signature.data() + pkg.signature.size());
  return buf;
}

std::optional<UpdatePackage> DeserializeUpdatePackage(const std::uint8_t* data, std::size_t len) {
  if (!data || len < 64) return std::nullopt;

  const std::uint8_t* p = data;
  const std::uint8_t* end = data + len;

  std::string magic;
  if (!ReadString(p, end, magic) || magic != "RTPROTECT-UPDATE-V1") return std::nullopt;

  UpdatePackage pkg;
  if (!ReadString(p, end, pkg.target_product)) return std::nullopt;
  if (!ReadString(p, end, pkg.target_version)) return std::nullopt;
  if (!ReadU64(p, end, pkg.sequence_number)) return std::nullopt;
  if (!ReadU64(p, end, pkg.timestamp)) return std::nullopt;

  std::uint16_t file_count = 0;
  if (!ReadU16(p, end, file_count)) return std::nullopt;
  pkg.files.reserve(file_count);

  for (std::uint16_t i = 0; i < file_count; ++i) {
    integrity::ResourceEntry entry;
    if (!ReadString(p, end, entry.name)) return std::nullopt;
    if (!ReadU64(p, end, entry.size)) return std::nullopt;
    if (end - p < 32) return std::nullopt;
    std::memcpy(entry.sha256.data(), p, 32);
    p += 32;
    pkg.files.push_back(std::move(entry));
  }

  if (static_cast<std::size_t>(end - p) != integrity::kEd25519SignatureLen) {
    return std::nullopt;
  }
  std::memcpy(pkg.signature.data(), p, integrity::kEd25519SignatureLen);

  return pkg;
}

UpdateStatus VerifyUpdateMetadata(const UpdatePackage& pkg,
                                  const integrity::Ed25519PublicKey& pubkey,
                                  const std::string& expected_product,
                                  std::uint64_t current_installed_sequence) {
  if (!expected_product.empty() && pkg.target_product != expected_product) {
    return UpdateStatus::kProductMismatch;
  }

  if (pkg.sequence_number <= current_installed_sequence) {
    return UpdateStatus::kDowngradeDetected;
  }

  auto bytes_to_verify = SerializeUpdateForSigning(pkg);
  if (!integrity::VerifyManifestSignature(bytes_to_verify, pkg.signature, pubkey)) {
    return UpdateStatus::kInvalidSignature;
  }

  return UpdateStatus::kValid;
}

}  // namespace rtprotect::licensing
