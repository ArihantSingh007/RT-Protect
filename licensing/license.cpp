// licensing/license.cpp

#include "licensing/license.h"

#include <algorithm>
#include <cstring>
#include <sstream>

namespace rtprotect::licensing {

const char* ToString(LicenseStatus status) {
  switch (status) {
    case LicenseStatus::kValid: return "valid";
    case LicenseStatus::kInvalidSignature: return "invalid signature";
    case LicenseStatus::kExpired: return "license expired";
    case LicenseStatus::kNotYetValid: return "license not yet valid (issued in future)";
    case LicenseStatus::kHardwareMismatch: return "hardware fingerprint mismatch";
    case LicenseStatus::kProductMismatch: return "product identifier mismatch";
    case LicenseStatus::kEditionMismatch: return "product edition mismatch";
    case LicenseStatus::kClockRollbackDetected: return "system clock rollback detected";
    case LicenseStatus::kMalformed: return "malformed license record";
    case LicenseStatus::kOversized: return "license payload exceeds size limit";
  }
  return "unknown LicenseStatus";
}

bool HasFeature(const License& lic, const std::string& feature) {
  for (const auto& f : lic.feature_flags) {
    if (f == feature) return true;
  }
  return false;
}

namespace {

void WriteU16(std::vector<std::uint8_t>& buf, std::uint16_t v) {
  buf.push_back(static_cast<std::uint8_t>(v & 0xFF));
  buf.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
}

void WriteU32(std::vector<std::uint8_t>& buf, std::uint32_t v) {
  for (int i = 0; i < 4; ++i) buf.push_back(static_cast<std::uint8_t>((v >> (i * 8)) & 0xFF));
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

bool ReadU32(const std::uint8_t*& p, const std::uint8_t* end, std::uint32_t& out) {
  if (end - p < 4) return false;
  out = 0;
  for (int i = 0; i < 4; ++i) out |= (static_cast<std::uint32_t>(p[i]) << (i * 8));
  p += 4;
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

std::vector<std::uint8_t> SerializeLicenseForSigning(const License& lic) {
  std::vector<std::uint8_t> buf;
  buf.reserve(512);

  WriteU32(buf, kLicenseMagic);
  WriteU32(buf, lic.schema_version);
  WriteString(buf, lic.license_id);
  WriteString(buf, lic.product_id);
  WriteString(buf, lic.edition);
  WriteString(buf, lic.customer_id);
  WriteU64(buf, lic.capabilities);

  // Feature flags
  std::uint16_t flag_count = static_cast<std::uint16_t>(std::min(lic.feature_flags.size(), static_cast<std::size_t>(0xFFFF)));
  WriteU16(buf, flag_count);
  for (std::size_t i = 0; i < flag_count; ++i) {
    WriteString(buf, lic.feature_flags[i]);
  }

  WriteU64(buf, lic.issued_at);
  WriteU64(buf, lic.expires_at);
  WriteU64(buf, lic.grace_period_seconds);
  WriteString(buf, lic.hardware_id);
  WriteString(buf, lic.metadata);

  return buf;
}

std::vector<std::uint8_t> SerializeLicense(const License& lic) {
  std::vector<std::uint8_t> buf = SerializeLicenseForSigning(lic);
  buf.insert(buf.end(), lic.signature.data(), lic.signature.data() + lic.signature.size());
  return buf;
}

std::optional<License> DeserializeLicense(const std::uint8_t* data, std::size_t len) {
  if (!data || len < 4 + 4 + 8 + 8 + 8 + integrity::kEd25519SignatureLen) return std::nullopt;
  if (len > kMaxLicenseSize) return std::nullopt;

  const std::uint8_t* p = data;
  const std::uint8_t* end = data + len;

  std::uint32_t magic = 0;
  if (!ReadU32(p, end, magic) || magic != kLicenseMagic) return std::nullopt;

  License lic;
  if (!ReadU32(p, end, lic.schema_version) || lic.schema_version != kLicenseSchemaVersion) {
    return std::nullopt;
  }

  if (!ReadString(p, end, lic.license_id)) return std::nullopt;
  if (!ReadString(p, end, lic.product_id)) return std::nullopt;
  if (!ReadString(p, end, lic.edition)) return std::nullopt;
  if (!ReadString(p, end, lic.customer_id)) return std::nullopt;
  if (!ReadU64(p, end, lic.capabilities)) return std::nullopt;

  std::uint16_t flag_count = 0;
  if (!ReadU16(p, end, flag_count)) return std::nullopt;
  lic.feature_flags.reserve(flag_count);
  for (std::uint16_t i = 0; i < flag_count; ++i) {
    std::string flag;
    if (!ReadString(p, end, flag)) return std::nullopt;
    lic.feature_flags.push_back(std::move(flag));
  }

  if (!ReadU64(p, end, lic.issued_at)) return std::nullopt;
  if (!ReadU64(p, end, lic.expires_at)) return std::nullopt;
  if (!ReadU64(p, end, lic.grace_period_seconds)) return std::nullopt;
  if (!ReadString(p, end, lic.hardware_id)) return std::nullopt;
  if (!ReadString(p, end, lic.metadata)) return std::nullopt;

  if (static_cast<std::size_t>(end - p) != integrity::kEd25519SignatureLen) {
    return std::nullopt;
  }
  std::memcpy(lic.signature.data(), p, integrity::kEd25519SignatureLen);

  return lic;
}

std::string LicenseToText(const License& lic) {
  std::ostringstream ss;
  ss << "RTPROTECT-LICENSE-V" << lic.schema_version << "\n";
  ss << "license_id=" << lic.license_id << "\n";
  ss << "product_id=" << lic.product_id << "\n";
  ss << "edition=" << lic.edition << "\n";
  ss << "customer_id=" << lic.customer_id << "\n";
  ss << "capabilities=" << lic.capabilities << "\n";
  ss << "issued_at=" << lic.issued_at << "\n";
  ss << "expires_at=" << lic.expires_at << "\n";
  ss << "grace_period=" << lic.grace_period_seconds << "\n";
  ss << "hardware_id=" << lic.hardware_id << "\n";
  ss << "metadata=" << lic.metadata << "\n";
  ss << "signature=";
  for (std::uint8_t b : lic.signature) {
    char h[3];
    std::snprintf(h, sizeof(h), "%02x", b);
    ss << h;
  }
  ss << "\n";
  return ss.str();
}

std::optional<License> LicenseFromText(const std::string& text) {
  License lic;
  std::istringstream ss(text);
  std::string line;
  bool got_header = false;

  while (std::getline(ss, line)) {
    if (line.empty() || line[0] == '#') continue;
    if (!got_header) {
      if (line.rfind("RTPROTECT-LICENSE-V1", 0) == 0) {
        got_header = true;
        continue;
      }
      return std::nullopt;
    }
    auto eq = line.find('=');
    if (eq == std::string::npos) continue;
    std::string key = line.substr(0, eq);
    std::string val = line.substr(eq + 1);

    if (key == "license_id") lic.license_id = val;
    else if (key == "product_id") lic.product_id = val;
    else if (key == "edition") lic.edition = val;
    else if (key == "customer_id") lic.customer_id = val;
    else if (key == "capabilities") lic.capabilities = std::strtoull(val.c_str(), nullptr, 10);
    else if (key == "issued_at") lic.issued_at = std::strtoull(val.c_str(), nullptr, 10);
    else if (key == "expires_at") lic.expires_at = std::strtoull(val.c_str(), nullptr, 10);
    else if (key == "grace_period") lic.grace_period_seconds = std::strtoull(val.c_str(), nullptr, 10);
    else if (key == "hardware_id") lic.hardware_id = val;
    else if (key == "metadata") lic.metadata = val;
    else if (key == "signature") {
      if (val.size() == integrity::kEd25519SignatureLen * 2) {
        for (std::size_t i = 0; i < integrity::kEd25519SignatureLen; ++i) {
          char byte_hex[3] = {val[i * 2], val[i * 2 + 1], 0};
          lic.signature[i] = static_cast<std::uint8_t>(std::strtoul(byte_hex, nullptr, 16));
        }
      }
    }
  }
  if (!got_header) return std::nullopt;
  return lic;
}

}  // namespace rtprotect::licensing
