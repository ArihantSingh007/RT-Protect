// licensing/license.cpp

#include "licensing/license.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <unordered_set>

namespace rtprotect::licensing {

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

bool WriteString(std::vector<std::uint8_t>& buf, const std::string& str, std::size_t max_len = kMaxLicenseFieldLen) {
  if (str.size() > max_len) return false;
  std::uint16_t len = static_cast<std::uint16_t>(str.size());
  WriteU16(buf, len);
  buf.insert(buf.end(), str.data(), str.data() + len);
  return true;
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

bool ReadString(const std::uint8_t*& p, const std::uint8_t* end, std::string& out, std::size_t max_len = kMaxLicenseFieldLen) {
  std::uint16_t len = 0;
  if (!ReadU16(p, end, len)) return false;
  if (len > max_len || static_cast<std::size_t>(end - p) < len) return false;
  out.assign(reinterpret_cast<const char*>(p), len);
  p += len;
  return true;
}

}  // namespace

std::vector<std::uint8_t> SerializeLicenseForSigning(const License& lic) {
  std::vector<std::uint8_t> buf;
  // Pre-validate all field lengths to prevent truncated serialization
  if (lic.license_id.size() > kMaxLicenseFieldLen ||
      lic.product_id.size() > kMaxLicenseFieldLen ||
      lic.edition.size() > kMaxLicenseFieldLen ||
      lic.customer_id.size() > kMaxLicenseFieldLen ||
      lic.hardware_id.size() > kMaxLicenseFieldLen ||
      lic.metadata.size() > 4096 ||
      lic.feature_flags.size() > 64) {
    return {};
  }

  buf.reserve(512);

  WriteU32(buf, kLicenseMagic);
  WriteU32(buf, lic.schema_version);
  WriteString(buf, lic.license_id);
  WriteString(buf, lic.product_id);
  WriteString(buf, lic.edition);
  WriteString(buf, lic.customer_id);
  WriteU64(buf, lic.capabilities);

  // Feature flags
  std::uint16_t flag_count = static_cast<std::uint16_t>(lic.feature_flags.size());
  WriteU16(buf, flag_count);
  for (std::size_t i = 0; i < flag_count; ++i) {
    if (!WriteString(buf, lic.feature_flags[i])) return {};
  }

  WriteU64(buf, lic.issued_at);
  WriteU64(buf, lic.expires_at);
  WriteU64(buf, lic.grace_period_seconds);
  WriteString(buf, lic.hardware_id);
  WriteString(buf, lic.metadata, 4096);

  return buf;
}

std::vector<std::uint8_t> SerializeLicense(const License& lic) {
  std::vector<std::uint8_t> buf = SerializeLicenseForSigning(lic);
  if (buf.empty()) return {};
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
  if (flag_count > 64) return std::nullopt;
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
  if (!ReadString(p, end, lic.metadata, 4096)) return std::nullopt;

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
  if (!lic.feature_flags.empty()) {
    ss << "feature_flags=";
    for (std::size_t i = 0; i < lic.feature_flags.size(); ++i) {
      if (i > 0) ss << ",";
      ss << lic.feature_flags[i];
    }
    ss << "\n";
  }
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

namespace {

bool ParseStrictU64(const std::string& str, std::uint64_t& out) {
  if (str.empty()) return false;
  char* end = nullptr;
  errno = 0;
  unsigned long long val = std::strtoull(str.c_str(), &end, 10);
  if (errno != 0 || end == str.c_str() || *end != '\0') return false;
  out = static_cast<std::uint64_t>(val);
  return true;
}

}  // namespace

std::optional<License> LicenseFromText(const std::string& text) {
  License lic;
  std::istringstream ss(text);
  std::string line;
  bool got_header = false;
  std::unordered_set<std::string> seen_keys;

  while (std::getline(ss, line)) {
    // Trim trailing CR
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty() || line[0] == '#') continue;

    if (!got_header) {
      if (line == "RTPROTECT-LICENSE-V1") {
        got_header = true;
        lic.schema_version = 1;
        continue;
      }
      return std::nullopt;  // Invalid header or unsupported version
    }

    auto eq = line.find('=');
    if (eq == std::string::npos) return std::nullopt;
    std::string key = line.substr(0, eq);
    std::string val = line.substr(eq + 1);

    // Reject duplicate keys
    if (seen_keys.find(key) != seen_keys.end()) return std::nullopt;
    seen_keys.insert(key);

    if (key == "license_id") {
      if (val.size() > kMaxLicenseFieldLen) return std::nullopt;
      lic.license_id = val;
    } else if (key == "product_id") {
      if (val.size() > kMaxLicenseFieldLen) return std::nullopt;
      lic.product_id = val;
    } else if (key == "edition") {
      if (val.size() > kMaxLicenseFieldLen) return std::nullopt;
      lic.edition = val;
    } else if (key == "customer_id") {
      if (val.size() > kMaxLicenseFieldLen) return std::nullopt;
      lic.customer_id = val;
    } else if (key == "capabilities") {
      if (!ParseStrictU64(val, lic.capabilities)) return std::nullopt;
    } else if (key == "feature_flags") {
      std::istringstream fss(val);
      std::string flag;
      while (std::getline(fss, flag, ',')) {
        if (!flag.empty() && flag.size() <= kMaxLicenseFieldLen) {
          lic.feature_flags.push_back(flag);
        }
      }
      if (lic.feature_flags.size() > 64) return std::nullopt;
    } else if (key == "issued_at") {
      if (!ParseStrictU64(val, lic.issued_at)) return std::nullopt;
    } else if (key == "expires_at") {
      if (!ParseStrictU64(val, lic.expires_at)) return std::nullopt;
    } else if (key == "grace_period") {
      if (!ParseStrictU64(val, lic.grace_period_seconds)) return std::nullopt;
    } else if (key == "hardware_id") {
      if (val.size() > kMaxLicenseFieldLen) return std::nullopt;
      lic.hardware_id = val;
    } else if (key == "metadata") {
      if (val.size() > 4096) return std::nullopt;
      lic.metadata = val;
    } else if (key == "signature") {
      if (val.size() != integrity::kEd25519SignatureLen * 2) return std::nullopt;
      for (std::size_t i = 0; i < integrity::kEd25519SignatureLen; ++i) {
        char byte_hex[3] = {val[i * 2], val[i * 2 + 1], 0};
        char* end = nullptr;
        unsigned long b = std::strtoul(byte_hex, &end, 16);
        if (end == byte_hex || *end != '\0') return std::nullopt;
        lic.signature[i] = static_cast<std::uint8_t>(b);
      }
    } else {
      // Reject unknown keys in canonical format
      return std::nullopt;
    }
  }

  if (!got_header) return std::nullopt;
  return lic;
}

const char* ToString(LicenseStatus status) {
  switch (status) {
    case LicenseStatus::kValid: return "valid";
    case LicenseStatus::kInvalidSignature: return "invalid signature";
    case LicenseStatus::kExpired: return "license expired";
    case LicenseStatus::kNotYetValid: return "license not yet valid (future issue time)";
    case LicenseStatus::kHardwareMismatch: return "hardware fingerprint mismatch";
    case LicenseStatus::kHardwareDegraded: return "hardware probes degraded under strict policy";
    case LicenseStatus::kProductMismatch: return "product identifier mismatch";
    case LicenseStatus::kEditionMismatch: return "product edition mismatch";
    case LicenseStatus::kClockRollbackDetected: return "system clock rollback detected";
    case LicenseStatus::kMalformed: return "malformed license payload";
    case LicenseStatus::kOversized: return "license payload exceeds size limit";
  }
  return "unknown LicenseStatus";
}

bool HasFeature(const License& lic, const std::string& feature) {
  return std::find(lic.feature_flags.begin(), lic.feature_flags.end(), feature) != lic.feature_flags.end();
}

}  // namespace rtprotect::licensing
