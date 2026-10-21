// licensing/activation.cpp

#include "licensing/activation.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <sstream>

#include <openssl/rand.h>

#include "integrity/verifier.h"

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

bool WriteString(std::vector<std::uint8_t>& buf, const std::string& str, std::size_t max_len = kMaxActivationFieldLen) {
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

bool ReadString(const std::uint8_t*& p, const std::uint8_t* end, std::string& out, std::size_t max_len = kMaxActivationFieldLen) {
  std::uint16_t len = 0;
  if (!ReadU16(p, end, len)) return false;
  if (len > max_len || (end - p) < len) return false;
  out.assign(reinterpret_cast<const char*>(p), len);
  p += len;
  return true;
}

std::string BytesToHex(const std::uint8_t* data, std::size_t len) {
  std::ostringstream ss;
  for (std::size_t i = 0; i < len; ++i) {
    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
  }
  return ss.str();
}

bool HexToBytes(const std::string& hex, std::uint8_t* out, std::size_t expected_len) {
  if (hex.size() != expected_len * 2) return false;
  for (std::size_t i = 0; i < expected_len; ++i) {
    char h[3] = { hex[i * 2], hex[i * 2 + 1], '\0' };
    char* end = nullptr;
    long v = std::strtol(h, &end, 16);
    if (end != h + 2 || v < 0 || v > 255) return false;
    out[i] = static_cast<std::uint8_t>(v);
  }
  return true;
}

}  // namespace

const char* ToString(ActivationStatus status) {
  switch (status) {
    case ActivationStatus::kValid: return "Valid";
    case ActivationStatus::kInvalidSignature: return "InvalidSignature";
    case ActivationStatus::kExpired: return "Expired";
    case ActivationStatus::kNotYetValid: return "NotYetValid";
    case ActivationStatus::kRevoked: return "Revoked";
    case ActivationStatus::kHardwareMismatch: return "HardwareMismatch";
    case ActivationStatus::kLicenseMismatch: return "LicenseMismatch";
    case ActivationStatus::kNonceMismatch: return "NonceMismatch";
    case ActivationStatus::kConcurrencyLimitExceeded: return "ConcurrencyLimitExceeded";
    case ActivationStatus::kMalformed: return "Malformed";
    case ActivationStatus::kClockRollbackDetected: return "ClockRollbackDetected";
  }
  return "Unknown";
}

ActivationRequest CreateActivationRequest(const std::string& license_id,
                                          const std::string& hardware_id,
                                          const std::string& app_version,
                                          std::uint64_t client_timestamp) {
  ActivationRequest req;
  req.schema_version = kActivationSchemaVersion;
  req.license_id = license_id;
  req.hardware_id = hardware_id;
  req.app_version = app_version;

  if (client_timestamp == 0) {
    auto now = std::chrono::system_clock::now().time_since_epoch();
    req.client_timestamp = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(now).count());
  } else {
    req.client_timestamp = client_timestamp;
  }

  // Generate random request ID
  std::array<std::uint8_t, 16> id_bytes{};
  if (RAND_bytes(id_bytes.data(), static_cast<int>(id_bytes.size())) != 1) {
    auto t = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    std::memcpy(id_bytes.data(), &t, sizeof(t));
  }
  req.request_id = "req-" + BytesToHex(id_bytes.data(), id_bytes.size());

  // Generate challenge nonce
  if (RAND_bytes(req.nonce.data(), static_cast<int>(req.nonce.size())) != 1) {
    auto t = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    std::memcpy(req.nonce.data(), &t, sizeof(t));
  }

  return req;
}

std::vector<std::uint8_t> SerializeActivationRequest(const ActivationRequest& req) {
  std::vector<std::uint8_t> buf;
  buf.reserve(256);
  WriteU32(buf, kActivationRequestMagic);
  WriteU32(buf, req.schema_version);
  WriteString(buf, req.request_id);
  WriteString(buf, req.license_id);
  WriteString(buf, req.hardware_id);
  WriteString(buf, req.app_version);
  WriteU64(buf, req.client_timestamp);
  buf.insert(buf.end(), req.nonce.begin(), req.nonce.end());
  return buf;
}

std::optional<ActivationRequest> DeserializeActivationRequest(const std::uint8_t* data, std::size_t len) {
  if (!data || len < 16) return std::nullopt;
  const std::uint8_t* p = data;
  const std::uint8_t* end = data + len;

  std::uint32_t magic = 0;
  if (!ReadU32(p, end, magic) || magic != kActivationRequestMagic) return std::nullopt;

  ActivationRequest req;
  if (!ReadU32(p, end, req.schema_version) || req.schema_version != kActivationSchemaVersion) {
    return std::nullopt;
  }
  if (!ReadString(p, end, req.request_id)) return std::nullopt;
  if (!ReadString(p, end, req.license_id)) return std::nullopt;
  if (!ReadString(p, end, req.hardware_id)) return std::nullopt;
  if (!ReadString(p, end, req.app_version)) return std::nullopt;
  if (!ReadU64(p, end, req.client_timestamp)) return std::nullopt;

  if (static_cast<std::size_t>(end - p) < kActivationNonceLen) return std::nullopt;
  std::memcpy(req.nonce.data(), p, kActivationNonceLen);
  p += kActivationNonceLen;

  return req;
}

std::vector<std::uint8_t> SerializeActivationTicketForSigning(const ActivationTicket& ticket) {
  std::vector<std::uint8_t> buf;
  buf.reserve(512);
  WriteU32(buf, kActivationTicketMagic);
  WriteU32(buf, ticket.schema_version);
  WriteString(buf, ticket.ticket_id);
  WriteString(buf, ticket.license_id);
  WriteString(buf, ticket.hardware_id);
  WriteU64(buf, ticket.issued_at);
  WriteU64(buf, ticket.expires_at);
  buf.insert(buf.end(), ticket.nonce.begin(), ticket.nonce.end());
  buf.insert(buf.end(), ticket.session_key.begin(), ticket.session_key.end());
  WriteString(buf, ticket.metadata, 4096);
  return buf;
}

std::vector<std::uint8_t> SerializeActivationTicket(const ActivationTicket& ticket) {
  auto buf = SerializeActivationTicketForSigning(ticket);
  buf.insert(buf.end(), ticket.signature.begin(), ticket.signature.end());
  return buf;
}

std::optional<ActivationTicket> DeserializeActivationTicket(const std::uint8_t* data, std::size_t len) {
  if (!data || len < integrity::kEd25519SignatureLen + 16) return std::nullopt;
  const std::uint8_t* p = data;
  const std::uint8_t* end = data + len;

  std::uint32_t magic = 0;
  if (!ReadU32(p, end, magic) || magic != kActivationTicketMagic) return std::nullopt;

  ActivationTicket ticket;
  if (!ReadU32(p, end, ticket.schema_version) || ticket.schema_version != kActivationSchemaVersion) {
    return std::nullopt;
  }
  if (!ReadString(p, end, ticket.ticket_id)) return std::nullopt;
  if (!ReadString(p, end, ticket.license_id)) return std::nullopt;
  if (!ReadString(p, end, ticket.hardware_id)) return std::nullopt;
  if (!ReadU64(p, end, ticket.issued_at)) return std::nullopt;
  if (!ReadU64(p, end, ticket.expires_at)) return std::nullopt;

  if (static_cast<std::size_t>(end - p) < kActivationNonceLen + kActivationSessionKeyLen) {
    return std::nullopt;
  }
  std::memcpy(ticket.nonce.data(), p, kActivationNonceLen);
  p += kActivationNonceLen;

  std::memcpy(ticket.session_key.data(), p, kActivationSessionKeyLen);
  p += kActivationSessionKeyLen;

  if (!ReadString(p, end, ticket.metadata, 4096)) return std::nullopt;

  if (static_cast<std::size_t>(end - p) != integrity::kEd25519SignatureLen) {
    return std::nullopt;
  }
  std::memcpy(ticket.signature.data(), p, integrity::kEd25519SignatureLen);
  return ticket;
}

std::string ActivationRequestToText(const ActivationRequest& req) {
  std::ostringstream ss;
  ss << "RTPROTECT_ACTIVATION_REQUEST_V" << req.schema_version << "\n";
  ss << "request_id=" << req.request_id << "\n";
  ss << "license_id=" << req.license_id << "\n";
  ss << "hardware_id=" << req.hardware_id << "\n";
  ss << "app_version=" << req.app_version << "\n";
  ss << "client_timestamp=" << req.client_timestamp << "\n";
  ss << "nonce=" << BytesToHex(req.nonce.data(), req.nonce.size()) << "\n";
  return ss.str();
}

std::optional<ActivationRequest> ActivationRequestFromText(const std::string& text) {
  ActivationRequest req;
  std::istringstream stream(text);
  std::string line;
  if (!std::getline(stream, line) || line.find("RTPROTECT_ACTIVATION_REQUEST_V") != 0) {
    return std::nullopt;
  }
  while (std::getline(stream, line)) {
    if (line.empty() || line[0] == '#') continue;
    auto eq = line.find('=');
    if (eq == std::string::npos) continue;
    std::string key = line.substr(0, eq);
    std::string val = line.substr(eq + 1);
    while (!val.empty() && (val.back() == '\r' || val.back() == '\n' || val.back() == ' ')) val.pop_back();

    if (key == "request_id") req.request_id = val;
    else if (key == "license_id") req.license_id = val;
    else if (key == "hardware_id") req.hardware_id = val;
    else if (key == "app_version") req.app_version = val;
    else if (key == "client_timestamp") req.client_timestamp = std::strtoull(val.c_str(), nullptr, 10);
    else if (key == "nonce") {
      if (!HexToBytes(val, req.nonce.data(), req.nonce.size())) return std::nullopt;
    }
  }
  if (req.request_id.empty() || req.license_id.empty()) return std::nullopt;
  return req;
}

std::string ActivationTicketToText(const ActivationTicket& ticket) {
  std::ostringstream ss;
  ss << "RTPROTECT_ACTIVATION_TICKET_V" << ticket.schema_version << "\n";
  ss << "ticket_id=" << ticket.ticket_id << "\n";
  ss << "license_id=" << ticket.license_id << "\n";
  ss << "hardware_id=" << ticket.hardware_id << "\n";
  ss << "issued_at=" << ticket.issued_at << "\n";
  ss << "expires_at=" << ticket.expires_at << "\n";
  ss << "nonce=" << BytesToHex(ticket.nonce.data(), ticket.nonce.size()) << "\n";
  ss << "session_key=" << BytesToHex(ticket.session_key.data(), ticket.session_key.size()) << "\n";
  if (!ticket.metadata.empty()) ss << "metadata=" << ticket.metadata << "\n";
  ss << "signature=" << BytesToHex(ticket.signature.data(), ticket.signature.size()) << "\n";
  return ss.str();
}

std::optional<ActivationTicket> ActivationTicketFromText(const std::string& text) {
  ActivationTicket ticket;
  std::istringstream stream(text);
  std::string line;
  if (!std::getline(stream, line) || line.find("RTPROTECT_ACTIVATION_TICKET_V") != 0) {
    return std::nullopt;
  }
  while (std::getline(stream, line)) {
    if (line.empty() || line[0] == '#') continue;
    auto eq = line.find('=');
    if (eq == std::string::npos) continue;
    std::string key = line.substr(0, eq);
    std::string val = line.substr(eq + 1);
    while (!val.empty() && (val.back() == '\r' || val.back() == '\n' || val.back() == ' ')) val.pop_back();

    if (key == "ticket_id") ticket.ticket_id = val;
    else if (key == "license_id") ticket.license_id = val;
    else if (key == "hardware_id") ticket.hardware_id = val;
    else if (key == "issued_at") ticket.issued_at = std::strtoull(val.c_str(), nullptr, 10);
    else if (key == "expires_at") ticket.expires_at = std::strtoull(val.c_str(), nullptr, 10);
    else if (key == "nonce") {
      if (!HexToBytes(val, ticket.nonce.data(), ticket.nonce.size())) return std::nullopt;
    } else if (key == "session_key") {
      if (!HexToBytes(val, ticket.session_key.data(), ticket.session_key.size())) return std::nullopt;
    } else if (key == "metadata") {
      ticket.metadata = val;
    } else if (key == "signature") {
      if (!HexToBytes(val, ticket.signature.data(), ticket.signature.size())) return std::nullopt;
    }
  }
  if (ticket.ticket_id.empty() || ticket.license_id.empty()) return std::nullopt;
  return ticket;
}

ActivationStatus VerifyActivationTicket(const ActivationTicket& ticket,
                                        const integrity::Ed25519PublicKey& pubkey,
                                        const ActivationRequest& req,
                                        std::uint64_t current_time,
                                        double min_hw_match_score,
                                        const HardwareSimilarityWeights* hw_weights) {
  // Check license ID match
  if (ticket.license_id != req.license_id) {
    return ActivationStatus::kLicenseMismatch;
  }

  // Check anti-replay challenge nonce match
  if (ticket.nonce != req.nonce) {
    return ActivationStatus::kNonceMismatch;
  }

  // Check hardware binding similarity
  if (!ticket.hardware_id.empty()) {
    if (!VerifyHardwareMatch(ticket.hardware_id, req.hardware_id, min_hw_match_score, hw_weights)) {
      return ActivationStatus::kHardwareMismatch;
    }
  }

  // Check temporal constraints if current_time is provided
  if (current_time > 0) {
    if (current_time + 300 < ticket.issued_at) {
      return ActivationStatus::kNotYetValid;
    }
    if (ticket.expires_at > 0 && current_time > ticket.expires_at) {
      return ActivationStatus::kExpired;
    }
  }

  // Verify Ed25519 signature
  auto bytes_signed = SerializeActivationTicketForSigning(ticket);
  if (!integrity::VerifyManifestSignature(bytes_signed, ticket.signature, pubkey)) {
    return ActivationStatus::kInvalidSignature;
  }

  return ActivationStatus::kValid;
}

}  // namespace rtprotect::licensing
