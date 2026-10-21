// licensing/activation.cpp

#include "licensing/activation.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <system_error>

#include <openssl/rand.h>

#include "crypto/aead.h"
#include "crypto/kdf.h"
#include "integrity/verifier.h"
#include "licensing/hardware_id.h"
#include "tooling/file_io.h"

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

std::vector<std::uint8_t> SerializeActivationToken(const ActivationToken& token) {
  if (token.license_id.size() > kMaxActivationFieldLen ||
      token.device_fingerprint_hash.size() > kMaxActivationFieldLen) {
    return {};
  }
  std::vector<std::uint8_t> buf;
  buf.reserve(256);

  WriteU32(buf, kActivationTokenMagic);
  WriteU32(buf, token.schema_version);
  if (!WriteString(buf, token.license_id)) return {};
  if (!WriteString(buf, token.device_fingerprint_hash)) return {};
  WriteU64(buf, token.issued_at);
  WriteU64(buf, token.expires_at);
  WriteU64(buf, token.grace_expires_at);
  buf.insert(buf.end(), token.server_nonce.begin(), token.server_nonce.end());
  buf.insert(buf.end(), token.vm_root.begin(), token.vm_root.end());
  WriteU64(buf, token.sequence_number);

  return buf;
}

std::optional<ActivationToken> DeserializeActivationToken(const std::uint8_t* data, std::size_t len) {
  if (!data || len < 4 + 4 + 2 + 2 + 8 + 8 + 8 + 32 + 32 + 8) return std::nullopt;
  const std::uint8_t* p = data;
  const std::uint8_t* end = data + len;

  std::uint32_t magic = 0;
  if (!ReadU32(p, end, magic) || magic != kActivationTokenMagic) return std::nullopt;

  ActivationToken token;
  if (!ReadU32(p, end, token.schema_version) || token.schema_version != kActivationSchemaVersion) {
    return std::nullopt;
  }
  if (!ReadString(p, end, token.license_id)) return std::nullopt;
  if (!ReadString(p, end, token.device_fingerprint_hash)) return std::nullopt;
  if (!ReadU64(p, end, token.issued_at)) return std::nullopt;
  if (!ReadU64(p, end, token.expires_at)) return std::nullopt;
  if (!ReadU64(p, end, token.grace_expires_at)) return std::nullopt;

  if (static_cast<std::size_t>(end - p) < token.server_nonce.size()) return std::nullopt;
  std::memcpy(token.server_nonce.data(), p, token.server_nonce.size());
  p += token.server_nonce.size();

  if (static_cast<std::size_t>(end - p) < token.vm_root.size()) return std::nullopt;
  std::memcpy(token.vm_root.data(), p, token.vm_root.size());
  p += token.vm_root.size();

  if (!ReadU64(p, end, token.sequence_number)) return std::nullopt;

  return token;
}

std::string GetActivationTokenPath(const std::string& product_id) {
  std::string sanitized_product = product_id.empty() ? "default" : product_id;
  for (char& c : sanitized_product) {
    if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_') {
      c = '_';
    }
  }

  std::filesystem::path base_dir;
  const char* override_dir = std::getenv("RTPROTECT_ACTIVATION_DIR");
  if (override_dir && override_dir[0] != '\0') {
    base_dir = std::filesystem::path(override_dir);
  } else {
#if defined(_WIN32)
    const char* local_app_data = std::getenv("LOCALAPPDATA");
    if (local_app_data && local_app_data[0] != '\0') {
      base_dir = std::filesystem::path(local_app_data) / "RTProtect";
    } else {
      const char* user_prof = std::getenv("USERPROFILE");
      if (user_prof && user_prof[0] != '\0') {
        base_dir = std::filesystem::path(user_prof) / "AppData" / "Local" / "RTProtect";
      } else {
        base_dir = std::filesystem::path(".rtprotect_activation");
      }
    }
#else
    const char* xdg_config = std::getenv("XDG_CONFIG_HOME");
    if (xdg_config && xdg_config[0] != '\0') {
      base_dir = std::filesystem::path(xdg_config) / "rtprotect";
    } else {
      const char* home = std::getenv("HOME");
      if (home && home[0] != '\0') {
        base_dir = std::filesystem::path(home) / ".config" / "rtprotect";
      } else {
        base_dir = std::filesystem::path(".rtprotect_activation");
      }
    }
#endif
  }

  std::error_code ec;
  std::filesystem::create_directories(base_dir, ec);
  return (base_dir / ("activation_" + sanitized_product + ".dat")).string();
}

bool LoadOrCreateDevToken(const std::string& product_id,
                          const std::string& license_id,
                          ActivationToken* out_token) {
  if (!out_token) return false;

  std::string token_path = GetActivationTokenPath(product_id);

  // Derive storage encryption key bound to device hardware ID
  std::string hwid = GetLocalHardwareId();
  crypto::SecureBuffer sec_hwid(reinterpret_cast<const std::uint8_t*>(hwid.data()), hwid.size());
  std::vector<std::uint8_t> salt = {'R', 'T', 'P', 'r', 'o', 't', 'e', 'c', 't', 'A', 'c', 't', 'i', 'v', 'a', 't', 'i', 'o', 'n', 'K', 'e', 'y'};
  std::string info = "rtprotect/activation-token-store/v1";
  auto derived = crypto::Hkdf::DeriveKey(sec_hwid, salt, info, crypto::kAes256KeyLen);
  if (!derived.has_value()) return false;
  auto enc_key = crypto::Aes256Key::FromBytes(derived->data(), derived->size());
  if (!enc_key.has_value()) return false;

  // Check if token already exists in local store
  if (std::filesystem::exists(token_path)) {
    auto file_bytes = tooling::ReadFile(token_path);
    if (file_bytes.has_value()) {
      auto msg = crypto::EncryptedMessage::Deserialize(file_bytes->data(), file_bytes->size());
      if (msg.has_value()) {
        crypto::AeadError err = crypto::AeadError::kNone;
        auto plaintext = crypto::Decrypt(*enc_key, *msg, nullptr, 0, &err);
        if (plaintext.has_value()) {
          auto token_opt = DeserializeActivationToken(plaintext->data(), plaintext->size());
          if (token_opt.has_value()) {
            bool lic_match = false;
            if (license_id.empty() || token_opt->license_id == license_id) {
              lic_match = true;
            }
#if defined(RTPROTECT_DEV_BUILD) || !defined(NDEBUG)
            else if ((license_id == "dev-license" || license_id.rfind("lic-dev-", 0) == 0) &&
                     (token_opt->license_id == "dev-license" || token_opt->license_id.rfind("lic-dev-", 0) == 0)) {
              lic_match = true;
            }
#endif
            if (lic_match) {
              *out_token = *token_opt;
              return true;
            }
          }
        }
      }
    }
  }

  // TODO(activation-server): replace with real /activate and /renew HTTP calls
  ActivationToken dev_token;
  dev_token.schema_version = kActivationSchemaVersion;
  dev_token.license_id = license_id.empty() ? "dev-license" : license_id;
  dev_token.device_fingerprint_hash = hwid;

  auto now = std::chrono::system_clock::now().time_since_epoch();
  std::uint64_t current_time = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(now).count());
  dev_token.issued_at = current_time;
  dev_token.expires_at = current_time + 14 * 86400;              // 14 days
  dev_token.grace_expires_at = dev_token.expires_at + 3 * 86400; // 3 days grace
  dev_token.sequence_number = 1;

  if (RAND_bytes(dev_token.server_nonce.data(), static_cast<int>(dev_token.server_nonce.size())) != 1) {
    return false;
  }
  if (RAND_bytes(dev_token.vm_root.data(), static_cast<int>(dev_token.vm_root.size())) != 1) {
    return false;
  }

  auto serialized = SerializeActivationToken(dev_token);
  if (serialized.empty()) return false;

  auto encrypted = crypto::Encrypt(*enc_key, serialized.data(), serialized.size());
  if (!encrypted.has_value()) return false;

  auto wire_bytes = encrypted->Serialize();
  if (!tooling::WriteFile(token_path, wire_bytes.data(), wire_bytes.size())) {
    return false;
  }

  *out_token = dev_token;
  return true;
}

}  // namespace rtprotect::licensing
