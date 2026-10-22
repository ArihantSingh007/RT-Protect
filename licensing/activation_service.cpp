// licensing/activation_service.cpp

#include "licensing/activation_service.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <sstream>

#include <openssl/rand.h>

#include "crypto/aead.h"
#include "crypto/kdf.h"
#include "licensing/activation_server.h"
#include "licensing/hardware_id.h"

namespace rtprotect::licensing {

namespace {

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

std::optional<std::string> ExtractJsonStringField(const std::string& json, const std::string& field_name) {
  std::string pattern = "\"" + field_name + "\"";
  auto pos = json.find(pattern);
  if (pos == std::string::npos) return std::nullopt;
  pos += pattern.size();
  while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':' || json[pos] == '\t')) ++pos;
  if (pos >= json.size() || json[pos] != '"') return std::nullopt;
  ++pos;
  std::string val;
  while (pos < json.size() && json[pos] != '"') {
    if (json[pos] == '\\' && pos + 1 < json.size()) {
      ++pos;
      if (json[pos] == '"') val += '"';
      else if (json[pos] == '\\') val += '\\';
      else if (json[pos] == 'n') val += '\n';
      else if (json[pos] == 'r') val += '\r';
      else if (json[pos] == 't') val += '\t';
      else val += json[pos];
    } else {
      val += json[pos];
    }
    ++pos;
  }
  return val;
}

std::string EscapeJsonString(const std::string& input) {
  std::string out;
  out.reserve(input.size() + 8);
  for (char c : input) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
          out += buf;
        } else {
          out += c;
        }
        break;
    }
  }
  return out;
}

std::uint64_t GetCurrentTimestamp() {
  auto now = std::chrono::system_clock::now().time_since_epoch();
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(now).count());
}

std::optional<crypto::Aes256Key> DeriveTransportKey(
    const std::string& license_key,
    const std::array<std::uint8_t, 32>& client_nonce,
    const std::array<std::uint8_t, 32>& server_nonce) {
  crypto::SecureBuffer sec_lic(reinterpret_cast<const std::uint8_t*>(license_key.data()), license_key.size());
  std::vector<std::uint8_t> salt;
  salt.reserve(64);
  salt.insert(salt.end(), client_nonce.begin(), client_nonce.end());
  salt.insert(salt.end(), server_nonce.begin(), server_nonce.end());
  std::string info = "rtprotect/transport/token-encryption/v1";
  auto derived = crypto::Hkdf::DeriveKey(sec_lic, salt, info, crypto::kAes256KeyLen);
  if (!derived.has_value()) return std::nullopt;
  return crypto::Aes256Key::FromBytes(derived->data(), derived->size());
}

}  // namespace

ActivationService::ActivationService(
    ActivationDatabase& db,
    integrity::Ed25519PrivateKey signing_key,
    const integrity::Ed25519PublicKey& verification_key)
    : db_(db), signing_key_(std::move(signing_key)), verification_key_(verification_key) {}

ActivateResponse ActivationService::ProcessActivate(const ActivateRequest& req, std::uint64_t current_time) {
  ActivateResponse resp;
  if (current_time == 0) current_time = GetCurrentTimestamp();

  if (req.license_key.empty() || req.device_fingerprint.empty() || req.product_id.empty()) {
    resp.status = ActivationStatus::kMalformed;
    resp.error_message = "Missing required parameters (license_key, device_fingerprint, or product_id)";
    return resp;
  }

  int retry_after = 0;
  if (!license_rate_limiter_.Allow(req.license_key, 1.0, &retry_after)) {
    resp.status = ActivationStatus::kConcurrencyLimitExceeded;
    resp.error_message = "Rate limit exceeded for license (retry after " + std::to_string(retry_after) + "s)";
    return resp;
  }

  // 1. Look up license in database
  auto lic_opt = db_.GetLicense(req.license_key);
  if (!lic_opt.has_value()) {
    resp.status = ActivationStatus::kLicenseMismatch;
    resp.error_message = "License key not found";
    return resp;
  }

  const auto& lic = *lic_opt;
  if (lic.product_id != req.product_id) {
    resp.status = ActivationStatus::kLicenseMismatch;
    resp.error_message = "License is not valid for product " + req.product_id;
    return resp;
  }

  if (lic.status != LicenseRecordStatus::kActive) {
    resp.status = ActivationStatus::kRevoked;
    resp.error_message = "License has been " + std::string(ToString(lic.status));
    return resp;
  }

  // 2. Anti-replay and validity check on client challenge nonce
  bool nonce_is_all_zero = true;
  for (std::uint8_t b : req.client_nonce) {
    if (b != 0) {
      nonce_is_all_zero = false;
      break;
    }
  }
  if (nonce_is_all_zero) {
    resp.status = ActivationStatus::kMalformed;
    resp.error_message = "Client challenge nonce cannot be missing or all-zero";
    return resp;
  }

  // Check client timestamp clock drift if timestamp was supplied
  if (req.client_timestamp > 0) {
    std::int64_t drift = std::abs(static_cast<std::int64_t>(current_time) - static_cast<std::int64_t>(req.client_timestamp));
    if (drift > 900) { // 15-minute maximum drift window (AWS SigV4 standard for distributed clock skew)
      resp.status = ActivationStatus::kMalformed;
      resp.error_message = "Client timestamp clock drift exceeds allowed 900s window";
      return resp;
    }
  }

  std::string client_nonce_hex = BytesToHex(req.client_nonce.data(), req.client_nonce.size());
  if (!db_.ConsumeNonceIfUnused(client_nonce_hex, current_time + 86400)) {
    resp.status = ActivationStatus::kNonceMismatch;
    resp.error_message = "Client challenge nonce has already been used (replay detected)";
    return resp;
  }

  // 3. Atomic seat limit enforcement and reservation with stale lease recovery
  auto seat_res = db_.ReserveSeatAtomic(req.license_key, req.device_fingerprint, lic.max_seats, current_time);
  if (!seat_res.success) {
    resp.status = ActivationStatus::kConcurrencyLimitExceeded;
    resp.error_message = seat_res.error;
    return resp;
  }

  // 4. Mint signed activation token bound to hardware ID and containing canonical vm_root
  ActivationToken token;
  token.schema_version = kActivationSchemaVersion;
  token.license_id = req.license_key;
  token.device_fingerprint_hash = req.device_fingerprint;
  token.issued_at = current_time;
  token.expires_at = current_time + 14 * 86400;              // 14 days
  token.grace_expires_at = token.expires_at + 3 * 86400;     // 3 days grace
  token.vm_root = lic.vm_root;                              // Bound canonical vm_root
  token.sequence_number = seat_res.sequence_number;

  if (RAND_bytes(resp.server_nonce.data(), static_cast<int>(resp.server_nonce.size())) != 1) {
    resp.status = ActivationStatus::kMalformed;
    resp.error_message = "Cryptographic RNG failure generating server nonce";
    return resp;
  }
  token.server_nonce = resp.server_nonce;

  if (!SignActivationToken(token, signing_key_)) {
    resp.status = ActivationStatus::kMalformed;
    resp.error_message = "Internal signing failure";
    return resp;
  }

  // 6. Encrypt token under ephemeral session key
  auto session_key = DeriveTransportKey(req.license_key, req.client_nonce, resp.server_nonce);
  if (!session_key.has_value()) {
    resp.status = ActivationStatus::kMalformed;
    resp.error_message = "Failed to derive transport key";
    return resp;
  }

  auto raw_token_bytes = SerializeActivationToken(token);
  auto encrypted = crypto::Encrypt(*session_key, raw_token_bytes.data(), raw_token_bytes.size());
  if (!encrypted.has_value()) {
    resp.status = ActivationStatus::kMalformed;
    resp.error_message = "Failed to encrypt activation token";
    return resp;
  }

  auto wire_bytes = encrypted->Serialize();
  resp.encrypted_token_hex = BytesToHex(wire_bytes.data(), wire_bytes.size());
  resp.token = token;
  resp.status = ActivationStatus::kValid;
  return resp;
}

RenewResponse ActivationService::ProcessRenew(const RenewRequest& req, std::uint64_t current_time) {
  RenewResponse resp;
  if (current_time == 0) current_time = GetCurrentTimestamp();

  if (req.token_hex.empty() || req.device_fingerprint.empty()) {
    resp.status = ActivationStatus::kMalformed;
    resp.error_message = "Missing required parameters (token or device_fingerprint)";
    return resp;
  }

  // 1. Deserialize submitted token
  std::vector<std::uint8_t> raw_token(req.token_hex.size() / 2);
  if (!HexToBytes(req.token_hex, raw_token.data(), raw_token.size())) {
    resp.status = ActivationStatus::kMalformed;
    resp.error_message = "Malformed token hex";
    return resp;
  }

  auto token_opt = DeserializeActivationToken(raw_token.data(), raw_token.size());
  if (!token_opt.has_value()) {
    resp.status = ActivationStatus::kMalformed;
    resp.error_message = "Deserialization failed for activation token";
    return resp;
  }

  const auto& token = *token_opt;

  // 2. Cryptographic signature check
  if (!VerifyActivationTokenSignature(token, verification_key_)) {
    resp.status = ActivationStatus::kInvalidSignature;
    resp.error_message = "Activation token signature verification failed";
    return resp;
  }

  int retry_after = 0;
  if (!license_rate_limiter_.Allow(token.license_id, 1.0, &retry_after)) {
    resp.status = ActivationStatus::kConcurrencyLimitExceeded;
    resp.error_message = "Rate limit exceeded for license (retry after " + std::to_string(retry_after) + "s)";
    return resp;
  }

  // 3. Grace period expiration check
  if (current_time > token.grace_expires_at) {
    resp.status = ActivationStatus::kExpired;
    resp.error_message = "Activation token has expired past its grace period and cannot be renewed";
    return resp;
  }

  // 4. Anti-replay check on client nonce
  bool client_nonce_zero = true;
  for (std::uint8_t b : req.client_nonce) {
    if (b != 0) {
      client_nonce_zero = false;
      break;
    }
  }
  if (client_nonce_zero) {
    resp.status = ActivationStatus::kMalformed;
    resp.error_message = "Client challenge nonce cannot be missing or all-zero";
    return resp;
  }
  std::string client_nonce_hex = BytesToHex(req.client_nonce.data(), req.client_nonce.size());
  if (!db_.ConsumeNonceIfUnused(client_nonce_hex, current_time + 86400)) {
    resp.status = ActivationStatus::kNonceMismatch;
    resp.error_message = "Client challenge nonce has already been used (replay detected)";
    return resp;
  }

  // 5. Atomic anti-replay check and retirement of existing token server_nonce
  std::string old_nonce_hex = BytesToHex(token.server_nonce.data(), token.server_nonce.size());
  if (!db_.ConsumeNonceIfUnused(old_nonce_hex, current_time + 86400 * 30)) {
    resp.status = ActivationStatus::kNonceMismatch;
    resp.error_message = "Token has already been renewed (anti-replay check failed)";
    return resp;
  }

  // 6. Check license status in database (checks instant revocation/chargeback)
  auto lic_opt = db_.GetLicense(token.license_id);
  if (!lic_opt.has_value()) {
    resp.status = ActivationStatus::kLicenseMismatch;
    resp.error_message = "License not found";
    return resp;
  }

  if (lic_opt->status != LicenseRecordStatus::kActive) {
    resp.status = ActivationStatus::kRevoked;
    resp.error_message = "License is " + std::string(ToString(lic_opt->status));
    return resp;
  }

  // 7. Hardware fingerprint match check (supports drift tolerance)
  if (!VerifyHardwareMatch(token.device_fingerprint_hash, req.device_fingerprint, 0.75)) {
    resp.status = ActivationStatus::kHardwareMismatch;
    resp.error_message = "Device fingerprint mismatch";
    return resp;
  }

  // 8. Mint renewed token with identical vm_root and bumped sequence number
  ActivationToken renewed = token;
  renewed.issued_at = current_time;
  renewed.expires_at = current_time + 14 * 86400;
  renewed.grace_expires_at = renewed.expires_at + 3 * 86400;
  renewed.sequence_number = token.sequence_number + 1;
  renewed.vm_root = token.vm_root; // Stable vm_root across renewals

  if (RAND_bytes(resp.server_nonce.data(), static_cast<int>(resp.server_nonce.size())) != 1) {
    resp.status = ActivationStatus::kMalformed;
    resp.error_message = "Cryptographic RNG failure generating server nonce";
    return resp;
  }
  renewed.server_nonce = resp.server_nonce;

  if (!SignActivationToken(renewed, signing_key_)) {
    resp.status = ActivationStatus::kMalformed;
    resp.error_message = "Failed to sign renewed token";
    return resp;
  }

  // 9. Update database activation record
  ActivationRecord act;
  act.license_id = token.license_id;
  act.device_fingerprint = req.device_fingerprint;
  act.first_seen = token.issued_at;
  act.last_seen = current_time;
  act.sequence_number = renewed.sequence_number;
  db_.RecordActivation(act);

  // 8. Encrypt renewed token under ephemeral session key
  auto session_key = DeriveTransportKey(token.license_id, req.client_nonce, resp.server_nonce);
  if (!session_key.has_value()) {
    resp.status = ActivationStatus::kMalformed;
    resp.error_message = "Failed to derive transport key";
    return resp;
  }

  auto raw_renewed = SerializeActivationToken(renewed);
  auto encrypted = crypto::Encrypt(*session_key, raw_renewed.data(), raw_renewed.size());
  if (!encrypted.has_value()) {
    resp.status = ActivationStatus::kMalformed;
    resp.error_message = "Failed to encrypt renewed token";
    return resp;
  }

  auto wire_bytes = encrypted->Serialize();
  resp.encrypted_token_hex = BytesToHex(wire_bytes.data(), wire_bytes.size());
  resp.token = renewed;
  resp.status = ActivationStatus::kValid;
  return resp;
}

DeactivateResponse ActivationService::ProcessDeactivate(const DeactivateRequest& req, std::uint64_t current_time) {
  DeactivateResponse resp;
  if (current_time == 0) current_time = GetCurrentTimestamp();

  if (req.token_hex.empty() || req.device_fingerprint.empty()) {
    resp.error_message = "Missing token or device_fingerprint";
    return resp;
  }

  std::vector<std::uint8_t> raw_token(req.token_hex.size() / 2);
  if (!HexToBytes(req.token_hex, raw_token.data(), raw_token.size())) {
    resp.error_message = "Malformed token hex";
    return resp;
  }

  auto token_opt = DeserializeActivationToken(raw_token.data(), raw_token.size());
  if (!token_opt.has_value()) {
    resp.error_message = "Token deserialization failed";
    return resp;
  }

  if (!VerifyActivationTokenSignature(*token_opt, verification_key_)) {
    resp.error_message = "Invalid token signature";
    return resp;
  }

  if (!VerifyHardwareMatch(token_opt->device_fingerprint_hash, req.device_fingerprint, 0.75)) {
    resp.error_message = "Hardware fingerprint mismatch";
    return resp;
  }

  // Remove activation record to free up the seat
  db_.RemoveActivation(token_opt->license_id, req.device_fingerprint);

  std::string nonce_hex = BytesToHex(token_opt->server_nonce.data(), token_opt->server_nonce.size());
  db_.RecordNonce(nonce_hex, current_time + 86400 * 30);

  resp.success = true;
  return resp;
}

std::string ActivationService::HandleActivateJson(const std::string& json_body, std::uint64_t current_time) {
  ActivateRequest req;
  auto lic = ExtractJsonStringField(json_body, "license_key");
  auto dev = ExtractJsonStringField(json_body, "device_fingerprint");
  auto prod = ExtractJsonStringField(json_body, "product_id");
  auto ver = ExtractJsonStringField(json_body, "client_version");
  auto nonce = ExtractJsonStringField(json_body, "client_nonce");
  auto ts = ExtractJsonStringField(json_body, "client_timestamp");

  if (!nonce.has_value() || nonce->size() != 64 || !HexToBytes(*nonce, req.client_nonce.data(), req.client_nonce.size())) {
    return "{\n  \"status\": \"malformed\",\n  \"error\": \"Missing or invalid 32-byte hexadecimal client_nonce\"\n}\n";
  }

  if (lic) req.license_key = *lic;
  if (dev) req.device_fingerprint = *dev;
  if (prod) req.product_id = *prod;
  if (ver) req.client_version = *ver;
  if (ts.has_value() && !ts->empty()) {
    req.client_timestamp = std::strtoull(ts->c_str(), nullptr, 10);
  }

  auto resp = ProcessActivate(req, current_time);

  std::ostringstream ss;
  ss << "{\n";
  ss << "  \"status\": \"" << ToString(resp.status) << "\",\n";
  if (!resp.error_message.empty()) {
    ss << "  \"error\": \"" << EscapeJsonString(resp.error_message) << "\",\n";
  }
  ss << "  \"server_nonce\": \"" << BytesToHex(resp.server_nonce.data(), resp.server_nonce.size()) << "\",\n";
  ss << "  \"encrypted_token\": \"" << resp.encrypted_token_hex << "\"\n";
  ss << "}\n";
  return ss.str();
}

std::string ActivationService::HandleRenewJson(const std::string& json_body, std::uint64_t current_time) {
  RenewRequest req;
  auto tok = ExtractJsonStringField(json_body, "token");
  auto dev = ExtractJsonStringField(json_body, "device_fingerprint");
  auto nonce = ExtractJsonStringField(json_body, "client_nonce");

  if (!nonce.has_value() || nonce->size() != 64 || !HexToBytes(*nonce, req.client_nonce.data(), req.client_nonce.size())) {
    return "{\n  \"status\": \"malformed\",\n  \"error\": \"Missing or invalid 32-byte hexadecimal client_nonce\"\n}\n";
  }

  if (tok) req.token_hex = *tok;
  if (dev) req.device_fingerprint = *dev;

  auto resp = ProcessRenew(req, current_time);

  std::ostringstream ss;
  ss << "{\n";
  ss << "  \"status\": \"" << ToString(resp.status) << "\",\n";
  if (!resp.error_message.empty()) {
    ss << "  \"error\": \"" << EscapeJsonString(resp.error_message) << "\",\n";
  }
  ss << "  \"server_nonce\": \"" << BytesToHex(resp.server_nonce.data(), resp.server_nonce.size()) << "\",\n";
  ss << "  \"encrypted_token\": \"" << resp.encrypted_token_hex << "\"\n";
  ss << "}\n";
  return ss.str();
}

std::string ActivationService::HandleDeactivateJson(const std::string& json_body, std::uint64_t current_time) {
  DeactivateRequest req;
  auto tok = ExtractJsonStringField(json_body, "token");
  auto dev = ExtractJsonStringField(json_body, "device_fingerprint");

  if (tok) req.token_hex = *tok;
  if (dev) req.device_fingerprint = *dev;

  auto resp = ProcessDeactivate(req, current_time);

  std::ostringstream ss;
  ss << "{\n";
  ss << "  \"success\": " << (resp.success ? "true" : "false") << ",\n";
  if (!resp.error_message.empty()) {
    ss << "  \"error\": \"" << EscapeJsonString(resp.error_message) << "\"\n";
  } else {
    ss << "  \"status\": \"deactivated\"\n";
  }
  ss << "}\n";
  return ss.str();
}

}  // namespace rtprotect::licensing
