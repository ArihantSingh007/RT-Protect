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
#include "integrity/sha256.h"
#include "licensing/activation_server.h"
#include "licensing/hardware_id.h"
#include "tooling/simple_json.h"

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

bool ConstantTimeStringEquals(const std::string& a, const std::string& b) {
  if (a.size() != b.size()) return false;
  unsigned char result = 0;
  for (std::size_t i = 0; i < a.size(); ++i) {
    result |= static_cast<unsigned char>(a[i] ^ b[i]);
  }
  return result == 0;
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

std::string AnonymizeLicenseKey(const std::string& key) {
  if (key.empty()) return "<empty>";
  auto d = integrity::Sha256(reinterpret_cast<const std::uint8_t*>(key.data()), key.size());
  if (d.has_value()) {
    return "key:sha256:" + BytesToHex(d->data(), 8);
  }
  return "key:masked:" + (key.size() > 4 ? key.substr(0, 4) + "..." : "...");
}

}  // namespace

ActivationService::ActivationService(
    ActivationDatabase& db,
    integrity::Ed25519PrivateKey signing_key,
    const integrity::Ed25519PublicKey& verification_key)
    : db_(db), signing_key_(std::move(signing_key)), verification_key_(verification_key) {}

ActivateResponse ActivationService::ProcessActivate(const ActivateRequest& req, std::uint64_t current_time, bool check_rate_limit) {
  ActivateResponse resp;
  if (current_time == 0) current_time = GetCurrentTimestamp();

  if (req.license_key.empty() || req.device_fingerprint.empty() || req.product_id.empty()) {
    resp.status = ActivationStatus::kMalformed;
    resp.error_message = "Missing required parameters (license_key, device_fingerprint, or product_id)";
    return resp;
  }

  std::string anon_key = AnonymizeLicenseKey(req.license_key);

  if (check_rate_limit) {
    int retry_after = 0;
    if (!license_rate_limiter_.Allow(anon_key, 1.0, &retry_after)) {
      resp.status = ActivationStatus::kConcurrencyLimitExceeded;
      resp.error_message = "Rate limit exceeded for license (retry after " + std::to_string(retry_after) + "s)";
      db_.RecordEvent({current_time, ActivationEventType::kRateLimited, anon_key, req.device_fingerprint, req.client_ip, resp.error_message});
      return resp;
    }
  }

  // 1. Look up license in database
  auto lic_opt = db_.GetLicense(req.license_key);
  if (!lic_opt.has_value()) {
    resp.status = ActivationStatus::kLicenseMismatch;
    resp.error_message = "License key not found";
    db_.RecordEvent({current_time, ActivationEventType::kActivationFailed, anon_key, req.device_fingerprint, req.client_ip, resp.error_message});
    return resp;
  }

  const auto& lic = *lic_opt;
  std::string safe_license_id = lic.license_id;

  if (lic.product_id != req.product_id) {
    resp.status = ActivationStatus::kLicenseMismatch;
    resp.error_message = "License is not valid for product " + req.product_id;
    db_.RecordEvent({current_time, ActivationEventType::kActivationFailed, safe_license_id, req.device_fingerprint, req.client_ip, resp.error_message});
    return resp;
  }

  if (lic.status != LicenseRecordStatus::kActive) {
    resp.status = ActivationStatus::kRevoked;
    resp.error_message = "License has been " + std::string(ToString(lic.status));
    db_.RecordEvent({current_time, ActivationEventType::kActivationFailed, safe_license_id, req.device_fingerprint, req.client_ip, resp.error_message});
    return resp;
  }

  // Validate activation credential secret if configured on license or required by server policy
  if (lic.activation_credential_hash.empty()) {
    if (require_activation_credentials_) {
      resp.status = ActivationStatus::kMalformed;
      resp.error_message = "License record lacks mandatory activation credential verifier in production mode";
      db_.RecordEvent({current_time, ActivationEventType::kActivationFailed, safe_license_id, req.device_fingerprint, req.client_ip, resp.error_message});
      return resp;
    }
  } else {
    if (req.activation_credential.empty()) {
      resp.status = ActivationStatus::kMalformed;
      resp.error_message = "Activation credential is required for this license";
      db_.RecordEvent({current_time, ActivationEventType::kActivationFailed, safe_license_id, req.device_fingerprint, req.client_ip, resp.error_message});
      return resp;
    }
    auto cred_hash = integrity::Sha256(
        reinterpret_cast<const std::uint8_t*>(req.activation_credential.data()),
        req.activation_credential.size());
    if (!cred_hash.has_value()) {
      resp.status = ActivationStatus::kMalformed;
      resp.error_message = "Hash computation failure";
      return resp;
    }
    std::string cred_hash_hex = BytesToHex(cred_hash->data(), cred_hash->size());
    if (!ConstantTimeStringEquals(cred_hash_hex, lic.activation_credential_hash)) {
      resp.status = ActivationStatus::kLicenseMismatch;
      resp.error_message = "Invalid activation credential";
      db_.RecordEvent({current_time, ActivationEventType::kActivationFailed, safe_license_id, req.device_fingerprint, req.client_ip, resp.error_message});
      return resp;
    }
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
    db_.RecordEvent({current_time, ActivationEventType::kActivationFailed, safe_license_id, req.device_fingerprint, req.client_ip, resp.error_message});
    return resp;
  }

  // Check client timestamp clock drift if timestamp was supplied
  if (req.client_timestamp > 0) {
    std::int64_t drift = std::abs(static_cast<std::int64_t>(current_time) - static_cast<std::int64_t>(req.client_timestamp));
    if (drift > 900) { // 15-minute maximum drift window
      resp.status = ActivationStatus::kMalformed;
      resp.error_message = "Client timestamp clock drift exceeds allowed 900s window";
      db_.RecordEvent({current_time, ActivationEventType::kActivationFailed, safe_license_id, req.device_fingerprint, req.client_ip, resp.error_message});
      return resp;
    }
  }

  std::string client_nonce_hex = BytesToHex(req.client_nonce.data(), req.client_nonce.size());
  if (db_.IsNonceUsed(client_nonce_hex)) {
    resp.status = ActivationStatus::kNonceMismatch;
    resp.error_message = "Client challenge nonce has already been used (replay detected)";
    db_.RecordEvent({current_time, ActivationEventType::kReplayBlocked, safe_license_id, req.device_fingerprint, req.client_ip, resp.error_message});
    return resp;
  }

  // 3. Atomic seat limit enforcement and reservation with stale lease recovery
  auto seat_res = db_.ReserveSeatAtomic(safe_license_id, req.device_fingerprint, lic.max_seats, current_time);
  if (!seat_res.success) {
    resp.status = ActivationStatus::kConcurrencyLimitExceeded;
    resp.error_message = seat_res.error;
    db_.RecordEvent({current_time, ActivationEventType::kSeatLimitExceeded, safe_license_id, req.device_fingerprint, req.client_ip, resp.error_message});
    return resp;
  }

  // 4. Mint signed activation token bound to hardware ID and containing canonical vm_root
  ActivationToken token;
  token.schema_version = kActivationSchemaVersion;
  token.license_id = safe_license_id;
  token.device_fingerprint_hash = req.device_fingerprint;
  token.issued_at = current_time;
  token.expires_at = current_time + 14 * 86400;              // 14 days
  token.grace_expires_at = token.expires_at + 3 * 86400;     // 3 days grace
  token.vm_root = lic.vm_root;                              // Bound canonical vm_root
  token.sequence_number = seat_res.sequence_number;

  if (RAND_bytes(resp.server_nonce.data(), static_cast<int>(resp.server_nonce.size())) != 1) {
    db_.RollbackSeatAtomic(safe_license_id, req.device_fingerprint, seat_res);
    resp.status = ActivationStatus::kMalformed;
    resp.error_message = "Cryptographic RNG failure generating server nonce";
    return resp;
  }
  token.server_nonce = resp.server_nonce;

  if (!SignActivationToken(token, signing_key_)) {
    db_.RollbackSeatAtomic(safe_license_id, req.device_fingerprint, seat_res);
    resp.status = ActivationStatus::kMalformed;
    resp.error_message = "Internal signing failure";
    return resp;
  }

  // 5. Encrypt token under ephemeral session key (using activation_credential if available, else license_key)
  auto session_key = DeriveTransportKey(!req.activation_credential.empty() ? req.activation_credential : req.license_key,
                                        req.client_nonce, resp.server_nonce);
  if (!session_key.has_value()) {
    db_.RollbackSeatAtomic(safe_license_id, req.device_fingerprint, seat_res);
    resp.status = ActivationStatus::kMalformed;
    resp.error_message = "Failed to derive transport key";
    return resp;
  }

  auto raw_token_bytes = SerializeActivationToken(token);
  auto encrypted = crypto::Encrypt(*session_key, raw_token_bytes.data(), raw_token_bytes.size());
  if (!encrypted.has_value()) {
    db_.RollbackSeatAtomic(safe_license_id, req.device_fingerprint, seat_res);
    resp.status = ActivationStatus::kMalformed;
    resp.error_message = "Failed to encrypt activation token";
    return resp;
  }

  // 6. Transactional commit: consume nonce only now that encryption has succeeded
  if (!db_.ConsumeNonceIfUnused(client_nonce_hex, current_time + 86400, current_time)) {
    db_.RollbackSeatAtomic(safe_license_id, req.device_fingerprint, seat_res);
    resp.status = ActivationStatus::kNonceMismatch;
    resp.error_message = "Nonce consumption collision during activation commit";
    return resp;
  }

  auto wire_bytes = encrypted->Serialize();
  resp.encrypted_token_hex = BytesToHex(wire_bytes.data(), wire_bytes.size());
  resp.token = token;
  resp.status = ActivationStatus::kValid;
  db_.RecordEvent({current_time, ActivationEventType::kActivationSuccess, safe_license_id, req.device_fingerprint, req.client_ip, "Activated seat seq=" + std::to_string(seat_res.sequence_number)});
  return resp;
}

RenewResponse ActivationService::ProcessRenew(const RenewRequest& req, std::uint64_t current_time, bool check_rate_limit) {
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

  if (check_rate_limit) {
    int retry_after = 0;
    if (!license_rate_limiter_.Allow(token.license_id, 1.0, &retry_after)) {
      resp.status = ActivationStatus::kConcurrencyLimitExceeded;
      resp.error_message = "Rate limit exceeded for license (retry after " + std::to_string(retry_after) + "s)";
      db_.RecordEvent({current_time, ActivationEventType::kRateLimited, token.license_id, req.device_fingerprint, req.client_ip, resp.error_message});
      return resp;
    }
  }

  // 3. Grace period expiration check
  if (current_time > token.grace_expires_at) {
    resp.status = ActivationStatus::kExpired;
    resp.error_message = "Activation token has expired past its grace period and cannot be renewed";
    db_.RecordEvent({current_time, ActivationEventType::kRenewalFailed, token.license_id, req.device_fingerprint, req.client_ip, resp.error_message});
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
    db_.RecordEvent({current_time, ActivationEventType::kRenewalFailed, token.license_id, req.device_fingerprint, req.client_ip, resp.error_message});
    return resp;
  }
  std::string client_nonce_hex = BytesToHex(req.client_nonce.data(), req.client_nonce.size());
  if (db_.IsNonceUsed(client_nonce_hex)) {
    resp.status = ActivationStatus::kNonceMismatch;
    resp.error_message = "Client challenge nonce has already been used (replay detected)";
    db_.RecordEvent({current_time, ActivationEventType::kReplayBlocked, token.license_id, req.device_fingerprint, req.client_ip, resp.error_message});
    return resp;
  }

  // 5. Anti-replay check of existing token server_nonce
  std::string old_nonce_hex = BytesToHex(token.server_nonce.data(), token.server_nonce.size());
  if (db_.IsNonceUsed(old_nonce_hex)) {
    resp.status = ActivationStatus::kNonceMismatch;
    resp.error_message = "Token has already been renewed (anti-replay check failed)";
    db_.RecordEvent({current_time, ActivationEventType::kReplayBlocked, token.license_id, req.device_fingerprint, req.client_ip, resp.error_message});
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

  // Verify token sequence strictly against current database activation record
  auto current_act = db_.GetActivation(token.license_id, req.device_fingerprint);
  if (!current_act.has_value()) {
    resp.status = ActivationStatus::kRevoked;
    resp.error_message = "No active seat record found for device";
    db_.RecordEvent({current_time, ActivationEventType::kRenewalFailed, token.license_id, req.device_fingerprint, req.client_ip, resp.error_message});
    return resp;
  }
  if (token.sequence_number != current_act->sequence_number) {
    resp.status = ActivationStatus::kRevoked;
    resp.error_message = "Stale token sequence (supplied=" + std::to_string(token.sequence_number) + ", current=" + std::to_string(current_act->sequence_number) + ")";
    db_.RecordEvent({current_time, ActivationEventType::kRenewalFailed, token.license_id, req.device_fingerprint, req.client_ip, resp.error_message});
    return resp;
  }

  // 8. Mint renewed token with identical vm_root and bumped sequence number
  ActivationToken renewed = token;
  renewed.issued_at = current_time;
  renewed.expires_at = current_time + 14 * 86400;
  renewed.grace_expires_at = renewed.expires_at + 3 * 86400;
  renewed.sequence_number = current_act->sequence_number + 1;
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

  // 9. Encrypt renewed token under ephemeral session key
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

  // 10. Atomic transactional commit: consume nonces and commit activation record under single lock
  ActivationRecord act;
  act.license_id = token.license_id;
  act.device_fingerprint = req.device_fingerprint;
  act.first_seen = token.issued_at;
  act.last_seen = current_time;
  act.sequence_number = renewed.sequence_number;
  if (!db_.CommitRenewalAtomic(client_nonce_hex, current_time + 86400,
                               old_nonce_hex, current_time + 86400 * 30,
                               act, current_act->sequence_number, current_time)) {
    resp.status = ActivationStatus::kMalformed;
    resp.error_message = "Atomic renewal commit failed (nonce replay or concurrent modification)";
    return resp;
  }

  auto wire_bytes = encrypted->Serialize();
  resp.encrypted_token_hex = BytesToHex(wire_bytes.data(), wire_bytes.size());
  resp.token = renewed;
  resp.status = ActivationStatus::kValid;
  db_.RecordEvent({current_time, ActivationEventType::kRenewalSuccess, token.license_id, req.device_fingerprint, req.client_ip, "Renewed seat seq=" + std::to_string(renewed.sequence_number)});
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

  // Require current active record and match sequence strictly
  auto current_act = db_.GetActivation(token_opt->license_id, req.device_fingerprint);
  if (!current_act.has_value()) {
    resp.error_message = "No active activation record found for device";
    return resp;
  }
  if (token_opt->sequence_number != current_act->sequence_number) {
    resp.error_message = "Stale token sequence: cannot deactivate newer activation record";
    return resp;
  }

  std::string nonce_hex = BytesToHex(token_opt->server_nonce.data(), token_opt->server_nonce.size());
  if (!db_.CommitDeactivationAtomic(token_opt->license_id, req.device_fingerprint,
                                   current_act->sequence_number, nonce_hex,
                                   current_time + 86400 * 30, current_time)) {
    resp.error_message = "Atomic deactivation commit failed";
    return resp;
  }

  db_.RecordEvent({current_time, ActivationEventType::kDeactivation, token_opt->license_id, req.device_fingerprint, req.client_ip, "Deactivated seat"});
  resp.success = true;
  return resp;
}

std::string ActivationService::HandleActivateJson(const std::string& json_body, std::uint64_t current_time, const std::string& client_ip) {
  if (current_time == 0) current_time = GetCurrentTimestamp();

  // Enforce IP rate limiting
  int retry_after = 0;
  if (!client_ip.empty() && !ip_rate_limiter_.Allow(client_ip, 1.0, &retry_after)) {
    db_.RecordEvent({current_time, ActivationEventType::kRateLimited, "", "", client_ip, "IP rate limit exceeded"});
    std::ostringstream ss;
    ss << "{\n"
       << "  \"status\": \"rate_limited\",\n"
       << "  \"error\": \"Rate limit exceeded for IP address (retry after " << retry_after << "s)\",\n"
       << "  \"retry_after\": " << retry_after << "\n"
       << "}\n";
    return ss.str();
  }

  auto root = tooling::JsonValue::Parse(json_body);
  if (!root.has_value() || !root->is_object()) {
    return "{\n  \"status\": \"malformed\",\n  \"error\": \"Malformed or invalid JSON body\"\n}\n";
  }

  const auto& obj = *root;
  ActivateRequest req;
  req.client_ip = client_ip;
  req.license_key = obj["license_key"].as_string();
  req.device_fingerprint = obj["device_fingerprint"].as_string();
  req.product_id = obj["product_id"].as_string();
  req.client_version = obj.contains("client_version") ? obj["client_version"].as_string() : "1.0.0";
  req.activation_credential = obj["activation_credential"].as_string();
  if (req.activation_credential.empty() && obj.contains("activation_secret")) {
    req.activation_credential = obj["activation_secret"].as_string();
  }
  if (obj.contains("client_timestamp")) {
    req.client_timestamp = static_cast<std::uint64_t>(obj["client_timestamp"].as_int());
  }

  std::string nonce = obj["client_nonce"].as_string();
  if (nonce.size() != 64 || !HexToBytes(nonce, req.client_nonce.data(), req.client_nonce.size())) {
    return "{\n  \"status\": \"malformed\",\n  \"error\": \"Missing or invalid 32-byte hexadecimal client_nonce\"\n}\n";
  }

  // Enforce license rate limiting
  std::string anon_key = AnonymizeLicenseKey(req.license_key);
  if (!req.license_key.empty() && !license_rate_limiter_.Allow(anon_key, 1.0, &retry_after)) {
    db_.RecordEvent({current_time, ActivationEventType::kRateLimited, anon_key, req.device_fingerprint, client_ip, "License rate limit exceeded"});
    std::ostringstream ss;
    ss << "{\n"
       << "  \"status\": \"rate_limited\",\n"
       << "  \"error\": \"Rate limit exceeded for license key (retry after " << retry_after << "s)\",\n"
       << "  \"retry_after\": " << retry_after << "\n"
       << "}\n";
    return ss.str();
  }

  auto resp = ProcessActivate(req, current_time, /*check_rate_limit=*/false);

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

std::string ActivationService::HandleRenewJson(const std::string& json_body, std::uint64_t current_time, const std::string& client_ip) {
  if (current_time == 0) current_time = GetCurrentTimestamp();

  // Enforce IP rate limiting
  int retry_after = 0;
  if (!client_ip.empty() && !ip_rate_limiter_.Allow(client_ip, 1.0, &retry_after)) {
    db_.RecordEvent({current_time, ActivationEventType::kRateLimited, "", "", client_ip, "IP rate limit exceeded"});
    std::ostringstream ss;
    ss << "{\n"
       << "  \"status\": \"rate_limited\",\n"
       << "  \"error\": \"Rate limit exceeded for IP address (retry after " << retry_after << "s)\",\n"
       << "  \"retry_after\": " << retry_after << "\n"
       << "}\n";
    return ss.str();
  }

  auto root = tooling::JsonValue::Parse(json_body);
  if (!root.has_value() || !root->is_object()) {
    return "{\n  \"status\": \"malformed\",\n  \"error\": \"Malformed or invalid JSON body\"\n}\n";
  }

  const auto& obj = *root;
  RenewRequest req;
  req.client_ip = client_ip;
  req.token_hex = obj["token"].as_string();
  req.device_fingerprint = obj["device_fingerprint"].as_string();

  std::string nonce = obj["client_nonce"].as_string();
  if (nonce.size() != 64 || !HexToBytes(nonce, req.client_nonce.data(), req.client_nonce.size())) {
    return "{\n  \"status\": \"malformed\",\n  \"error\": \"Missing or invalid 32-byte hexadecimal client_nonce\"\n}\n";
  }

  // Enforce license rate limiting if token can be parsed
  if (req.token_hex.size() >= 64) {
    std::vector<std::uint8_t> raw_token(req.token_hex.size() / 2);
    if (HexToBytes(req.token_hex, raw_token.data(), raw_token.size())) {
      auto token_opt = DeserializeActivationToken(raw_token.data(), raw_token.size());
      if (token_opt.has_value()) {
        if (!license_rate_limiter_.Allow(token_opt->license_id, 1.0, &retry_after)) {
          db_.RecordEvent({current_time, ActivationEventType::kRateLimited, token_opt->license_id, req.device_fingerprint, client_ip, "License rate limit exceeded"});
          std::ostringstream ss;
          ss << "{\n"
             << "  \"status\": \"rate_limited\",\n"
             << "  \"error\": \"Rate limit exceeded for license key (retry after " << retry_after << "s)\",\n"
             << "  \"retry_after\": " << retry_after << "\n"
             << "}\n";
          return ss.str();
        }
      }
    }
  }

  auto resp = ProcessRenew(req, current_time, /*check_rate_limit=*/false);

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

std::string ActivationService::HandleDeactivateJson(const std::string& json_body, std::uint64_t current_time, const std::string& client_ip) {
  auto root = tooling::JsonValue::Parse(json_body);
  if (!root.has_value() || !root->is_object()) {
    return "{\n  \"success\": false,\n  \"error\": \"Malformed or invalid JSON body\"\n}\n";
  }

  const auto& obj = *root;
  DeactivateRequest req;
  req.client_ip = client_ip;
  req.token_hex = obj["token"].as_string();
  req.device_fingerprint = obj["device_fingerprint"].as_string();

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

double ActivationService::ComputeSeatChurnRisk(const std::string& license_id, std::uint64_t current_time) const {
  if (current_time == 0) current_time = GetCurrentTimestamp();
  return db_.ComputeSeatChurnRisk(license_id, current_time);
}

std::vector<ActivationEvent> ActivationService::GetRecentEvents(const std::string& license_id, std::size_t limit) const {
  return db_.GetRecentEvents(license_id, limit);
}

}  // namespace rtprotect::licensing
