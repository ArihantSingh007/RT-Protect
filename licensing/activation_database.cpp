// licensing/activation_database.cpp

#include "licensing/activation_database.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <unordered_set>

#include "tooling/file_io.h"
#include "crypto/aead.h"
#include "crypto/kdf.h"
#include "licensing/hardware_id.h"

namespace rtprotect::licensing {

namespace {

bool ParseU64Strict(const std::string& s, std::uint64_t* out) {
  if (s.empty()) return false;
  char* end = nullptr;
  errno = 0;
  unsigned long long v = std::strtoull(s.c_str(), &end, 10);
  if (errno != 0 || end != s.c_str() + s.size()) return false;
  if (out) *out = static_cast<std::uint64_t>(v);
  return true;
}

bool ParseU32Strict(const std::string& s, std::uint32_t* out) {
  std::uint64_t v = 0;
  if (!ParseU64Strict(s, &v) || v > 0xFFFFFFFFULL) return false;
  if (out) *out = static_cast<std::uint32_t>(v);
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
    char c1 = hex[i * 2];
    char c2 = hex[i * 2 + 1];
    if (!std::isxdigit(static_cast<unsigned char>(c1)) ||
        !std::isxdigit(static_cast<unsigned char>(c2))) {
      return false;
    }
    auto hex_val = [](char c) -> int {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'a' && c <= 'f') return c - 'a' + 10;
      if (c >= 'A' && c <= 'F') return c - 'A' + 10;
      return -1;
    };
    int v1 = hex_val(c1);
    int v2 = hex_val(c2);
    if (v1 < 0 || v2 < 0) return false;
    out[i] = static_cast<std::uint8_t>((v1 << 4) | v2);
  }
  return true;
}

std::string EscapeField(const std::string& str) {
  std::string out;
  out.reserve(str.size());
  for (char c : str) {
    if (c == '\\') {
      out += "\\\\";
    } else if (c == '|') {
      out += "\\p";
    } else if (c == '\n') {
      out += "\\n";
    } else if (c == '\r') {
      out += "\\r";
    } else {
      out += c;
    }
  }
  return out;
}

std::string UnescapeField(const std::string& str) {
  std::string out;
  out.reserve(str.size());
  for (std::size_t i = 0; i < str.size(); ++i) {
    if (str[i] == '\\' && i + 1 < str.size()) {
      char next = str[i + 1];
      if (next == '\\') { out += '\\'; ++i; }
      else if (next == 'p') { out += '|'; ++i; }
      else if (next == 'n') { out += '\n'; ++i; }
      else if (next == 'r') { out += '\r'; ++i; }
      else { out += next; ++i; }
    } else {
      out += str[i];
    }
  }
  return out;
}

}  // namespace

const char* ToString(LicenseRecordStatus status) {
  switch (status) {
    case LicenseRecordStatus::kActive: return "active";
    case LicenseRecordStatus::kRevoked: return "revoked";
    case LicenseRecordStatus::kRefunded: return "refunded";
  }
  return "unknown";
}

std::optional<LicenseRecordStatus> ParseLicenseRecordStatus(const std::string& s) {
  if (s == "active") return LicenseRecordStatus::kActive;
  if (s == "revoked") return LicenseRecordStatus::kRevoked;
  if (s == "refunded") return LicenseRecordStatus::kRefunded;
  return std::nullopt;
}

const char* ToString(ActivationEventType type) {
  switch (type) {
    case ActivationEventType::kActivationSuccess: return "activation_success";
    case ActivationEventType::kActivationFailed: return "activation_failed";
    case ActivationEventType::kSeatLimitExceeded: return "seat_limit_exceeded";
    case ActivationEventType::kRenewalSuccess: return "renewal_success";
    case ActivationEventType::kRenewalFailed: return "renewal_failed";
    case ActivationEventType::kDeactivation: return "deactivation";
    case ActivationEventType::kRateLimited: return "rate_limited";
    case ActivationEventType::kReplayBlocked: return "replay_blocked";
  }
  return "unknown";
}

std::optional<ActivationEventType> ParseActivationEventType(const std::string& s) {
  if (s == "activation_success") return ActivationEventType::kActivationSuccess;
  if (s == "activation_failed") return ActivationEventType::kActivationFailed;
  if (s == "seat_limit_exceeded") return ActivationEventType::kSeatLimitExceeded;
  if (s == "renewal_success") return ActivationEventType::kRenewalSuccess;
  if (s == "renewal_failed") return ActivationEventType::kRenewalFailed;
  if (s == "deactivation") return ActivationEventType::kDeactivation;
  if (s == "rate_limited") return ActivationEventType::kRateLimited;
  if (s == "replay_blocked") return ActivationEventType::kReplayBlocked;
  return std::nullopt;
}

ActivationDatabase::ActivationDatabase(const std::string& db_path, const crypto::Aes256Key* encryption_key) {
  if (encryption_key) {
    std::array<std::uint8_t, 32> raw{};
    std::memcpy(raw.data(), encryption_key->bytes().data(), 32);
    encryption_key_raw_ = raw;
  }
  Open(db_path);
}

bool ActivationDatabase::IsOpen() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return is_open_valid_;
}

std::string ActivationDatabase::GetLastOpenError() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return last_open_error_;
}

void ActivationDatabase::SetAllowLegacyPlaintext(bool allow) {
  std::lock_guard<std::mutex> lock(mutex_);
  allow_legacy_plaintext_ = allow;
}

bool ActivationDatabase::MigrateToEnvelopeEncryption() {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!is_open_valid_) return false;
  envelope_encryption_enabled_ = true;
  return SaveLocked();
}

bool ActivationDatabase::Open(const std::string& db_path) {
  std::lock_guard<std::mutex> lock(mutex_);
  db_path_ = db_path;
  is_open_valid_ = false;
  last_open_error_.clear();

  if (db_path_.empty()) {
    is_open_valid_ = true;
    return true;
  }
  if (!std::filesystem::exists(db_path_)) {
    licenses_.clear();
    activations_.clear();
    used_nonces_.clear();
    events_.clear();
    is_open_valid_ = true;
    return true; // Fresh database
  }

  auto data = tooling::ReadFile(db_path_);
  if (!data.has_value()) {
    last_open_error_ = "Failed to read database file: " + db_path_;
    return false;
  }
  if (data->empty()) {
    licenses_.clear();
    activations_.clear();
    used_nonces_.clear();
    events_.clear();
    is_open_valid_ = true;
    return true;
  }

  std::unordered_map<std::string, LicenseRecord> staged_licenses;
  std::unordered_map<std::string, std::vector<ActivationRecord>> staged_activations;
  std::unordered_map<std::string, std::uint64_t> staged_used_nonces;
  std::vector<ActivationEvent> staged_events;

  std::string content(reinterpret_cast<const char*>(data->data()), data->size());
  std::istringstream stream(content);
  std::string line;
  std::string section;
  std::size_t line_no = 0;

  while (std::getline(stream, line)) {
    ++line_no;
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n' || line.back() == ' ')) {
      line.pop_back();
    }
    if (line.empty() || line[0] == '#') continue;

    if (line == "[licenses]" || line == "[activations]" || line == "[used_nonces]" || line == "[events]") {
      section = line;
      continue;
    }

    std::istringstream row(line);
    if (section == "[licenses]") {
      // Format: license_id|product_id|status|max_seats|vm_root_hex|created_at[|activation_credential_hash]
      std::string lic_id, prod_id, status_str, seats_str, root_hex, created_str, cred_hash;
      if (std::getline(row, lic_id, '|') &&
          std::getline(row, prod_id, '|') &&
          std::getline(row, status_str, '|') &&
          std::getline(row, seats_str, '|') &&
          std::getline(row, root_hex, '|') &&
          std::getline(row, created_str, '|')) {
        std::getline(row, cred_hash);
        LicenseRecord rec;
        rec.license_id = UnescapeField(lic_id);
        rec.product_id = UnescapeField(prod_id);
        auto st = ParseLicenseRecordStatus(status_str);
        if (!st.has_value()) {
          last_open_error_ = "Line " + std::to_string(line_no) + ": unrecognized license status '" + status_str + "'";
          return false;
        }
        rec.status = *st;
        if (!ParseU32Strict(seats_str, &rec.max_seats) || rec.max_seats == 0) {
          last_open_error_ = "Line " + std::to_string(line_no) + ": invalid max_seats '" + seats_str + "'";
          return false;
        }
        if (!DecryptVmRootLocked(rec.license_id, rec.product_id, root_hex, rec.vm_root)) {
          last_open_error_ = "Line " + std::to_string(line_no) + ": failed to decrypt or authenticate vm_root for license " + rec.license_id;
          return false;
        }
        if (!ParseU64Strict(created_str, &rec.created_at)) {
          last_open_error_ = "Line " + std::to_string(line_no) + ": invalid created timestamp '" + created_str + "'";
          return false;
        }
        rec.activation_credential_hash = UnescapeField(cred_hash);
        staged_licenses[rec.license_id] = rec;
      } else {
        last_open_error_ = "Line " + std::to_string(line_no) + ": malformed license row";
        return false;
      }
    } else if (section == "[activations]") {
      // Format: license_id|device_fingerprint|first_seen|last_seen|sequence_number
      std::string lic_id, dev_fp, first_str, last_str, seq_str;
      if (std::getline(row, lic_id, '|') &&
          std::getline(row, dev_fp, '|') &&
          std::getline(row, first_str, '|') &&
          std::getline(row, last_str, '|') &&
          std::getline(row, seq_str, '|')) {
        ActivationRecord rec;
        rec.license_id = UnescapeField(lic_id);
        rec.device_fingerprint = UnescapeField(dev_fp);
        if (!ParseU64Strict(first_str, &rec.first_seen) ||
            !ParseU64Strict(last_str, &rec.last_seen) ||
            !ParseU64Strict(seq_str, &rec.sequence_number)) {
          last_open_error_ = "Line " + std::to_string(line_no) + ": malformed numeric activation fields";
          return false;
        }
        staged_activations[rec.license_id].push_back(rec);
      } else {
        last_open_error_ = "Line " + std::to_string(line_no) + ": malformed activation row";
        return false;
      }
    } else if (section == "[used_nonces]") {
      // Format: nonce_hex|expires_at
      std::string nonce_hex, exp_str;
      if (std::getline(row, nonce_hex, '|') && std::getline(row, exp_str, '|')) {
        std::uint64_t exp = 0;
        if (!ParseU64Strict(exp_str, &exp)) {
          last_open_error_ = "Line " + std::to_string(line_no) + ": malformed nonce expiry";
          return false;
        }
        staged_used_nonces[nonce_hex] = exp;
      } else {
        last_open_error_ = "Line " + std::to_string(line_no) + ": malformed nonce row";
        return false;
      }
    } else if (section == "[events]") {
      // Format: timestamp|event_type|license_id|device_fingerprint|ip_address|details
      std::string ts_str, type_str, lic_id, dev_fp, ip_str, details;
      if (std::getline(row, ts_str, '|') &&
          std::getline(row, type_str, '|') &&
          std::getline(row, lic_id, '|') &&
          std::getline(row, dev_fp, '|') &&
          std::getline(row, ip_str, '|') &&
          std::getline(row, details)) {
        auto et = ParseActivationEventType(type_str);
        std::uint64_t ts = 0;
        if (!et.has_value() || !ParseU64Strict(ts_str, &ts)) {
          last_open_error_ = "Line " + std::to_string(line_no) + ": malformed event row";
          return false;
        }
        ActivationEvent evt;
        evt.timestamp = ts;
        evt.type = *et;
        evt.license_id = UnescapeField(lic_id);
        evt.device_fingerprint = UnescapeField(dev_fp);
        evt.ip_address = UnescapeField(ip_str);
        evt.details = UnescapeField(details);
        staged_events.push_back(evt);
      } else {
        last_open_error_ = "Line " + std::to_string(line_no) + ": malformed event format";
        return false;
      }
    } else {
      last_open_error_ = "Line " + std::to_string(line_no) + ": unknown section or syntax '" + line + "'";
      return false;
    }
  }

  licenses_ = std::move(staged_licenses);
  activations_ = std::move(staged_activations);
  used_nonces_ = std::move(staged_used_nonces);
  events_ = std::move(staged_events);
  is_open_valid_ = true;
  return true;
}

void ActivationDatabase::SetEncryptionKey(const crypto::Aes256Key& key) {
  std::lock_guard<std::mutex> lock(mutex_);
  std::array<std::uint8_t, 32> raw{};
  std::memcpy(raw.data(), key.bytes().data(), 32);
  encryption_key_raw_ = raw;
}

void ActivationDatabase::EnableEnvelopeEncryption(bool enable) {
  std::lock_guard<std::mutex> lock(mutex_);
  envelope_encryption_enabled_ = enable;
}

std::optional<crypto::Aes256Key> ActivationDatabase::GetEffectiveEncryptionKeyLocked() const {
  if (encryption_key_raw_.has_value()) {
    return crypto::Aes256Key::FromBytes(encryption_key_raw_->data(), encryption_key_raw_->size());
  }
  std::string hwid = GetLocalHardwareId();
  crypto::SecureBuffer sec_hwid(reinterpret_cast<const std::uint8_t*>(hwid.data()), hwid.size());
  std::vector<std::uint8_t> salt = {'R', 'T', 'P', 'r', 'o', 't', 'e', 'c', 't', 'A', 'c', 't', 'D', 'B', 'K', 'e', 'y'};
  auto derived = crypto::Hkdf::DeriveKey(sec_hwid, salt, "rtprotect/activation-db/vm-root/v1", crypto::kAes256KeyLen);
  if (derived.has_value()) {
    return crypto::Aes256Key::FromBytes(derived->data(), derived->size());
  }
  return std::nullopt;
}

std::optional<std::string> ActivationDatabase::EncryptVmRootLocked(
    const std::string& license_id,
    const std::string& product_id,
    const std::array<std::uint8_t, 32>& root) const {
  if (!envelope_encryption_enabled_) {
    if (!allow_legacy_plaintext_) {
      return std::nullopt; // Strictly fail closed: plaintext disallowed
    }
    return BytesToHex(root.data(), root.size());
  }
  auto key = GetEffectiveEncryptionKeyLocked();
  if (!key.has_value()) {
    return std::nullopt; // Fail closed: key unavailable
  }
  std::string aad = "rtprotect:db:v1:" + license_id + ":" + product_id;
  auto enc = crypto::Encrypt(*key, root.data(), root.size(),
                             reinterpret_cast<const std::uint8_t*>(aad.data()), aad.size());
  if (!enc.has_value()) {
    return std::nullopt; // Fail closed: encryption failure
  }
  return "enc:" + BytesToHex(enc->nonce.bytes, crypto::kGcmNonceLen) + ":" +
         BytesToHex(enc->tag, crypto::kGcmTagLen) + ":" +
         BytesToHex(enc->ciphertext.data(), enc->ciphertext.size());
}

bool ActivationDatabase::DecryptVmRootLocked(
    const std::string& license_id,
    const std::string& product_id,
    const std::string& field,
    std::array<std::uint8_t, 32>& out_root) const {
  if (field.rfind("enc:", 0) == 0) {
    auto colon1 = field.find(':', 4);
    if (colon1 == std::string::npos) return false;
    auto colon2 = field.find(':', colon1 + 1);
    if (colon2 == std::string::npos) return false;

    std::string iv_hex = field.substr(4, colon1 - 4);
    std::string tag_hex = field.substr(colon1 + 1, colon2 - colon1 - 1);
    std::string ct_hex = field.substr(colon2 + 1);

    crypto::EncryptedMessage msg;
    if (!HexToBytes(iv_hex, msg.nonce.bytes, crypto::kGcmNonceLen)) return false;
    if (!HexToBytes(tag_hex, msg.tag, crypto::kGcmTagLen)) return false;
    if (ct_hex.size() % 2 != 0) return false;
    msg.ciphertext.resize(ct_hex.size() / 2);
    if (!HexToBytes(ct_hex, msg.ciphertext.data(), msg.ciphertext.size())) return false;

    auto key = GetEffectiveEncryptionKeyLocked();
    if (!key.has_value()) return false;
    std::string aad = "rtprotect:db:v1:" + license_id + ":" + product_id;
    crypto::AeadError err = crypto::AeadError::kNone;
    auto plain = crypto::Decrypt(*key, msg,
                                 reinterpret_cast<const std::uint8_t*>(aad.data()), aad.size(),
                                 &err);
    if (!plain.has_value() || plain->size() != 32) return false;

    std::memcpy(out_root.data(), plain->data(), 32);
    return true;
  }
  if (!allow_legacy_plaintext_) {
    return false; // Reject legacy plaintext hex unless explicitly enabled
  }
  return HexToBytes(field, out_root.data(), out_root.size());
}

std::optional<std::string> ActivationDatabase::SerializeLocked() const {
  std::ostringstream ss;
  ss << "# RTProtect Activation Authority Database\n\n";

  ss << "[licenses]\n";
  for (const auto& pair : licenses_) {
    const auto& l = pair.second;
    auto enc_root = EncryptVmRootLocked(l.license_id, l.product_id, l.vm_root);
    if (!enc_root.has_value()) {
      return std::nullopt; // Fail closed if encryption fails
    }
    ss << EscapeField(l.license_id) << "|"
       << EscapeField(l.product_id) << "|"
       << ToString(l.status) << "|"
       << l.max_seats << "|"
       << *enc_root << "|"
       << l.created_at;
    if (!l.activation_credential_hash.empty()) {
      ss << "|" << EscapeField(l.activation_credential_hash);
    }
    ss << "\n";
  }

  ss << "\n[activations]\n";
  for (const auto& pair : activations_) {
    for (const auto& a : pair.second) {
      ss << EscapeField(a.license_id) << "|"
         << EscapeField(a.device_fingerprint) << "|"
         << a.first_seen << "|"
         << a.last_seen << "|"
         << a.sequence_number << "\n";
    }
  }

  ss << "\n[used_nonces]\n";
  for (const auto& pair : used_nonces_) {
    ss << pair.first << "|" << pair.second << "\n";
  }

  ss << "\n[events]\n";
  for (const auto& e : events_) {
    ss << e.timestamp << "|"
       << ToString(e.type) << "|"
       << EscapeField(e.license_id) << "|"
       << EscapeField(e.device_fingerprint) << "|"
       << EscapeField(e.ip_address) << "|"
       << EscapeField(e.details) << "\n";
  }

  return ss.str();
}

bool ActivationDatabase::SaveLocked() const {
  if (!is_open_valid_) return false;
  if (db_path_.empty()) return true;
  auto content = SerializeLocked();
  if (!content.has_value()) return false;

  std::string tmp_path = db_path_ + ".tmp";
  if (!tooling::WriteFile(tmp_path, reinterpret_cast<const std::uint8_t*>(content->data()), content->size())) {
    return false;
  }
  std::error_code ec;
  std::filesystem::rename(tmp_path, db_path_, ec);
  if (ec) {
    std::filesystem::remove(db_path_, ec);
    std::filesystem::rename(tmp_path, db_path_, ec);
    if (ec) {
      std::filesystem::remove(tmp_path, ec);
      return false;
    }
  }
  return true;
}

bool ActivationDatabase::Save(const std::string& db_path) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!is_open_valid_) return false;
  const std::string& target = db_path.empty() ? db_path_ : db_path;
  if (target.empty()) return true;
  auto content = SerializeLocked();
  if (!content.has_value()) return false;

  std::string tmp_path = target + ".tmp";
  if (!tooling::WriteFile(tmp_path, reinterpret_cast<const std::uint8_t*>(content->data()), content->size())) {
    return false;
  }
  std::error_code ec;
  std::filesystem::rename(tmp_path, target, ec);
  if (ec) {
    std::filesystem::remove(target, ec);
    std::filesystem::rename(tmp_path, target, ec);
    if (ec) {
      std::filesystem::remove(tmp_path, ec);
      return false;
    }
  }
  return true;
}

bool ActivationDatabase::RegisterLicense(const LicenseRecord& record, bool allow_overwrite) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (record.license_id.empty() || record.product_id.empty()) return false;
  auto it = licenses_.find(record.license_id);
  if (it != licenses_.end() && !allow_overwrite) {
    return false; // Reject duplicate license registration to prevent silent revocation resurrection
  }
  std::optional<LicenseRecord> prev;
  if (it != licenses_.end()) {
    prev = it->second;
  }
  licenses_[record.license_id] = record;
  if (!SaveLocked()) {
    if (prev.has_value()) {
      licenses_[record.license_id] = *prev;
    } else {
      licenses_.erase(record.license_id);
    }
    return false;
  }
  return true;
}

std::optional<LicenseRecord> ActivationDatabase::GetLicense(const std::string& license_id) const {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = licenses_.find(license_id);
  if (it == licenses_.end()) return std::nullopt;
  return it->second;
}

bool ActivationDatabase::UpdateLicenseStatus(const std::string& license_id, LicenseRecordStatus status) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = licenses_.find(license_id);
  if (it == licenses_.end()) return false;
  auto prev_status = it->second.status;
  it->second.status = status;
  if (!SaveLocked()) {
    it->second.status = prev_status;
    return false;
  }
  return true;
}

std::size_t ActivationDatabase::GetActiveSeatCount(const std::string& license_id) const {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = activations_.find(license_id);
  if (it == activations_.end()) return 0;
  return it->second.size();
}

std::vector<ActivationRecord> ActivationDatabase::GetActivations(const std::string& license_id) const {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = activations_.find(license_id);
  if (it == activations_.end()) return {};
  return it->second;
}

std::optional<ActivationRecord> ActivationDatabase::GetActivation(
    const std::string& license_id,
    const std::string& device_fingerprint) const {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = activations_.find(license_id);
  if (it == activations_.end()) return std::nullopt;
  for (const auto& rec : it->second) {
    if (rec.device_fingerprint == device_fingerprint) return rec;
  }
  return std::nullopt;
}

bool ActivationDatabase::RecordActivation(const ActivationRecord& record) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto& list = activations_[record.license_id];
  auto original_list = list;
  for (auto& existing : list) {
    if (existing.device_fingerprint == record.device_fingerprint) {
      existing.last_seen = record.last_seen;
      existing.sequence_number = record.sequence_number;
      if (!SaveLocked()) {
        list = std::move(original_list);
        return false;
      }
      return true;
    }
  }
  list.push_back(record);
  if (!SaveLocked()) {
    list = std::move(original_list);
    return false;
  }
  return true;
}

bool ActivationDatabase::RemoveActivation(const std::string& license_id, const std::string& device_fingerprint) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = activations_.find(license_id);
  if (it == activations_.end()) return false;
  auto& list = it->second;
  auto original_list = list;
  for (auto s_it = list.begin(); s_it != list.end(); ++s_it) {
    if (s_it->device_fingerprint == device_fingerprint) {
      list.erase(s_it);
      if (!SaveLocked()) {
        list = std::move(original_list);
        return false;
      }
      return true;
    }
  }
  return false;
}

SeatReservationResult ActivationDatabase::ReserveSeatAtomic(
    const std::string& license_id,
    const std::string& device_fingerprint,
    std::uint32_t max_seats,
    std::uint64_t current_time,
    std::uint64_t stale_timeout_seconds) {
  std::lock_guard<std::mutex> lock(mutex_);
  SeatReservationResult res;
  if (license_id.empty() || device_fingerprint.empty()) {
    res.error = "Empty license_id or device_fingerprint";
    return res;
  }

  auto& acts = activations_[license_id];
  std::vector<ActivationRecord> original_acts = acts;

  // 1. Purge stale activations exceeding lease timeout (stale-seat recovery)
  if (stale_timeout_seconds > 0) {
    acts.erase(
        std::remove_if(acts.begin(), acts.end(), [&](const ActivationRecord& a) {
          if (a.device_fingerprint == device_fingerprint) return false;
          return (current_time > a.last_seen && (current_time - a.last_seen) > stale_timeout_seconds);
        }),
        acts.end());
  }

  // 2. Existing activation for this device: re-activate/bump sequence
  for (auto& a : acts) {
    if (a.device_fingerprint == device_fingerprint) {
      res.previous_sequence_number = a.sequence_number;
      res.previous_last_seen = a.last_seen;
      a.last_seen = current_time;
      a.sequence_number++;
      if (!SaveLocked()) {
        acts = std::move(original_acts);
        res.success = false;
        res.error = "Database write-through persistence failed";
        return res;
      }
      res.success = true;
      res.is_new_seat = false;
      res.sequence_number = a.sequence_number;
      res.first_seen = a.first_seen;
      return res;
    }
  }

  // 3. New activation: enforce capacity limit
  if (acts.size() >= max_seats) {
    acts = std::move(original_acts);
    res.success = false;
    res.error = "Concurrent seat limit reached (" + std::to_string(original_acts.size()) + " of " +
                std::to_string(max_seats) + " seats active)";
    return res;
  }

  // 4. Reserve new seat
  ActivationRecord new_rec;
  new_rec.license_id = license_id;
  new_rec.device_fingerprint = device_fingerprint;
  new_rec.first_seen = current_time;
  new_rec.last_seen = current_time;
  new_rec.sequence_number = 1;
  acts.push_back(new_rec);

  if (!SaveLocked()) {
    acts = std::move(original_acts);
    res.success = false;
    res.error = "Database write-through persistence failed";
    return res;
  }

  res.success = true;
  res.is_new_seat = true;
  res.sequence_number = 1;
  res.first_seen = current_time;
  return res;
}

bool ActivationDatabase::RollbackSeatAtomic(
    const std::string& license_id,
    const std::string& device_fingerprint,
    const SeatReservationResult& reservation) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = activations_.find(license_id);
  if (it == activations_.end()) return false;
  auto& acts = it->second;
  auto original_acts = acts;

  if (reservation.is_new_seat) {
    for (auto s_it = acts.begin(); s_it != acts.end(); ++s_it) {
      if (s_it->device_fingerprint == device_fingerprint) {
        if (s_it->sequence_number != reservation.sequence_number) {
          return false; // Concurrent newer activation has already advanced this seat
        }
        acts.erase(s_it);
        if (!SaveLocked()) {
          acts = std::move(original_acts);
          return false;
        }
        return true;
      }
    }
  } else {
    for (auto& a : acts) {
      if (a.device_fingerprint == device_fingerprint) {
        if (a.sequence_number != reservation.sequence_number) {
          return false; // Concurrent newer renewal has already advanced this seat
        }
        a.sequence_number = reservation.previous_sequence_number;
        a.last_seen = reservation.previous_last_seen;
        if (!SaveLocked()) {
          acts = std::move(original_acts);
          return false;
        }
        return true;
      }
    }
  }
  return false;
}

bool ActivationDatabase::CommitRenewalAtomic(
    const std::string& client_nonce_hex,
    std::uint64_t client_nonce_expiry,
    const std::string& old_server_nonce_hex,
    std::uint64_t old_server_nonce_expiry,
    const ActivationRecord& updated_activation,
    std::uint64_t expected_sequence_number,
    std::uint64_t current_time) {
  std::lock_guard<std::mutex> lock(mutex_);

  auto c_it = used_nonces_.find(client_nonce_hex);
  if (c_it != used_nonces_.end() && c_it->second > current_time) {
    return false; // Replay detected
  }
  auto s_it = used_nonces_.find(old_server_nonce_hex);
  if (s_it != used_nonces_.end() && s_it->second > current_time) {
    return false; // Replay detected
  }

  auto act_it = activations_.find(updated_activation.license_id);
  if (act_it == activations_.end()) return false;
  auto& acts = act_it->second;

  auto target = acts.end();
  for (auto it = acts.begin(); it != acts.end(); ++it) {
    if (it->device_fingerprint == updated_activation.device_fingerprint) {
      target = it;
      break;
    }
  }
  if (target == acts.end() || target->sequence_number != expected_sequence_number) {
    return false;
  }

  auto orig_nonces = used_nonces_;
  auto orig_acts = acts;

  used_nonces_[client_nonce_hex] = client_nonce_expiry;
  used_nonces_[old_server_nonce_hex] = old_server_nonce_expiry;
  target->last_seen = updated_activation.last_seen;
  target->sequence_number = updated_activation.sequence_number;

  if (!SaveLocked()) {
    used_nonces_ = std::move(orig_nonces);
    acts = std::move(orig_acts);
    return false;
  }
  return true;
}

bool ActivationDatabase::CommitDeactivationAtomic(
    const std::string& license_id,
    const std::string& device_fingerprint,
    std::uint64_t expected_sequence_number,
    const std::string& server_nonce_hex,
    std::uint64_t nonce_expiry,
    std::uint64_t current_time) {
  std::lock_guard<std::mutex> lock(mutex_);

  auto n_it = used_nonces_.find(server_nonce_hex);
  if (n_it != used_nonces_.end() && n_it->second > current_time) {
    return false;
  }

  auto act_it = activations_.find(license_id);
  if (act_it == activations_.end()) return false;
  auto& acts = act_it->second;

  auto target = acts.end();
  for (auto it = acts.begin(); it != acts.end(); ++it) {
    if (it->device_fingerprint == device_fingerprint) {
      target = it;
      break;
    }
  }
  if (target == acts.end() || target->sequence_number != expected_sequence_number) {
    return false;
  }

  auto orig_nonces = used_nonces_;
  auto orig_acts = acts;

  used_nonces_[server_nonce_hex] = nonce_expiry;
  acts.erase(target);
  if (acts.empty()) {
    activations_.erase(act_it);
  }

  if (!SaveLocked()) {
    used_nonces_ = std::move(orig_nonces);
    activations_[license_id] = std::move(orig_acts);
    return false;
  }
  return true;
}

bool ActivationDatabase::IsNonceUsed(const std::string& nonce_hex) const {
  std::lock_guard<std::mutex> lock(mutex_);
  return used_nonces_.find(nonce_hex) != used_nonces_.end();
}

bool ActivationDatabase::RecordNonce(const std::string& nonce_hex, std::uint64_t expires_at) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (nonce_hex.empty()) return false;
  auto orig = used_nonces_;
  used_nonces_[nonce_hex] = expires_at;
  if (!SaveLocked()) {
    used_nonces_ = std::move(orig);
    return false;
  }
  return true;
}

bool ActivationDatabase::ConsumeNonceIfUnused(const std::string& nonce_hex, std::uint64_t expires_at, std::uint64_t current_time) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (nonce_hex.empty()) return false;
  auto it = used_nonces_.find(nonce_hex);
  if (it != used_nonces_.end()) {
    return false; // Already used (replay attack)
  }
  // Opportunistically prune only nonces whose stored expiry <= current_time
  if (current_time > 0) {
    for (auto pit = used_nonces_.begin(); pit != used_nonces_.end();) {
      if (pit->second <= current_time) {
        pit = used_nonces_.erase(pit);
      } else {
        ++pit;
      }
    }
  }
  auto orig = used_nonces_;
  used_nonces_[nonce_hex] = expires_at;
  if (!SaveLocked()) {
    used_nonces_ = std::move(orig);
    return false;
  }
  return true;
}

void ActivationDatabase::PruneExpiredNonces(std::uint64_t current_time) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto orig = used_nonces_;
  bool modified = false;
  for (auto it = used_nonces_.begin(); it != used_nonces_.end();) {
    if (it->second <= current_time) {
      it = used_nonces_.erase(it);
      modified = true;
    } else {
      ++it;
    }
  }
  if (modified) {
    if (!SaveLocked()) {
      used_nonces_ = std::move(orig);
    }
  }
}

bool ActivationDatabase::RecordEvent(const ActivationEvent& event) {
  std::lock_guard<std::mutex> lock(mutex_);
  events_.push_back(event);
  // Cap max in-memory events to prevent unbounded growth
  if (events_.size() > 5000) {
    events_.erase(events_.begin(), events_.begin() + 1000);
  }
  // Finding 7.3: Avoid full synchronous database rewrites on ephemeral rate-limiting events
  if (event.type == ActivationEventType::kRateLimited) {
    return true;
  }
  return SaveLocked();
}

std::vector<ActivationEvent> ActivationDatabase::GetRecentEvents(const std::string& license_id, std::size_t limit) const {
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<ActivationEvent> out;
  for (auto it = events_.rbegin(); it != events_.rend(); ++it) {
    if (license_id.empty() || it->license_id == license_id) {
      out.push_back(*it);
      if (out.size() >= limit) break;
    }
  }
  return out;
}

std::vector<ActivationEvent> ActivationDatabase::GetAllEvents() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return events_;
}

std::vector<LicenseRecord> ActivationDatabase::GetAllLicenses() const {
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<LicenseRecord> out;
  out.reserve(licenses_.size());
  for (const auto& kv : licenses_) {
    out.push_back(kv.second);
  }
  return out;
}

double ActivationDatabase::ComputeSeatChurnRisk(const std::string& license_id,
                                                std::uint64_t current_time,
                                                std::uint64_t window_seconds) const {
  std::lock_guard<std::mutex> lock(mutex_);
  auto lic_it = licenses_.find(license_id);
  if (lic_it == licenses_.end()) return 0.0;
  std::uint32_t max_seats = lic_it->second.max_seats;
  if (max_seats == 0) max_seats = 1;

  std::uint64_t window_start = (current_time > window_seconds) ? (current_time - window_seconds) : 0;

  std::unordered_set<std::string> distinct_devices;
  std::size_t abuse_events = 0;

  for (const auto& e : events_) {
    if (e.license_id == license_id && e.timestamp >= window_start && e.timestamp <= current_time) {
      if (!e.device_fingerprint.empty()) {
        distinct_devices.insert(e.device_fingerprint);
      }
      if (e.type == ActivationEventType::kRateLimited ||
          e.type == ActivationEventType::kReplayBlocked ||
          e.type == ActivationEventType::kSeatLimitExceeded ||
          e.type == ActivationEventType::kActivationFailed ||
          e.type == ActivationEventType::kRenewalFailed) {
        abuse_events++;
      }
    }
  }

  auto act_it = activations_.find(license_id);
  if (act_it != activations_.end()) {
    for (const auto& a : act_it->second) {
      if (a.last_seen >= window_start && a.last_seen <= current_time) {
        distinct_devices.insert(a.device_fingerprint);
      }
    }
  }

  double device_ratio = static_cast<double>(distinct_devices.size()) / static_cast<double>(max_seats);
  double risk = 0.0;
  if (device_ratio > 1.0) {
    // Risk starts climbing when distinct devices in window exceeds max allowed seats
    risk += (device_ratio - 1.0) * 0.25;
  }
  if (abuse_events > 0) {
    risk += (std::min)(0.5, static_cast<double>(abuse_events) * 0.1);
  }

  return (std::min)(1.0, (std::max)(0.0, risk));
}

void ActivationDatabase::Clear() {
  std::lock_guard<std::mutex> lock(mutex_);
  licenses_.clear();
  activations_.clear();
  used_nonces_.clear();
  events_.clear();
  SaveLocked();
}

}  // namespace rtprotect::licensing
