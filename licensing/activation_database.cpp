// licensing/activation_database.cpp

#include "licensing/activation_database.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>

#include "tooling/file_io.h"

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

ActivationDatabase::ActivationDatabase(const std::string& db_path) {
  Open(db_path);
}

bool ActivationDatabase::Open(const std::string& db_path) {
  std::lock_guard<std::mutex> lock(mutex_);
  db_path_ = db_path;
  licenses_.clear();
  activations_.clear();
  used_nonces_.clear();

  if (db_path_.empty() || !std::filesystem::exists(db_path_)) {
    return true; // Fresh database
  }

  auto data = tooling::ReadFile(db_path_);
  if (!data.has_value() || data->empty()) return false;

  std::string content(reinterpret_cast<const char*>(data->data()), data->size());
  std::istringstream stream(content);
  std::string line;
  std::string section;

  while (std::getline(stream, line)) {
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n' || line.back() == ' ')) {
      line.pop_back();
    }
    if (line.empty() || line[0] == '#') continue;

    if (line == "[licenses]" || line == "[activations]" || line == "[used_nonces]") {
      section = line;
      continue;
    }

    std::istringstream row(line);
    if (section == "[licenses]") {
      // Format: license_id|product_id|status|max_seats|vm_root_hex|created_at
      std::string lic_id, prod_id, status_str, seats_str, root_hex, created_str;
      if (std::getline(row, lic_id, '|') &&
          std::getline(row, prod_id, '|') &&
          std::getline(row, status_str, '|') &&
          std::getline(row, seats_str, '|') &&
          std::getline(row, root_hex, '|') &&
          std::getline(row, created_str, '|')) {
        LicenseRecord rec;
        rec.license_id = lic_id;
        rec.product_id = prod_id;
        auto st = ParseLicenseRecordStatus(status_str);
        if (!st.has_value()) {
          // Fail closed: ignore corrupted or unknown status instead of defaulting to kActive
          continue;
        }
        rec.status = *st;
        rec.max_seats = static_cast<std::uint32_t>(std::strtoul(seats_str.c_str(), nullptr, 10));
        HexToBytes(root_hex, rec.vm_root.data(), rec.vm_root.size());
        rec.created_at = std::strtoull(created_str.c_str(), nullptr, 10);
        licenses_[rec.license_id] = rec;
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
        rec.license_id = lic_id;
        rec.device_fingerprint = dev_fp;
        rec.first_seen = std::strtoull(first_str.c_str(), nullptr, 10);
        rec.last_seen = std::strtoull(last_str.c_str(), nullptr, 10);
        rec.sequence_number = std::strtoull(seq_str.c_str(), nullptr, 10);
        activations_[rec.license_id].push_back(rec);
      }
    } else if (section == "[used_nonces]") {
      // Format: nonce_hex|expires_at
      std::string nonce_hex, exp_str;
      if (std::getline(row, nonce_hex, '|') && std::getline(row, exp_str, '|')) {
        std::uint64_t exp = std::strtoull(exp_str.c_str(), nullptr, 10);
        used_nonces_[nonce_hex] = exp;
      }
    }
  }

  return true;
}

bool ActivationDatabase::SaveLocked() const {
  if (db_path_.empty()) return true;

  std::ostringstream ss;
  ss << "# RTProtect Activation Authority Database\n\n";

  ss << "[licenses]\n";
  for (const auto& pair : licenses_) {
    const auto& l = pair.second;
    ss << l.license_id << "|"
       << l.product_id << "|"
       << ToString(l.status) << "|"
       << l.max_seats << "|"
       << BytesToHex(l.vm_root.data(), l.vm_root.size()) << "|"
       << l.created_at << "\n";
  }

  ss << "\n[activations]\n";
  for (const auto& pair : activations_) {
    for (const auto& a : pair.second) {
      ss << a.license_id << "|"
         << a.device_fingerprint << "|"
         << a.first_seen << "|"
         << a.last_seen << "|"
         << a.sequence_number << "\n";
    }
  }

  ss << "\n[used_nonces]\n";
  for (const auto& pair : used_nonces_) {
    ss << pair.first << "|" << pair.second << "\n";
  }

  std::string content = ss.str();
  return tooling::WriteFile(db_path_, reinterpret_cast<const std::uint8_t*>(content.data()), content.size());
}

bool ActivationDatabase::Save(const std::string& db_path) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (db_path.empty() || db_path == db_path_) {
    return SaveLocked();
  }

  std::ostringstream ss;
  ss << "# RTProtect Activation Authority Database\n\n";

  ss << "[licenses]\n";
  for (const auto& pair : licenses_) {
    const auto& l = pair.second;
    ss << l.license_id << "|"
       << l.product_id << "|"
       << ToString(l.status) << "|"
       << l.max_seats << "|"
       << BytesToHex(l.vm_root.data(), l.vm_root.size()) << "|"
       << l.created_at << "\n";
  }

  ss << "\n[activations]\n";
  for (const auto& pair : activations_) {
    for (const auto& a : pair.second) {
      ss << a.license_id << "|"
         << a.device_fingerprint << "|"
         << a.first_seen << "|"
         << a.last_seen << "|"
         << a.sequence_number << "\n";
    }
  }

  ss << "\n[used_nonces]\n";
  for (const auto& pair : used_nonces_) {
    ss << pair.first << "|" << pair.second << "\n";
  }

  std::string content = ss.str();
  return tooling::WriteFile(db_path, reinterpret_cast<const std::uint8_t*>(content.data()), content.size());
}

bool ActivationDatabase::RegisterLicense(const LicenseRecord& record) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (record.license_id.empty() || record.product_id.empty()) return false;
  licenses_[record.license_id] = record;
  SaveLocked();
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
  it->second.status = status;
  SaveLocked();
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
  for (auto& existing : list) {
    if (existing.device_fingerprint == record.device_fingerprint) {
      existing.last_seen = record.last_seen;
      existing.sequence_number = record.sequence_number;
      SaveLocked();
      return true;
    }
  }
  list.push_back(record);
  SaveLocked();
  return true;
}

bool ActivationDatabase::RemoveActivation(const std::string& license_id, const std::string& device_fingerprint) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = activations_.find(license_id);
  if (it == activations_.end()) return false;
  auto& list = it->second;
  for (auto s_it = list.begin(); s_it != list.end(); ++s_it) {
    if (s_it->device_fingerprint == device_fingerprint) {
      list.erase(s_it);
      SaveLocked();
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
      a.last_seen = current_time;
      a.sequence_number++;
      res.success = true;
      res.is_new_seat = false;
      res.sequence_number = a.sequence_number;
      res.first_seen = a.first_seen;
      SaveLocked();
      return res;
    }
  }

  // 3. New activation: enforce capacity limit
  if (acts.size() >= max_seats) {
    res.success = false;
    res.error = "Concurrent seat limit reached (" + std::to_string(acts.size()) + " of " +
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

  res.success = true;
  res.is_new_seat = true;
  res.sequence_number = 1;
  res.first_seen = current_time;

  SaveLocked();
  return res;
}

bool ActivationDatabase::IsNonceUsed(const std::string& nonce_hex) const {
  std::lock_guard<std::mutex> lock(mutex_);
  return used_nonces_.find(nonce_hex) != used_nonces_.end();
}

bool ActivationDatabase::RecordNonce(const std::string& nonce_hex, std::uint64_t expires_at) {
  std::lock_guard<std::mutex> lock(mutex_);
  used_nonces_[nonce_hex] = expires_at;
  SaveLocked();
  return true;
}

bool ActivationDatabase::ConsumeNonceIfUnused(const std::string& nonce_hex, std::uint64_t expires_at) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (nonce_hex.empty()) return false;
  auto it = used_nonces_.find(nonce_hex);
  if (it != used_nonces_.end()) {
    return false; // Already used (replay attack)
  }
  // Opportunistically prune expired nonces to prevent unbounded growth
  std::uint64_t now = (expires_at > 86400) ? (expires_at - 86400) : expires_at;
  for (auto pit = used_nonces_.begin(); pit != used_nonces_.end();) {
    if (pit->second <= now) {
      pit = used_nonces_.erase(pit);
    } else {
      ++pit;
    }
  }
  used_nonces_[nonce_hex] = expires_at;
  SaveLocked();
  return true;
}

void ActivationDatabase::PruneExpiredNonces(std::uint64_t current_time) {
  std::lock_guard<std::mutex> lock(mutex_);
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
    SaveLocked();
  }
}

void ActivationDatabase::Clear() {
  std::lock_guard<std::mutex> lock(mutex_);
  licenses_.clear();
  activations_.clear();
  used_nonces_.clear();
  SaveLocked();
}

}  // namespace rtprotect::licensing
