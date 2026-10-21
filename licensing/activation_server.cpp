// licensing/activation_server.cpp

#include "licensing/activation_server.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <unordered_set>

#include <openssl/rand.h>

#include "integrity/signer.h"

namespace rtprotect::licensing {

namespace {

std::string BytesToHex(const std::uint8_t* data, std::size_t len) {
  std::ostringstream ss;
  for (std::size_t i = 0; i < len; ++i) {
    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
  }
  return ss.str();
}

}  // namespace

bool SignActivationTicket(ActivationTicket& ticket, const integrity::Ed25519PrivateKey& privkey) {
  auto bytes_to_sign = SerializeActivationTicketForSigning(ticket);
  auto sig = integrity::SignManifestBytes(bytes_to_sign, privkey);
  if (!sig.has_value()) return false;
  ticket.signature = *sig;
  return true;
}

void ActivationManager::RegisterLicense(const std::string& license_id, std::uint32_t max_concurrency) {
  std::lock_guard<std::mutex> lock(mutex_);
  licenses_[license_id] = RegisteredLicensePolicy{license_id, max_concurrency};
}

bool ActivationManager::RevokeLicense(const std::string& license_id, const std::string& reason) {
  std::lock_guard<std::mutex> lock(mutex_);
  revoked_licenses_[license_id] = reason.empty() ? "Revoked by vendor" : reason;
  active_sessions_.erase(license_id);
  return true;
}

bool ActivationManager::RevokeTicket(const std::string& ticket_id, const std::string& reason) {
  std::lock_guard<std::mutex> lock(mutex_);
  revoked_tickets_[ticket_id] = reason.empty() ? "Revoked by vendor" : reason;
  for (auto& pair : active_sessions_) {
    auto& list = pair.second;
    for (auto it = list.begin(); it != list.end();) {
      if (it->ticket_id == ticket_id) {
        it = list.erase(it);
      } else {
        ++it;
      }
    }
  }
  return true;
}

bool ActivationManager::UnrevokeLicense(const std::string& license_id) {
  std::lock_guard<std::mutex> lock(mutex_);
  return revoked_licenses_.erase(license_id) > 0;
}

bool ActivationManager::UnrevokeTicket(const std::string& ticket_id) {
  std::lock_guard<std::mutex> lock(mutex_);
  return revoked_tickets_.erase(ticket_id) > 0;
}

bool ActivationManager::IsLicenseRevoked(const std::string& license_id) const {
  std::lock_guard<std::mutex> lock(mutex_);
  return revoked_licenses_.find(license_id) != revoked_licenses_.end();
}

bool ActivationManager::IsTicketRevoked(const std::string& ticket_id) const {
  std::lock_guard<std::mutex> lock(mutex_);
  return revoked_tickets_.find(ticket_id) != revoked_tickets_.end();
}

void ActivationManager::CleanupExpiredSessions(std::uint64_t current_time) {
  if (current_time == 0) {
    auto now = std::chrono::system_clock::now().time_since_epoch();
    current_time = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(now).count());
  }

  for (auto it = active_sessions_.begin(); it != active_sessions_.end();) {
    auto& list = it->second;
    for (auto s_it = list.begin(); s_it != list.end();) {
      if (s_it->expires_at <= current_time) {
        s_it = list.erase(s_it);
      } else {
        ++s_it;
      }
    }
    if (list.empty()) {
      it = active_sessions_.erase(it);
    } else {
      ++it;
    }
  }
}

std::size_t ActivationManager::GetActiveDeviceCount(const std::string& license_id, std::uint64_t current_time) const {
  if (current_time == 0) {
    auto now = std::chrono::system_clock::now().time_since_epoch();
    current_time = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(now).count());
  }

  auto it = active_sessions_.find(license_id);
  if (it == active_sessions_.end()) return 0;

  std::unordered_set<std::string> devices;
  for (const auto& s : it->second) {
    if (s.expires_at > current_time) {
      devices.insert(s.hardware_id);
    }
  }
  return devices.size();
}

ActivationManager::IssueTicketResult ActivationManager::IssueTicket(const ActivationRequest& req,
                                                                    const integrity::Ed25519PrivateKey& privkey,
                                                                    std::uint64_t validity_seconds,
                                                                    std::uint64_t current_time) {
  std::lock_guard<std::mutex> lock(mutex_);

  if (current_time == 0) {
    auto now = std::chrono::system_clock::now().time_since_epoch();
    current_time = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(now).count());
  }

  // 1. Check if license is revoked
  auto rev_it = revoked_licenses_.find(req.license_id);
  if (rev_it != revoked_licenses_.end()) {
    return {ActivationStatus::kRevoked, std::nullopt, "License is revoked: " + rev_it->second};
  }

  // 2. Concurrency checks
  std::uint32_t max_concurrency = 1;
  auto lic_it = licenses_.find(req.license_id);
  if (lic_it != licenses_.end()) {
    max_concurrency = lic_it->second.max_concurrency;
  }

  // Purge expired sessions for this license
  auto& sessions = active_sessions_[req.license_id];
  for (auto s_it = sessions.begin(); s_it != sessions.end();) {
    if (s_it->expires_at <= current_time) {
      s_it = sessions.erase(s_it);
    } else {
      ++s_it;
    }
  }

  // Count active devices, excluding renewals from the same hardware_id
  std::unordered_set<std::string> active_devices;
  for (const auto& s : sessions) {
    if (s.hardware_id != req.hardware_id) {
      active_devices.insert(s.hardware_id);
    }
  }

  if (active_devices.size() >= max_concurrency) {
    return {ActivationStatus::kConcurrencyLimitExceeded, std::nullopt,
            "Concurrency limit of " + std::to_string(max_concurrency) + " device(s) exceeded"};
  }

  // 3. Construct ticket
  ActivationTicket ticket;
  ticket.schema_version = kActivationSchemaVersion;
  ticket.license_id = req.license_id;
  ticket.hardware_id = req.hardware_id;
  ticket.issued_at = current_time;
  ticket.expires_at = current_time + validity_seconds;
  ticket.nonce = req.nonce;

  // Random 16-byte ticket ID
  std::array<std::uint8_t, 16> id_bytes{};
  if (RAND_bytes(id_bytes.data(), static_cast<int>(id_bytes.size())) != 1) {
    auto t = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    std::memcpy(id_bytes.data(), &t, sizeof(t));
  }
  ticket.ticket_id = "tkt-" + BytesToHex(id_bytes.data(), id_bytes.size());

  // Random session key
  if (RAND_bytes(ticket.session_key.data(), static_cast<int>(ticket.session_key.size())) != 1) {
    auto t = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    std::memcpy(ticket.session_key.data(), &t, sizeof(t));
  }

  // Sign ticket
  if (!SignActivationTicket(ticket, privkey)) {
    return {ActivationStatus::kInvalidSignature, std::nullopt, "Failed to sign activation ticket with private key"};
  }

  // 4. Update session registry (replace existing session for this hardware_id or add new)
  bool replaced = false;
  for (auto& s : sessions) {
    if (s.hardware_id == req.hardware_id) {
      s.ticket_id = ticket.ticket_id;
      s.issued_at = ticket.issued_at;
      s.expires_at = ticket.expires_at;
      replaced = true;
      break;
    }
  }
  if (!replaced) {
    sessions.push_back(ActiveSession{ticket.ticket_id, ticket.hardware_id, ticket.issued_at, ticket.expires_at});
  }

  return {ActivationStatus::kValid, ticket, ""};
}

std::string ActivationManager::ExportRevocationListJson() const {
  std::lock_guard<std::mutex> lock(mutex_);
  std::ostringstream ss;
  ss << "{\n";
  ss << "  \"revoked_licenses\": [\n";
  std::size_t i = 0;
  for (const auto& [lic_id, reason] : revoked_licenses_) {
    if (i++ > 0) ss << ",\n";
    ss << "    {\"license_id\": \"" << lic_id << "\", \"reason\": \"" << reason << "\"}";
  }
  ss << "\n  ],\n";
  ss << "  \"revoked_tickets\": [\n";
  i = 0;
  for (const auto& [tkt_id, reason] : revoked_tickets_) {
    if (i++ > 0) ss << ",\n";
    ss << "    {\"ticket_id\": \"" << tkt_id << "\", \"reason\": \"" << reason << "\"}";
  }
  ss << "\n  ]\n";
  ss << "}\n";
  return ss.str();
}

bool ActivationManager::ImportRevocationListJson(const std::string& json_str) {
  std::lock_guard<std::mutex> lock(mutex_);
  // Simple robust parser for revocation entries
  auto parse_array = [&](const std::string& tag, std::unordered_map<std::string, std::string>& dest, const std::string& key_name) {
    auto pos = json_str.find("\"" + tag + "\"");
    if (pos == std::string::npos) return;
    auto start = json_str.find('[', pos);
    auto end = json_str.find(']', start);
    if (start == std::string::npos || end == std::string::npos) return;
    std::string block = json_str.substr(start, end - start + 1);

    std::size_t cur = 0;
    while ((cur = block.find('"', cur)) != std::string::npos) {
      auto end_key = block.find('"', cur + 1);
      if (end_key == std::string::npos) break;
      std::string field = block.substr(cur + 1, end_key - cur - 1);
      cur = end_key + 1;
      if (field == key_name) {
        auto val_start = block.find('"', cur);
        if (val_start == std::string::npos) break;
        auto val_end = block.find('"', val_start + 1);
        if (val_end == std::string::npos) break;
        std::string id = block.substr(val_start + 1, val_end - val_start - 1);
        cur = val_end + 1;

        std::string reason = "Revoked by vendor";
        auto reason_field = block.find("\"reason\"", cur);
        if (reason_field != std::string::npos && reason_field < block.find('}', cur)) {
          auto r_val_start = block.find('"', reason_field + 8);
          if (r_val_start != std::string::npos) {
            auto r_val_end = block.find('"', r_val_start + 1);
            if (r_val_end != std::string::npos) {
              reason = block.substr(r_val_start + 1, r_val_end - r_val_start - 1);
              cur = r_val_end + 1;
            }
          }
        }
        dest[id] = reason;
      }
    }
  };

  parse_array("revoked_licenses", revoked_licenses_, "license_id");
  parse_array("revoked_tickets", revoked_tickets_, "ticket_id");
  return true;
}

ActivationToken ActivateDevice(const std::string& license_key,
                               const std::string& hardware_id,
                               const std::string& product_id) {
  (void)product_id;
  ActivationToken token;
  token.schema_version = kActivationSchemaVersion;
  token.license_id = license_key;
  token.device_fingerprint_hash = hardware_id;

  auto now = std::chrono::system_clock::now().time_since_epoch();
  std::uint64_t current_time = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(now).count());
  token.issued_at = current_time;
  token.expires_at = current_time + 14 * 86400;              // 14 days
  token.grace_expires_at = token.expires_at + 3 * 86400;     // 3 days grace
  token.sequence_number = 1;

  if (RAND_bytes(token.server_nonce.data(), static_cast<int>(token.server_nonce.size())) != 1) {
    for (std::size_t i = 0; i < token.server_nonce.size(); ++i) {
      token.server_nonce[i] = static_cast<std::uint8_t>((i * 13 + 0x5A) & 0xFF);
    }
  }
  if (RAND_bytes(token.vm_root.data(), static_cast<int>(token.vm_root.size())) != 1) {
    for (std::size_t i = 0; i < token.vm_root.size(); ++i) {
      token.vm_root[i] = static_cast<std::uint8_t>((i * 7 + 0x3C) & 0xFF);
    }
  }

  return token;
}

ActivationToken RenewToken(const ActivationToken& current_token) {
  ActivationToken token = current_token;
  auto now = std::chrono::system_clock::now().time_since_epoch();
  std::uint64_t current_time = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(now).count());
  token.issued_at = current_time;
  token.expires_at = current_time + 14 * 86400;
  token.grace_expires_at = token.expires_at + 3 * 86400;
  token.sequence_number = current_token.sequence_number + 1;

  if (RAND_bytes(token.server_nonce.data(), static_cast<int>(token.server_nonce.size())) != 1) {
    for (std::size_t i = 0; i < token.server_nonce.size(); ++i) {
      token.server_nonce[i] = static_cast<std::uint8_t>((i * 17 + 0x7B) & 0xFF);
    }
  }
  return token;
}

}  // namespace rtprotect::licensing
