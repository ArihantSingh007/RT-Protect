// licensing/countermeasure_config.cpp
//
// Continuous Response Channel implementation.

#include "licensing/countermeasure_config.h"

#include <atomic>
#include <ctime>
#include <cstring>
#include <vector>
#include <openssl/evp.h>

#include "integrity/verifier.h"
#include "licensing/secure_storage.h"

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

bool WriteString(std::vector<std::uint8_t>& buf, const std::string& str) {
  if (str.size() > 512) return false;
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

bool ReadString(const std::uint8_t*& p, const std::uint8_t* end, std::string& out) {
  std::uint16_t len = 0;
  if (!ReadU16(p, end, len)) return false;
  if (end - p < len) return false;
  out.assign(reinterpret_cast<const char*>(p), len);
  p += len;
  return true;
}

}  // namespace

std::vector<std::uint8_t> SerializeCountermeasureConfigForSigning(const CountermeasureConfig& cfg) {
  // Enforce list limits to prevent malformed or oversized payloads
  if (cfg.blacklisted_process_names.size() > 1000 ||
      cfg.blacklisted_process_hashes.size() > 5000 ||
      cfg.blacklisted_window_titles.size() > 1000 ||
      cfg.blacklisted_driver_hashes.size() > 5000) {
    return {};
  }

  // Validate threshold ranges
  if (cfg.risk_threshold_restrict < 0 || cfg.risk_threshold_restrict > 100 ||
      cfg.risk_threshold_terminate < 0 || cfg.risk_threshold_terminate > 100 ||
      cfg.risk_threshold_restrict >= cfg.risk_threshold_terminate) {
    return {};
  }

  std::vector<std::uint8_t> buf;
  buf.reserve(512);

  WriteU32(buf, kCountermeasureConfigMagic);
  WriteU32(buf, cfg.schema_version);
  WriteU64(buf, cfg.sequence_number);
  WriteU64(buf, cfg.issued_at);
  WriteU64(buf, cfg.expires_at);

  // Product ID binding
  if (!WriteString(buf, cfg.product_id)) return {};

  // Blacklisted process names
  WriteU32(buf, static_cast<std::uint32_t>(cfg.blacklisted_process_names.size()));
  for (const auto& name : cfg.blacklisted_process_names) {
    if (!WriteString(buf, name)) return {};
  }

  // Blacklisted process hashes
  WriteU32(buf, static_cast<std::uint32_t>(cfg.blacklisted_process_hashes.size()));
  for (auto hash : cfg.blacklisted_process_hashes) {
    WriteU32(buf, hash);
  }

  // Blacklisted window titles
  WriteU32(buf, static_cast<std::uint32_t>(cfg.blacklisted_window_titles.size()));
  for (const auto& title : cfg.blacklisted_window_titles) {
    if (!WriteString(buf, title)) return {};
  }

  // Blacklisted driver hashes
  WriteU32(buf, static_cast<std::uint32_t>(cfg.blacklisted_driver_hashes.size()));
  for (auto hash : cfg.blacklisted_driver_hashes) {
    WriteU32(buf, hash);
  }

  // Policy thresholds & flags
  WriteU32(buf, static_cast<std::uint32_t>(cfg.risk_threshold_restrict));
  WriteU32(buf, static_cast<std::uint32_t>(cfg.risk_threshold_terminate));
  buf.push_back(cfg.enforce_hardware_breakpoints ? 1 : 0);
  buf.push_back(cfg.enforce_timing_checks ? 1 : 0);
  buf.push_back(cfg.enforce_memory_hooks ? 1 : 0);
  buf.push_back(cfg.enforce_anti_dump ? 1 : 0);

  return buf;
}

std::vector<std::uint8_t> SerializeCountermeasureConfig(const CountermeasureConfig& cfg) {
  auto buf = SerializeCountermeasureConfigForSigning(cfg);
  if (buf.empty()) return {};
  buf.insert(buf.end(), cfg.signature.begin(), cfg.signature.end());
  return buf;
}

std::optional<CountermeasureConfig> DeserializeCountermeasureConfig(const std::uint8_t* data, std::size_t len) {
  if (!data || len < 40 + sizeof(integrity::Ed25519Signature)) return std::nullopt;

  const std::uint8_t* p = data;
  const std::uint8_t* end = data + len;

  std::uint32_t magic = 0;
  if (!ReadU32(p, end, magic) || magic != kCountermeasureConfigMagic) return std::nullopt;

  CountermeasureConfig cfg;
  if (!ReadU32(p, end, cfg.schema_version) || cfg.schema_version != kCountermeasureSchemaVersion) return std::nullopt;
  if (!ReadU64(p, end, cfg.sequence_number)) return std::nullopt;
  if (!ReadU64(p, end, cfg.issued_at)) return std::nullopt;
  if (!ReadU64(p, end, cfg.expires_at)) return std::nullopt;

  // Product ID binding
  if (!ReadString(p, end, cfg.product_id)) return std::nullopt;

  // Process names
  std::uint32_t proc_name_count = 0;
  if (!ReadU32(p, end, proc_name_count) || proc_name_count > 1000) return std::nullopt;
  cfg.blacklisted_process_names.resize(proc_name_count);
  for (std::size_t i = 0; i < proc_name_count; ++i) {
    if (!ReadString(p, end, cfg.blacklisted_process_names[i])) return std::nullopt;
  }

  // Process hashes
  std::uint32_t proc_hash_count = 0;
  if (!ReadU32(p, end, proc_hash_count) || proc_hash_count > 5000) return std::nullopt;
  cfg.blacklisted_process_hashes.resize(proc_hash_count);
  for (std::size_t i = 0; i < proc_hash_count; ++i) {
    if (!ReadU32(p, end, cfg.blacklisted_process_hashes[i])) return std::nullopt;
  }

  // Window titles
  std::uint32_t title_count = 0;
  if (!ReadU32(p, end, title_count) || title_count > 1000) return std::nullopt;
  cfg.blacklisted_window_titles.resize(title_count);
  for (std::size_t i = 0; i < title_count; ++i) {
    if (!ReadString(p, end, cfg.blacklisted_window_titles[i])) return std::nullopt;
  }

  // Driver hashes
  std::uint32_t driver_count = 0;
  if (!ReadU32(p, end, driver_count) || driver_count > 5000) return std::nullopt;
  cfg.blacklisted_driver_hashes.resize(driver_count);
  for (std::size_t i = 0; i < driver_count; ++i) {
    if (!ReadU32(p, end, cfg.blacklisted_driver_hashes[i])) return std::nullopt;
  }

  // Thresholds & flags
  std::uint32_t thresh_res = 0, thresh_term = 0;
  if (!ReadU32(p, end, thresh_res) || !ReadU32(p, end, thresh_term)) return std::nullopt;
  if (thresh_res > 100 || thresh_term > 100 || thresh_res >= thresh_term) {
    return std::nullopt;
  }
  cfg.risk_threshold_restrict = static_cast<int>(thresh_res);
  cfg.risk_threshold_terminate = static_cast<int>(thresh_term);

  if (end - p < 4) return std::nullopt;
  cfg.enforce_hardware_breakpoints = (*p++ != 0);
  cfg.enforce_timing_checks = (*p++ != 0);
  cfg.enforce_memory_hooks = (*p++ != 0);
  cfg.enforce_anti_dump = (*p++ != 0);

  if (static_cast<std::size_t>(end - p) != sizeof(integrity::Ed25519Signature)) {
    return std::nullopt;
  }
  std::memcpy(cfg.signature.data(), p, sizeof(cfg.signature));

  return cfg;
}

bool SignCountermeasureConfig(CountermeasureConfig& cfg, const integrity::Ed25519PrivateKey& privkey) {
  auto signable = SerializeCountermeasureConfigForSigning(cfg);
  if (signable.empty()) return false;
  EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
      EVP_PKEY_ED25519, nullptr, privkey.data(), integrity::kEd25519PrivateKeyLen);
  if (!pkey) return false;

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) {
    EVP_PKEY_free(pkey);
    return false;
  }

  std::size_t sig_len = integrity::kEd25519SignatureLen;
  bool ok = EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) == 1 &&
            EVP_DigestSign(ctx, cfg.signature.data(), &sig_len, signable.data(), signable.size()) == 1 &&
            sig_len == integrity::kEd25519SignatureLen;

  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return ok;
}

bool VerifyCountermeasureConfigSignature(const CountermeasureConfig& cfg, const integrity::Ed25519PublicKey& pubkey) {
  auto signable = SerializeCountermeasureConfigForSigning(cfg);
  if (signable.empty()) return false;
  return integrity::VerifyManifestSignature(signable, cfg.signature, pubkey);
}

bool SaveCountermeasureConfig(const std::string& product_id, const CountermeasureConfig& cfg) {
  if (!cfg.product_id.empty() && cfg.product_id != product_id) return false;
  auto serialized = SerializeCountermeasureConfig(cfg);
  if (serialized.empty()) return false;
  return SecureStorage::Store(product_id + "_countermeasures", serialized, "rtprotect_countermeasures");
}

std::optional<CountermeasureConfig> LoadCountermeasureConfig(const std::string& product_id) {
  auto data = SecureStorage::Load(product_id + "_countermeasures");
  if (!data.has_value()) return std::nullopt;
  auto cfg = DeserializeCountermeasureConfig(data->data(), data->size());
  if (!cfg.has_value()) return std::nullopt;
  if (!cfg->product_id.empty() && cfg->product_id != product_id) return std::nullopt;
  std::uint64_t now = static_cast<std::uint64_t>(std::time(nullptr));
  if (cfg->IsExpired(now)) {
    return std::nullopt;
  }
  return cfg;
}

namespace {
std::atomic<CountermeasureUpdateHook> s_cm_hook{nullptr};
}  // namespace

void SetCountermeasureUpdateHook(CountermeasureUpdateHook hook) {
  s_cm_hook.store(hook, std::memory_order_release);
}

void NotifyCountermeasureUpdate(const CountermeasureConfig& cfg) {
  auto hook = s_cm_hook.load(std::memory_order_acquire);
  if (hook) {
    hook(cfg);
  }
}

}  // namespace rtprotect::licensing
