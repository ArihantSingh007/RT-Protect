// licensing/trusted_time.cpp

#include "licensing/trusted_time.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <algorithm>

#include "licensing/secure_storage.h"

namespace rtprotect::licensing {

namespace {

struct InProcessTimeBaseline {
  std::uint64_t start_wall_seconds;
  std::uint64_t start_steady_seconds;

  InProcessTimeBaseline() {
    auto wall_now = std::chrono::system_clock::now().time_since_epoch();
    start_wall_seconds = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(wall_now).count());

    auto steady_now = std::chrono::steady_clock::now().time_since_epoch();
    start_steady_seconds = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(steady_now).count());
  }
};

const InProcessTimeBaseline& GetProcessBaseline() {
  static const InProcessTimeBaseline baseline;
  return baseline;
}

std::string MakeTimeStateKey(const std::string& product_id) {
  std::string s = product_id.empty() ? "default" : product_id;
  for (char& c : s) {
    if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_') {
      c = '_';
    }
  }
  return "time_state_" + s;
}

std::vector<std::uint8_t> SerializeTimeState(const TrustedTimeState& state) {
  std::vector<std::uint8_t> buf;
  buf.reserve(25);

  auto write_u64 = [&buf](std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
      buf.push_back(static_cast<std::uint8_t>((v >> (i * 8)) & 0xFF));
    }
  };

  write_u64(state.last_known_server_time);
  write_u64(state.last_known_wall_time);
  write_u64(state.last_anchor_steady_seconds);
  buf.push_back(state.tamper_detected ? 1 : 0);
  return buf;
}

std::optional<TrustedTimeState> DeserializeTimeState(const std::vector<std::uint8_t>& buf) {
  if (buf.size() < 25) return std::nullopt;

  auto read_u64 = [&buf](std::size_t offset) -> std::uint64_t {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
      v |= (static_cast<std::uint64_t>(buf[offset + i]) << (i * 8));
    }
    return v;
  };

  TrustedTimeState state;
  state.last_known_server_time = read_u64(0);
  state.last_known_wall_time = read_u64(8);
  state.last_anchor_steady_seconds = read_u64(16);
  state.tamper_detected = (buf[24] != 0);
  return state;
}

}  // namespace

bool TrustedTime::AnchorServerTime(const std::string& product_id, std::uint64_t server_timestamp) {
  if (server_timestamp == 0) return false;

  std::string key = MakeTimeStateKey(product_id);
  TrustedTimeState state;

  auto existing_bytes = SecureStorage::Load(key);
  if (existing_bytes.has_value()) {
    auto parsed = DeserializeTimeState(*existing_bytes);
    if (parsed.has_value()) {
      state = *parsed;
    }
  }

  // Anchor server time strictly forward
  state.last_known_server_time = (std::max)(state.last_known_server_time, server_timestamp);

  auto wall_now = std::chrono::system_clock::now().time_since_epoch();
  std::uint64_t now_wall = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(wall_now).count());
  state.last_known_wall_time = (std::max)(state.last_known_wall_time, now_wall);

  auto steady_now = std::chrono::steady_clock::now().time_since_epoch();
  state.last_anchor_steady_seconds = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(steady_now).count());

  // Successful server verification resets local tamper flags
  state.tamper_detected = false;

  auto serialized = SerializeTimeState(state);
  return SecureStorage::Store(key, serialized, "rtprotect_time_state");
}

std::optional<std::uint64_t> TrustedTime::GetTrustedTime(const std::string& product_id) {
  auto wall_now = std::chrono::system_clock::now().time_since_epoch();
  std::uint64_t now_wall = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(wall_now).count());

  auto steady_now = std::chrono::steady_clock::now().time_since_epoch();
  std::uint64_t now_steady = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(steady_now).count());

  const auto& baseline = GetProcessBaseline();

  // 1. In-process check: did wall clock jump backward since process startup?
  if (now_wall + kAllowedSkewSeconds < baseline.start_wall_seconds) {
    // Clock moved backward during active runtime!
    return std::nullopt;
  }

  std::string key = MakeTimeStateKey(product_id);
  auto existing_bytes = SecureStorage::Load(key);
  if (!existing_bytes.has_value()) {
    // No persistent anchor yet - accept current wall clock
    return now_wall;
  }

  auto state_opt = DeserializeTimeState(*existing_bytes);
  if (!state_opt.has_value()) {
    return now_wall;
  }

  TrustedTimeState state = *state_opt;

  // 2. Persistent tamper flag check
  if (state.tamper_detected) {
    return std::nullopt;
  }

  // 3. Wall clock behind last-known server timestamp
  if (state.last_known_server_time > 0 &&
      now_wall + kAllowedSkewSeconds < state.last_known_server_time) {
    state.tamper_detected = true;
    SecureStorage::Store(key, SerializeTimeState(state), "rtprotect_time_state");
    return std::nullopt;
  }

  // 4. Monotonic progression check against last anchor
  if (state.last_known_server_time > 0 && state.last_anchor_steady_seconds > 0 &&
      now_steady >= state.last_anchor_steady_seconds) {
    std::uint64_t elapsed_steady = now_steady - state.last_anchor_steady_seconds;
    std::uint64_t monotonic_projected = state.last_known_server_time + elapsed_steady;
    if (now_wall + kAllowedSkewSeconds < monotonic_projected) {
      state.tamper_detected = true;
      SecureStorage::Store(key, SerializeTimeState(state), "rtprotect_time_state");
      return std::nullopt;
    }
  }

  // 5. Wall clock behind last-known wall clock across executions
  if (state.last_known_wall_time > 0 &&
      now_wall + kAllowedSkewSeconds < state.last_known_wall_time) {
    state.tamper_detected = true;
    SecureStorage::Store(key, SerializeTimeState(state), "rtprotect_time_state");
    return std::nullopt;
  }

  // Update last-known wall time
  state.last_known_wall_time = (std::max)(state.last_known_wall_time, now_wall);
  SecureStorage::Store(key, SerializeTimeState(state), "rtprotect_time_state");

  return (std::max)(now_wall, state.last_known_server_time);
}

TimeValidationResult TrustedTime::ValidateToken(const std::string& product_id,
                                                const ActivationToken& token,
                                                bool allow_grace) {
  auto current_time_opt = GetTrustedTime(product_id);
  if (!current_time_opt.has_value()) {
    return TimeValidationResult::kClockTampered;
  }

  std::uint64_t current_time = *current_time_opt;

  // Token issued in the distant future
  if (token.issued_at > 0 && token.issued_at > current_time + kAllowedSkewSeconds) {
    return TimeValidationResult::kNotYetValid;
  }

  // Active validity window
  if (token.expires_at == 0 || current_time <= token.expires_at) {
    return TimeValidationResult::kValid;
  }

  // Grace period window
  if (allow_grace && token.grace_expires_at > 0 && current_time <= token.grace_expires_at) {
    return TimeValidationResult::kInGracePeriod;
  }

  return TimeValidationResult::kExpired;
}

std::optional<std::uint64_t> TrustedTime::ParseHttpDate(const std::string& http_date_str) {
  // Format: "Wed, 21 Oct 2026 12:00:00 GMT" or "21 Oct 2026 12:00:00 GMT"
  if (http_date_str.empty()) return std::nullopt;

  char day_name[8] = {0};
  int day = 0;
  char month_name[8] = {0};
  int year = 0, hour = 0, min = 0, sec = 0;

  int parsed = 0;
  if (http_date_str.find(',') != std::string::npos) {
    parsed = std::sscanf(http_date_str.c_str(), "%7[^,], %d %7s %d %d:%d:%d",
                         day_name, &day, month_name, &year, &hour, &min, &sec);
  } else {
    parsed = std::sscanf(http_date_str.c_str(), "%d %7s %d %d:%d:%d",
                         &day, month_name, &year, &hour, &min, &sec);
  }

  if (parsed < 6) return std::nullopt;

  static const char* const kMonths[] = {
      "Jan", "Feb", "Mar", "Apr", "May", "Jun",
      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
  };

  int month_idx = -1;
  for (int i = 0; i < 12; ++i) {
    if (std::strncmp(month_name, kMonths[i], 3) == 0) {
      month_idx = i;
      break;
    }
  }

  if (month_idx < 0) return std::nullopt;

  std::tm tm_val{};
  tm_val.tm_mday = day;
  tm_val.tm_mon = month_idx;
  tm_val.tm_year = year - 1900;
  tm_val.tm_hour = hour;
  tm_val.tm_min = min;
  tm_val.tm_sec = sec;
  tm_val.tm_isdst = 0;

#if defined(_WIN32)
  time_t t = _mkgmtime(&tm_val);
#else
  time_t t = timegm(&tm_val);
#endif

  if (t == static_cast<time_t>(-1)) {
    return std::nullopt;
  }
  return static_cast<std::uint64_t>(t);
}

void TrustedTime::ResetTimeStateForTesting(const std::string& product_id) {
  SecureStorage::Delete(MakeTimeStateKey(product_id));
}

}  // namespace rtprotect::licensing
