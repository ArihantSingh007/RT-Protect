// licensing/trusted_time.cpp

#include "licensing/trusted_time.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <algorithm>
#include <mutex>

#if defined(_WIN32)
#include <windows.h>
#endif

#include "licensing/secure_storage.h"

namespace rtprotect::licensing {

namespace {

static std::recursive_mutex s_trusted_time_mutex;

TrustedTime::WallTimeProvider s_test_wall_fn = nullptr;
TrustedTime::UptimeProvider s_test_uptime_fn = nullptr;
TrustedTime::BootIdProvider s_test_boot_id_fn = nullptr;

std::uint64_t DefaultWallSeconds() {
  auto wall_now = std::chrono::system_clock::now().time_since_epoch();
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(wall_now).count());
}

#if defined(_WIN32)
std::uint64_t DefaultSystemUptimeSeconds() {
  return static_cast<std::uint64_t>(GetTickCount64() / 1000);
}
#else
std::uint64_t DefaultSystemUptimeSeconds() {
  auto steady_now = std::chrono::steady_clock::now().time_since_epoch();
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(steady_now).count());
}
#endif

// Derives a stable boot session identifier from estimated boot time: (wall_now - uptime_now).
// Stays constant across process lifecycles and relaunches within the same boot,
// and changes reliably across machine reboots.
std::uint64_t DefaultBootId() {
  std::uint64_t wall = DefaultWallSeconds();
  std::uint64_t uptime = DefaultSystemUptimeSeconds();
  return (wall >= uptime) ? (wall - uptime) : 0;
}

struct InProcessTimeBaseline {
  std::uint64_t start_wall_seconds = 0;
  std::uint64_t start_steady_seconds = 0;
  bool initialized = false;
};

static InProcessTimeBaseline s_process_baseline;

InProcessTimeBaseline InitializeProcessBaselineLocked() {
  InProcessTimeBaseline b;
  b.start_wall_seconds = s_test_wall_fn ? s_test_wall_fn() : DefaultWallSeconds();
  if (s_test_uptime_fn != nullptr) {
    b.start_steady_seconds = s_test_uptime_fn();
  } else {
    auto steady_now = std::chrono::steady_clock::now().time_since_epoch();
    b.start_steady_seconds = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(steady_now).count());
  }
  b.initialized = true;
  return b;
}

InProcessTimeBaseline GetProcessBaseline() {
  if (!s_process_baseline.initialized) {
    s_process_baseline = InitializeProcessBaselineLocked();
  }
  return s_process_baseline;
}

struct BaselineAutoInit {
  BaselineAutoInit() {
    TrustedTime::InitializeProcessBaseline();
  }
};
static BaselineAutoInit s_baseline_auto_init;

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
  buf.reserve(41);

  auto write_u64 = [&buf](std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
      buf.push_back(static_cast<std::uint8_t>((v >> (i * 8)) & 0xFF));
    }
  };

  write_u64(state.last_known_server_time);
  write_u64(state.last_known_wall_time);
  write_u64(state.accumulated_monotonic_seconds);
  write_u64(state.last_boot_id);
  write_u64(state.last_session_uptime_seconds);
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
  state.accumulated_monotonic_seconds = read_u64(16);

  if (buf.size() >= 41) {
    state.last_boot_id = read_u64(24);
    state.last_session_uptime_seconds = read_u64(32);
    state.tamper_detected = (buf[40] != 0);
  } else {
    // Legacy 25-byte format: byte 24 is tamper flag
    state.last_boot_id = 0;
    state.last_session_uptime_seconds = 0;
    state.tamper_detected = (buf[24] != 0);
  }
  return state;
}

}  // namespace

void TrustedTime::InitializeProcessBaseline() {
  std::lock_guard<std::recursive_mutex> lock(s_trusted_time_mutex);
  if (!s_process_baseline.initialized) {
    s_process_baseline = InitializeProcessBaselineLocked();
  }
}

void TrustedTime::SetTimeProvidersForTesting(WallTimeProvider wall_fn,
                                             UptimeProvider uptime_fn,
                                             BootIdProvider boot_id_fn) {
  std::lock_guard<std::recursive_mutex> lock(s_trusted_time_mutex);
  s_test_wall_fn = wall_fn;
  s_test_uptime_fn = uptime_fn;
  s_test_boot_id_fn = boot_id_fn;
}

void TrustedTime::ResetTimeProvidersForTesting() {
  std::lock_guard<std::recursive_mutex> lock(s_trusted_time_mutex);
  s_test_wall_fn = nullptr;
  s_test_uptime_fn = nullptr;
  s_test_boot_id_fn = nullptr;
  s_process_baseline.initialized = false;
}

void TrustedTime::ResetProcessBaselineForTesting(std::uint64_t start_wall, std::uint64_t start_steady) {
  std::lock_guard<std::recursive_mutex> lock(s_trusted_time_mutex);
  s_process_baseline.start_wall_seconds = start_wall;
  s_process_baseline.start_steady_seconds = start_steady;
  s_process_baseline.initialized = true;
}

std::uint64_t TrustedTime::GetCurrentBootId() {
  std::lock_guard<std::recursive_mutex> lock(s_trusted_time_mutex);
  return s_test_boot_id_fn ? s_test_boot_id_fn() : DefaultBootId();
}

std::uint64_t TrustedTime::GetCurrentSystemUptime() {
  std::lock_guard<std::recursive_mutex> lock(s_trusted_time_mutex);
  return s_test_uptime_fn ? s_test_uptime_fn() : DefaultSystemUptimeSeconds();
}

bool TrustedTime::AnchorServerTime(const std::string& product_id, std::uint64_t server_timestamp) {
  if (server_timestamp == 0) return false;

  std::lock_guard<std::recursive_mutex> lock(s_trusted_time_mutex);

  std::string key = MakeTimeStateKey(product_id);
  TrustedTimeState state;

  auto existing_bytes = SecureStorage::Load(key);
  if (existing_bytes.has_value()) {
    auto parsed = DeserializeTimeState(*existing_bytes);
    if (parsed.has_value()) {
      state = *parsed;
    }
  }

  std::uint64_t now_uptime = s_test_uptime_fn ? s_test_uptime_fn() : DefaultSystemUptimeSeconds();
  std::uint64_t current_boot_id = s_test_boot_id_fn ? s_test_boot_id_fn() : DefaultBootId();

  // Anchor server time strictly forward
  state.last_known_server_time = (std::max)(state.last_known_server_time, server_timestamp);

  // Finding 1 fix: Reset high-water wall time to the verified server timestamp rather than max().
  // This allows recovering from forward-clock excursions once authoritative server anchor is obtained.
  state.last_known_wall_time = server_timestamp;
  state.accumulated_monotonic_seconds = 0; // Reset monotonic counter relative to fresh anchor
  state.last_boot_id = current_boot_id;
  state.last_session_uptime_seconds = now_uptime;

  // Successful server verification resets local tamper flags
  state.tamper_detected = false;

  auto serialized = SerializeTimeState(state);
  return SecureStorage::Store(key, serialized, "rtprotect_time_state");
}

std::optional<std::uint64_t> TrustedTime::GetTrustedTime(const std::string& product_id) {
  std::lock_guard<std::recursive_mutex> lock(s_trusted_time_mutex);

  std::uint64_t now_wall = s_test_wall_fn ? s_test_wall_fn() : DefaultWallSeconds();
  std::uint64_t now_uptime = s_test_uptime_fn ? s_test_uptime_fn() : DefaultSystemUptimeSeconds();
  std::uint64_t current_boot_id = s_test_boot_id_fn ? s_test_boot_id_fn() : DefaultBootId();

  const auto& baseline = GetProcessBaseline();

  std::uint64_t current_steady = 0;
  if (s_test_uptime_fn != nullptr) {
    current_steady = s_test_uptime_fn();
  } else {
    auto steady_now = std::chrono::steady_clock::now().time_since_epoch();
    current_steady = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(steady_now).count());
  }
  std::uint64_t elapsed_steady = (current_steady >= baseline.start_steady_seconds)
                                     ? (current_steady - baseline.start_steady_seconds)
                                     : 0;

  std::string key = MakeTimeStateKey(product_id);
  auto existing_bytes = SecureStorage::Load(key);
  if (!existing_bytes.has_value()) {
    // No persistent anchor yet
    if (elapsed_steady >= kAllowedSkewSeconds) {
      if (now_wall + kAllowedSkewSeconds < baseline.start_wall_seconds + elapsed_steady) {
        return std::nullopt; // Wall clock frozen while process was actively running
      }
    }
    return now_wall;
  }

  auto state_opt = DeserializeTimeState(*existing_bytes);
  if (!state_opt.has_value()) {
    return now_wall;
  }

  TrustedTimeState state = *state_opt;
  const TrustedTimeState initial_loaded_state = state;

  // Check same-boot session predicate (Finding 5 fix: require |delta_wall - delta_uptime| <= 60s for forward runs)
  bool is_same_boot = false;
  if (state.last_boot_id != 0 && state.last_session_uptime_seconds > 0) {
    std::uint64_t boot_diff = (current_boot_id >= state.last_boot_id)
                                  ? (current_boot_id - state.last_boot_id)
                                  : (state.last_boot_id - current_boot_id);
    if (boot_diff <= kAllowedSkewSeconds && now_uptime >= state.last_session_uptime_seconds) {
      if (now_wall >= state.last_known_wall_time) {
        std::uint64_t delta_wall = now_wall - state.last_known_wall_time;
        std::uint64_t delta_uptime = now_uptime - state.last_session_uptime_seconds;
        std::uint64_t drift = (delta_wall >= delta_uptime)
                                  ? (delta_wall - delta_uptime)
                                  : (delta_uptime - delta_wall);
        if (drift <= 60) {
          is_same_boot = true;
        }
      } else {
        // Wall clock moved backward!
        // In an active session where uptime has advanced continuously (now_uptime >= last_session_uptime),
        // and in-process steady time has advanced, this is a mid-session backward clock step.
        if (current_steady >= baseline.start_steady_seconds) {
          is_same_boot = true;
        }
      }
    } else if (now_uptime >= state.last_session_uptime_seconds &&
               current_steady >= baseline.start_steady_seconds &&
               now_wall < state.last_known_wall_time) {
      // Wall clock backward step shifted estimated boot_id (wall - uptime),
      // but active process runtime and monotonic uptime are intact.
      is_same_boot = true;
    }
  }

  if (is_same_boot) {
    std::uint64_t delta = now_uptime - state.last_session_uptime_seconds;
    state.accumulated_monotonic_seconds += delta;
    state.last_session_uptime_seconds = now_uptime;
  } else {
    // A reboot occurred (or first observation of boot_id)
    state.last_boot_id = current_boot_id;
    if (state.last_session_uptime_seconds > 0) {
      state.accumulated_monotonic_seconds += now_uptime;
    }
    state.last_session_uptime_seconds = now_uptime;
  }

  // 2. Persistent tamper flag check
  if (state.tamper_detected) {
    return std::nullopt;
  }

  // Monotonic steady progression provides the projected trusted minimum time:
  std::uint64_t min_projected_time = 0;
  if (state.last_known_server_time > 0) {
    min_projected_time = state.last_known_server_time + state.accumulated_monotonic_seconds;
  }
  std::uint64_t in_proc_projected = baseline.start_wall_seconds + elapsed_steady;
  min_projected_time = (std::max)(min_projected_time, in_proc_projected);

  // Finding 1 fix: Clamp persisted high-water mark against server-anchored time + monotonic progression + skew.
  // Never persist an unverified future high-water mark that causes permanent lockout.
  if (state.last_known_server_time > 0) {
    std::uint64_t max_allowed_wall = state.last_known_server_time + state.accumulated_monotonic_seconds + kAllowedSkewSeconds;
    if (state.last_known_wall_time > max_allowed_wall) {
      state.last_known_wall_time = max_allowed_wall;
    }
  }

  // Finding 2 fix: Handling backward clock steps mid-session vs. across reboots.
  // In-process check: has wall clock frozen while process steady time advanced?
  bool in_process_backward_step = (now_wall + kAllowedSkewSeconds < baseline.start_wall_seconds);
  if (!in_process_backward_step && elapsed_steady >= kAllowedSkewSeconds) {
    if (now_wall + kAllowedSkewSeconds < baseline.start_wall_seconds + elapsed_steady) {
      return std::nullopt; // Wall clock frozen while process was actively running
    }
  }

  if (!is_same_boot) {
    // 3. Across reboots: Wall clock behind last-known server timestamp
    if (state.last_known_server_time > 0 &&
        now_wall + kAllowedSkewSeconds < state.last_known_server_time) {
      state.tamper_detected = true;
      SecureStorage::Store(key, SerializeTimeState(state), "rtprotect_time_state");
      return std::nullopt;
    }

    // 4. Across reboots: Wall clock behind last-known wall clock
    if (state.last_known_wall_time > 0 &&
        now_wall + kAllowedSkewSeconds < state.last_known_wall_time) {
      state.tamper_detected = true;
      SecureStorage::Store(key, SerializeTimeState(state), "rtprotect_time_state");
      return std::nullopt;
    }

    // 6. Across reboots: Monotonic anti-clock-freeze verification against server anchor
    if (state.last_known_server_time > 0) {
      std::uint64_t server_monotonic_projected = state.last_known_server_time + state.accumulated_monotonic_seconds;
      if (now_wall + kAllowedSkewSeconds < server_monotonic_projected) {
        state.tamper_detected = true;
        SecureStorage::Store(key, SerializeTimeState(state), "rtprotect_time_state");
        return std::nullopt;
      }
    }
  } else {
    // In the SAME boot session:
    // Backward clock steps during active session (e.g. NTP synchronization) are not fatal;
    // steady monotonic clock maintains true forward time (min_projected_time).
    // Gross inconsistency (>1 hour rollback from server anchor) triggers tamper detection.
    if (state.last_known_server_time > 0 &&
        now_wall + kLargeInconsistencySeconds < state.last_known_server_time) {
      state.tamper_detected = true;
      SecureStorage::Store(key, SerializeTimeState(state), "rtprotect_time_state");
      return std::nullopt;
    }
  }

  // 7. Update high-water mark and throttle writes to SecureStorage
  std::uint64_t wall_to_record = now_wall;
  if (state.last_known_server_time > 0) {
    std::uint64_t max_allowed_wall = state.last_known_server_time + state.accumulated_monotonic_seconds + kAllowedSkewSeconds;
    if (wall_to_record > max_allowed_wall) {
      wall_to_record = max_allowed_wall;
    }
  }
  state.last_known_wall_time = (std::max)(state.last_known_wall_time, wall_to_record);

  bool need_persist = false;
  if (state.last_known_wall_time > initial_loaded_state.last_known_wall_time &&
      state.last_known_wall_time - initial_loaded_state.last_known_wall_time >= 60) {
    need_persist = true;
  }
  if (state.accumulated_monotonic_seconds > initial_loaded_state.accumulated_monotonic_seconds &&
      state.accumulated_monotonic_seconds - initial_loaded_state.accumulated_monotonic_seconds >= 60) {
    need_persist = true;
  }
  if (state.tamper_detected != initial_loaded_state.tamper_detected ||
      state.last_boot_id != initial_loaded_state.last_boot_id) {
    need_persist = true;
  }

  if (need_persist) {
    SecureStorage::Store(key, SerializeTimeState(state), "rtprotect_time_state");
  }

  std::uint64_t trusted = (std::max)(now_wall, min_projected_time);
  return trusted;
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
  std::lock_guard<std::recursive_mutex> lock(s_trusted_time_mutex);
  ResetTimeProvidersForTesting();
  SecureStorage::Delete(MakeTimeStateKey(product_id));
}

}  // namespace rtprotect::licensing
