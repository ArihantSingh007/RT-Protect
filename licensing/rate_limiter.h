// licensing/rate_limiter.h
//
// In-Memory Token Bucket Rate Limiter for Activation Authority.
// Protects endpoints against brute-force credential guessing, denial-of-service,
// and activation token harvesting.

#pragma once

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

namespace rtprotect::licensing {

class RateLimiter {
 public:
  // refill_rate_per_sec: tokens added per second
  // max_tokens: maximum bucket capacity (burst limit)
  // max_entries: maximum active tracked keys to prevent unbounded memory growth
  RateLimiter(double refill_rate_per_sec = 2.0, double max_tokens = 20.0, std::size_t max_entries = 10000)
      : max_entries_(max_entries == 0 ? 10000 : max_entries) {
    Configure(refill_rate_per_sec, max_tokens);
  }

  void Configure(double refill_rate_per_sec, double max_tokens) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!std::isfinite(refill_rate_per_sec) || refill_rate_per_sec <= 0.0) {
      refill_rate_per_sec = 1.0;
    }
    if (!std::isfinite(max_tokens) || max_tokens <= 0.0) {
      max_tokens = 1.0;
    }
    refill_rate_ = refill_rate_per_sec;
    max_tokens_ = max_tokens;
    buckets_.clear();
  }

  bool Allow(const std::string& key, double cost = 1.0, int* retry_after_seconds = nullptr) {
    if (!std::isfinite(cost) || cost <= 0.0) {
      if (retry_after_seconds) *retry_after_seconds = 1;
      return false;
    }

    std::string safe_key = key.empty() ? "<anonymous>" : key;
    std::lock_guard<std::mutex> lock(mu_);
    auto now = std::chrono::steady_clock::now();

    // Capacity bounding: prune stale buckets when reaching maximum entries limit
    if (buckets_.size() >= max_entries_ && buckets_.find(safe_key) == buckets_.end()) {
      PruneStaleLocked(now);
      if (buckets_.size() >= max_entries_ && !buckets_.empty()) {
        // Deterministic LRU eviction: evict oldest inactive entry
        auto oldest_it = buckets_.begin();
        for (auto it = buckets_.begin(); it != buckets_.end(); ++it) {
          if (it->second.last_refill < oldest_it->second.last_refill) {
            oldest_it = it;
          }
        }
        buckets_.erase(oldest_it);
      }
    }

    auto& bucket = buckets_[safe_key];
    if (bucket.last_refill == std::chrono::steady_clock::time_point{}) {
      bucket.tokens = max_tokens_;
      bucket.last_refill = now;
    } else {
      double elapsed_sec = std::chrono::duration<double>(now - bucket.last_refill).count();
      bucket.tokens = (std::min)(max_tokens_, bucket.tokens + elapsed_sec * refill_rate_);
      bucket.last_refill = now;
    }

    if (bucket.tokens >= cost) {
      bucket.tokens -= cost;
      if (retry_after_seconds) *retry_after_seconds = 0;
      return true;
    }

    if (retry_after_seconds) {
      double needed = cost - bucket.tokens;
      *retry_after_seconds = (std::max)(1, static_cast<int>(std::ceil(needed / refill_rate_)));
    }
    return false;
  }

  void Reset(const std::string& key) {
    std::string safe_key = key.empty() ? "<anonymous>" : key;
    std::lock_guard<std::mutex> lock(mu_);
    buckets_.erase(safe_key);
  }

  void Clear() {
    std::lock_guard<std::mutex> lock(mu_);
    buckets_.clear();
  }

  std::size_t active_buckets_count() const {
    std::lock_guard<std::mutex> lock(mu_);
    return buckets_.size();
  }

 private:
  struct Bucket {
    double tokens = 0.0;
    std::chrono::steady_clock::time_point last_refill{};
  };

  void PruneStaleLocked(std::chrono::steady_clock::time_point now) {
    // Prune entries that have reached full token capacity and have been idle > 60s
    for (auto it = buckets_.begin(); it != buckets_.end(); ) {
      double elapsed = std::chrono::duration<double>(now - it->second.last_refill).count();
      double current_tokens = it->second.tokens + elapsed * refill_rate_;
      if (current_tokens >= max_tokens_ && elapsed > 60.0) {
        it = buckets_.erase(it);
      } else {
        ++it;
      }
    }
  }

  mutable std::mutex mu_;
  double refill_rate_ = 2.0;
  double max_tokens_ = 20.0;
  std::size_t max_entries_ = 10000;
  std::unordered_map<std::string, Bucket> buckets_;
};

}  // namespace rtprotect::licensing
