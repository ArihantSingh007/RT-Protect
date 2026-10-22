// licensing/rate_limiter.h
//
// In-Memory Token Bucket Rate Limiter for Activation Authority.
// Protects endpoints against brute-force credential guessing, denial-of-service,
// and activation token harvesting.

#pragma once

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
  RateLimiter(double refill_rate_per_sec = 2.0, double max_tokens = 20.0)
      : refill_rate_(refill_rate_per_sec), max_tokens_(max_tokens) {}

  void Configure(double refill_rate_per_sec, double max_tokens) {
    std::lock_guard<std::mutex> lock(mu_);
    refill_rate_ = refill_rate_per_sec;
    max_tokens_ = max_tokens;
    buckets_.clear();
  }

  bool Allow(const std::string& key, double cost = 1.0, int* retry_after_seconds = nullptr) {
    if (key.empty()) return true;
    std::lock_guard<std::mutex> lock(mu_);
    auto now = std::chrono::steady_clock::now();

    auto& bucket = buckets_[key];
    if (bucket.last_refill == std::chrono::steady_clock::time_point{}) {
      bucket.tokens = max_tokens_;
      bucket.last_refill = now;
    } else {
      double elapsed_sec = std::chrono::duration<double>(now - bucket.last_refill).count();
      bucket.tokens = std::min(max_tokens_, bucket.tokens + elapsed_sec * refill_rate_);
      bucket.last_refill = now;
    }

    if (bucket.tokens >= cost) {
      bucket.tokens -= cost;
      if (retry_after_seconds) *retry_after_seconds = 0;
      return true;
    }

    if (retry_after_seconds) {
      double needed = cost - bucket.tokens;
      *retry_after_seconds = std::max(1, static_cast<int>(std::ceil(needed / refill_rate_)));
    }
    return false;
  }

  void Reset(const std::string& key) {
    std::lock_guard<std::mutex> lock(mu_);
    buckets_.erase(key);
  }

  void Clear() {
    std::lock_guard<std::mutex> lock(mu_);
    buckets_.clear();
  }

 private:
  struct Bucket {
    double tokens = 0.0;
    std::chrono::steady_clock::time_point last_refill{};
  };

  mutable std::mutex mu_;
  double refill_rate_;
  double max_tokens_;
  std::unordered_map<std::string, Bucket> buckets_;
};

}  // namespace rtprotect::licensing
