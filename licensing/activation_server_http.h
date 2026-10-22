// licensing/activation_server_http.h
//
// Hardened multi-threaded HTTP/HTTPS server for RTProtect Activation Authority.
// Supports per-socket timeouts, request size bounds, concurrent worker dispatch,
// and optional native TLS termination.

#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "licensing/activation_service.h"
#include "licensing/rate_limiter.h"

namespace rtprotect::licensing {

class ActivationServerHttp {
 public:
  explicit ActivationServerHttp(ActivationService& service);
  ~ActivationServerHttp();

  // Configures optional TLS server termination using X.509 certificate and private key
  bool EnableTls(const std::string& cert_file, const std::string& key_file);

  // Starts the HTTP/HTTPS server on specified port (use 0 for auto-assigned ephemeral port)
  bool Start(std::uint16_t port = 8080, const std::string& host = "127.0.0.1");

  // Explicitly allow binding unencrypted HTTP on non-loopback addresses (insecure dev mode only)
  void SetAllowInsecureNonLoopback(bool allow) { allow_insecure_non_loopback_ = allow; }

  // Determines whether a host string is a safe loopback interface
  static bool IsLoopbackHost(const std::string& host);

  // Stops server and cleanly joins all in-flight worker threads
  void Stop();

  bool is_running() const { return running_.load(); }
  bool is_tls() const { return is_tls_; }
  std::uint16_t port() const { return port_; }
  std::string base_url() const;

  RateLimiter& ip_rate_limiter() { return ip_rate_limiter_; }

  // Maximum allowed sizes for denial-of-service prevention
  static constexpr std::size_t kMaxHeaderBytes = 8192;         // 8 KB max headers
  static constexpr std::size_t kMaxRequestBodyBytes = 65536;   // 64 KB max payload
  static constexpr std::size_t kMaxConcurrentClients = 64;     // Max in-flight threads

 private:
  void ServerLoop();
  void HandleClient(uintptr_t client_sock_fd, const std::string& client_ip);

  void RegisterClientSocket(uintptr_t s);
  void UnregisterClientSocket(uintptr_t s);
  void CloseAllClientSockets();

  ActivationService& service_;
  std::atomic<bool> running_{false};
  std::atomic<std::size_t> active_clients_{0};
  std::uint16_t port_{0};
  std::string host_{"127.0.0.1"};
  uintptr_t listen_fd_{~0ULL}; // SOCKET on Win32, int on POSIX
  std::thread accept_thread_;

  // Worker thread lifecycle tracking to prevent shutdown use-after-free
  std::mutex workers_mu_;
  std::condition_variable workers_cv_;
  std::unordered_map<std::thread::id, std::thread> active_workers_;
  std::vector<std::thread> finished_workers_;

  // Open socket tracking to unblock in-flight workers on shutdown
  std::mutex sockets_mu_;
  std::unordered_set<uintptr_t> client_sockets_;

  bool is_tls_{false};
  bool allow_insecure_non_loopback_{false};
  std::string tls_cert_file_;
  std::string tls_key_file_;
  void* ssl_ctx_{nullptr}; // SSL_CTX* when TLS enabled
  RateLimiter ip_rate_limiter_{5.0, 30.0}; // 5 tokens/sec, burst 30 tokens per IP
};

}  // namespace rtprotect::licensing
