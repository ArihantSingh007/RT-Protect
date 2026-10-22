// licensing/activation_server_http.h
//
// Hardened multi-threaded HTTP/HTTPS server for RTProtect Activation Authority.
// Supports per-socket timeouts, request size bounds, concurrent worker dispatch,
// and optional native TLS termination.

#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

#include "licensing/activation_service.h"

namespace rtprotect::licensing {

class ActivationServerHttp {
 public:
  explicit ActivationServerHttp(ActivationService& service);
  ~ActivationServerHttp();

  // Configures optional TLS server termination using X.509 certificate and private key
  bool EnableTls(const std::string& cert_file, const std::string& key_file);

  // Starts the HTTP/HTTPS server on specified port (use 0 for auto-assigned ephemeral port)
  bool Start(std::uint16_t port = 8080, const std::string& host = "127.0.0.1");

  // Stops server and terminates worker threads
  void Stop();

  bool is_running() const { return running_.load(); }
  bool is_tls() const { return is_tls_; }
  std::uint16_t port() const { return port_; }
  std::string base_url() const;

  // Maximum allowed sizes for denial-of-service prevention
  static constexpr std::size_t kMaxHeaderBytes = 8192;         // 8 KB max headers
  static constexpr std::size_t kMaxRequestBodyBytes = 65536;   // 64 KB max payload
  static constexpr std::size_t kMaxConcurrentClients = 64;     // Max in-flight threads

 private:
  void ServerLoop();
  void HandleClient(uintptr_t client_sock_fd);

  ActivationService& service_;
  std::atomic<bool> running_{false};
  std::atomic<std::size_t> active_clients_{0};
  std::uint16_t port_{0};
  std::string host_{"127.0.0.1"};
  uintptr_t listen_fd_{~0ULL}; // SOCKET on Win32, int on POSIX
  std::thread accept_thread_;

  bool is_tls_{false};
  std::string tls_cert_file_;
  std::string tls_key_file_;
  void* ssl_ctx_{nullptr}; // SSL_CTX* when TLS enabled
};

}  // namespace rtprotect::licensing
