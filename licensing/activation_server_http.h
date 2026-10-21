// licensing/activation_server_http.h
//
// Lightweight embedded HTTP server for RTProtect Activation Authority.
// Listens for /activate, /renew, and /deactivate REST requests.

#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>

#include "licensing/activation_service.h"

namespace rtprotect::licensing {

class ActivationServerHttp {
 public:
  explicit ActivationServerHttp(ActivationService& service);
  ~ActivationServerHttp();

  // Starts the HTTP server on specified port (use 0 for auto-assigned ephemeral port)
  bool Start(std::uint16_t port = 8080, const std::string& host = "127.0.0.1");

  // Stops server and terminates worker thread
  void Stop();

  bool is_running() const { return running_.load(); }
  std::uint16_t port() const { return port_; }
  std::string base_url() const;

 private:
  void ServerLoop();

  ActivationService& service_;
  std::atomic<bool> running_{false};
  std::uint16_t port_{0};
  std::string host_{"127.0.0.1"};
  uintptr_t listen_fd_{~0ULL}; // SOCKET on Win32, int on POSIX
  std::thread worker_thread_;
};

}  // namespace rtprotect::licensing
