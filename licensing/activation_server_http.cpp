// licensing/activation_server_http.cpp

#include "licensing/activation_server_http.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <vector>

#include <openssl/ssl.h>
#include <openssl/err.h>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET socket_t;
#define INVALID_SOCKET_VALUE INVALID_SOCKET
#define CLOSE_SOCKET(s) closesocket(s)
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
typedef int socket_t;
#define INVALID_SOCKET_VALUE (-1)
#define CLOSE_SOCKET(s) close(s)
#endif

namespace rtprotect::licensing {

namespace {

#if defined(_WIN32)
struct WinsockInit {
  WinsockInit() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
  }
  ~WinsockInit() {
    WSACleanup();
  }
};
static WinsockInit s_winsock_init;
#endif

void SetSocketTimeouts(socket_t s, int timeout_seconds) {
#if defined(_WIN32)
  DWORD tv_ms = static_cast<DWORD>(timeout_seconds * 1000);
  setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv_ms), sizeof(tv_ms));
  setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv_ms), sizeof(tv_ms));
#else
  struct timeval tv {};
  tv.tv_sec = timeout_seconds;
  tv.tv_usec = 0;
  setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

}  // namespace

ActivationServerHttp::ActivationServerHttp(ActivationService& service)
    : service_(service) {}

ActivationServerHttp::~ActivationServerHttp() {
  Stop();
  if (ssl_ctx_) {
    SSL_CTX_free(reinterpret_cast<SSL_CTX*>(ssl_ctx_));
    ssl_ctx_ = nullptr;
  }
}

bool ActivationServerHttp::EnableTls(const std::string& cert_file, const std::string& key_file) {
  if (running_.load()) return false; // Must be configured before Start()

  if (ssl_ctx_) {
    SSL_CTX_free(reinterpret_cast<SSL_CTX*>(ssl_ctx_));
    ssl_ctx_ = nullptr;
  }

  const SSL_METHOD* method = TLS_server_method();
  SSL_CTX* ctx = SSL_CTX_new(method);
  if (!ctx) return false;

  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

  if (SSL_CTX_use_certificate_file(ctx, cert_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
    SSL_CTX_free(ctx);
    return false;
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, key_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
    SSL_CTX_free(ctx);
    return false;
  }

  if (!SSL_CTX_check_private_key(ctx)) {
    SSL_CTX_free(ctx);
    return false;
  }

  ssl_ctx_ = ctx;
  is_tls_ = true;
  tls_cert_file_ = cert_file;
  tls_key_file_ = key_file;
  return true;
}

std::string ActivationServerHttp::base_url() const {
  std::string scheme = is_tls_ ? "https://" : "http://";
  return scheme + host_ + ":" + std::to_string(port_);
}

bool ActivationServerHttp::Start(std::uint16_t port, const std::string& host) {
  Stop();

  host_ = host;
  port_ = port;

  socket_t listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (listen_sock == INVALID_SOCKET_VALUE) {
    return false;
  }

  int opt = 1;
#if defined(_WIN32)
  setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));
#else
  setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  inet_pton(AF_INET, host.c_str(), &addr.sin_addr);

  if (bind(listen_sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    CLOSE_SOCKET(listen_sock);
    return false;
  }

  if (listen(listen_sock, 32) != 0) {
    CLOSE_SOCKET(listen_sock);
    return false;
  }

  // Retrieve assigned port if dynamic (port 0)
  sockaddr_in bound_addr{};
  socklen_t addr_len = sizeof(bound_addr);
  if (getsockname(listen_sock, reinterpret_cast<sockaddr*>(&bound_addr), &addr_len) == 0) {
    port_ = ntohs(bound_addr.sin_port);
  }

  listen_fd_ = static_cast<uintptr_t>(listen_sock);
  running_.store(true);

  accept_thread_ = std::thread(&ActivationServerHttp::ServerLoop, this);
  return true;
}

void ActivationServerHttp::RegisterClientSocket(uintptr_t s) {
  std::lock_guard<std::mutex> lock(sockets_mu_);
  client_sockets_.insert(s);
}

void ActivationServerHttp::UnregisterClientSocket(uintptr_t s) {
  std::lock_guard<std::mutex> lock(sockets_mu_);
  client_sockets_.erase(s);
}

void ActivationServerHttp::CloseAllClientSockets() {
  std::lock_guard<std::mutex> lock(sockets_mu_);
  for (uintptr_t s_fd : client_sockets_) {
    socket_t s = static_cast<socket_t>(s_fd);
    CLOSE_SOCKET(s);
  }
  client_sockets_.clear();
}

void ActivationServerHttp::Stop() {
  if (!running_.exchange(false)) return;

  if (listen_fd_ != ~0ULL) {
    socket_t s = static_cast<socket_t>(listen_fd_);
    listen_fd_ = ~0ULL;
    CLOSE_SOCKET(s);
  }

  if (accept_thread_.joinable()) {
    accept_thread_.join();
  }

  // Force-close all open client sockets so in-flight workers immediately unblock from recv()
  CloseAllClientSockets();

  // Safely wait for all active worker threads to terminate and join them
  {
    std::unique_lock<std::mutex> lock(workers_mu_);
    workers_cv_.wait(lock, [this]() { return active_workers_.empty(); });
    for (auto& t : finished_workers_) {
      if (t.joinable()) t.join();
    }
    finished_workers_.clear();
  }
}

void ActivationServerHttp::ServerLoop() {
  socket_t listen_sock = static_cast<socket_t>(listen_fd_);

  while (running_.load()) {
    // Periodically prune any finished worker threads
    {
      std::lock_guard<std::mutex> lock(workers_mu_);
      for (auto& t : finished_workers_) {
        if (t.joinable()) t.join();
      }
      finished_workers_.clear();
    }

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(listen_sock, &read_fds);

    timeval tv{};
    tv.tv_sec = 0;
    tv.tv_usec = 100000; // 100ms poll interval

    int sel = select(static_cast<int>(listen_sock + 1), &read_fds, nullptr, nullptr, &tv);
    if (sel <= 0) continue;

    sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    socket_t client_sock = accept(listen_sock, reinterpret_cast<sockaddr*>(&client_addr), &client_len);
    if (client_sock == INVALID_SOCKET_VALUE) continue;

    // Atomic concurrency cap check & acquisition (strictly eliminates TOCTOU overshoot)
    std::size_t curr = active_clients_.load(std::memory_order_relaxed);
    bool slot_acquired = false;
    while (curr < kMaxConcurrentClients) {
      if (active_clients_.compare_exchange_weak(curr, curr + 1,
                                               std::memory_order_acquire,
                                               std::memory_order_relaxed)) {
        slot_acquired = true;
        break;
      }
    }

    if (!slot_acquired) {
      const char* busy_resp =
          "HTTP/1.1 503 Service Unavailable\r\n"
          "Content-Type: application/json\r\n"
          "Content-Length: 33\r\n"
          "Connection: close\r\n\r\n"
          "{\"error\":\"server busy - try later\"}\n";
      send(client_sock, busy_resp, static_cast<int>(std::strlen(busy_resp)), 0);
      CLOSE_SOCKET(client_sock);
      continue;
    }

    // Spawn and track worker thread lifecycle
    std::thread t([this, client_sock]() {
      HandleClient(static_cast<uintptr_t>(client_sock));

      {
        std::lock_guard<std::mutex> lock(workers_mu_);
        auto it = active_workers_.find(std::this_thread::get_id());
        if (it != active_workers_.end()) {
          finished_workers_.push_back(std::move(it->second));
          active_workers_.erase(it);
        }
        active_clients_.fetch_sub(1, std::memory_order_release);
      }
      workers_cv_.notify_all();
    });

    std::thread::id tid = t.get_id();
    {
      std::lock_guard<std::mutex> lock(workers_mu_);
      active_workers_[tid] = std::move(t);
    }
  }
}

void ActivationServerHttp::HandleClient(uintptr_t client_sock_fd) {
  socket_t client_sock = static_cast<socket_t>(client_sock_fd);
  RegisterClientSocket(client_sock_fd);

  // Set 5-second socket timeout to prevent Slowloris attacks
  SetSocketTimeouts(client_sock, 5);

  SSL* ssl = nullptr;
  if (is_tls_ && ssl_ctx_) {
    ssl = SSL_new(reinterpret_cast<SSL_CTX*>(ssl_ctx_));
    if (!ssl) {
      UnregisterClientSocket(client_sock_fd);
      CLOSE_SOCKET(client_sock);
      return;
    }
    SSL_set_fd(ssl, static_cast<int>(client_sock));
    if (SSL_accept(ssl) <= 0) {
      SSL_free(ssl);
      UnregisterClientSocket(client_sock_fd);
      CLOSE_SOCKET(client_sock);
      return;
    }
  }

  auto raw_read = [&](char* buf, int max_len) -> int {
    if (ssl) {
      return SSL_read(ssl, buf, max_len);
    }
    return recv(client_sock, buf, max_len, 0);
  };

  auto raw_write = [&](const char* buf, int len) -> int {
    if (ssl) {
      return SSL_write(ssl, buf, len);
    }
    return send(client_sock, buf, len, 0);
  };

  std::string raw_req;
  char buf[4096];
  std::size_t content_length = 0;
  std::size_t header_end = std::string::npos;
  bool payload_too_large = false;

  while (running_.load()) {
    int bytes = raw_read(buf, sizeof(buf));
    if (bytes <= 0) break;

    raw_req.append(buf, bytes);

    // Limit maximum total size to prevent unbounded memory consumption
    if (raw_req.size() > (kMaxHeaderBytes + kMaxRequestBodyBytes)) {
      payload_too_large = true;
      break;
    }

    if (header_end == std::string::npos) {
      header_end = raw_req.find("\r\n\r\n");
      if (header_end != std::string::npos) {
        if (header_end > kMaxHeaderBytes) {
          payload_too_large = true;
          break;
        }

        auto cl_pos = raw_req.find("Content-Length:");
        if (cl_pos == std::string::npos) cl_pos = raw_req.find("content-length:");
        if (cl_pos != std::string::npos && cl_pos < header_end) {
          cl_pos += 15;
          while (cl_pos < header_end && (raw_req[cl_pos] == ' ' || raw_req[cl_pos] == '\t')) ++cl_pos;
          content_length = std::strtoul(raw_req.c_str() + cl_pos, nullptr, 10);
          if (content_length > kMaxRequestBodyBytes) {
            payload_too_large = true;
            break;
          }
        }
      }
    }

    if (header_end != std::string::npos) {
      std::size_t body_len = raw_req.size() - (header_end + 4);
      if (body_len >= content_length) break;
    }
  }

  std::string status_line = "HTTP/1.1 200 OK";
  std::string resp_body;

  if (payload_too_large) {
    status_line = "HTTP/1.1 413 Payload Too Large";
    resp_body = "{\"error\":\"payload exceeds maximum allowed limit\"}\n";
  } else if (raw_req.empty()) {
    if (ssl) {
      SSL_shutdown(ssl);
      SSL_free(ssl);
    }
    UnregisterClientSocket(client_sock_fd);
    CLOSE_SOCKET(client_sock);
    return;
  } else {
    // Parse method and path
    std::istringstream stream(raw_req);
    std::string method, path, proto;
    stream >> method >> path >> proto;

    std::string body;
    if (header_end != std::string::npos) {
      body = raw_req.substr(header_end + 4);
      if (body.size() > content_length) body.resize(content_length);
    }

    if (path == "/activate" && method == "POST") {
      resp_body = service_.HandleActivateJson(body);
    } else if (path == "/renew" && method == "POST") {
      resp_body = service_.HandleRenewJson(body);
    } else if (path == "/deactivate" && method == "POST") {
      resp_body = service_.HandleDeactivateJson(body);
    } else if (path == "/health" && method == "GET") {
      resp_body = "{\"status\":\"ok\"}\n";
    } else {
      status_line = "HTTP/1.1 404 Not Found";
      resp_body = "{\"error\":\"endpoint not found\"}\n";
    }
  }

  std::ostringstream resp_stream;
  resp_stream << status_line << "\r\n";
  resp_stream << "Content-Type: application/json\r\n";
  resp_stream << "Content-Length: " << resp_body.size() << "\r\n";
  resp_stream << "Connection: close\r\n";
  resp_stream << "\r\n";
  resp_stream << resp_body;

  std::string resp_str = resp_stream.str();
  raw_write(resp_str.data(), static_cast<int>(resp_str.size()));

  if (ssl) {
    SSL_shutdown(ssl);
    SSL_free(ssl);
  }
  UnregisterClientSocket(client_sock_fd);
  CLOSE_SOCKET(client_sock);
}

}  // namespace rtprotect::licensing
