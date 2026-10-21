// licensing/activation_server_http.cpp

#include "licensing/activation_server_http.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <vector>

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

}  // namespace

ActivationServerHttp::ActivationServerHttp(ActivationService& service)
    : service_(service) {}

ActivationServerHttp::~ActivationServerHttp() {
  Stop();
}

std::string ActivationServerHttp::base_url() const {
  return "http://" + host_ + ":" + std::to_string(port_);
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

  if (listen(listen_sock, 16) != 0) {
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

  worker_thread_ = std::thread(&ActivationServerHttp::ServerLoop, this);
  return true;
}

void ActivationServerHttp::Stop() {
  if (!running_.exchange(false)) return;

  if (listen_fd_ != ~0ULL) {
    socket_t s = static_cast<socket_t>(listen_fd_);
    listen_fd_ = ~0ULL;
    CLOSE_SOCKET(s);
  }

  if (worker_thread_.joinable()) {
    worker_thread_.join();
  }
}

void ActivationServerHttp::ServerLoop() {
  socket_t listen_sock = static_cast<socket_t>(listen_fd_);

  while (running_.load()) {
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(listen_sock, &read_fds);

    timeval tv{};
    tv.tv_sec = 0;
    tv.tv_usec = 100000; // 100ms timeout to check running_ flag

    int sel = select(static_cast<int>(listen_sock + 1), &read_fds, nullptr, nullptr, &tv);
    if (sel <= 0) continue;

    sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    socket_t client_sock = accept(listen_sock, reinterpret_cast<sockaddr*>(&client_addr), &client_len);
    if (client_sock == INVALID_SOCKET_VALUE) continue;

    // Read HTTP request
    std::string raw_req;
    char buf[4096];
    std::size_t content_length = 0;
    std::size_t header_end = std::string::npos;

    while (running_.load()) {
      int bytes = recv(client_sock, buf, sizeof(buf), 0);
      if (bytes <= 0) break;
      raw_req.append(buf, bytes);

      if (header_end == std::string::npos) {
        header_end = raw_req.find("\r\n\r\n");
        if (header_end != std::string::npos) {
          // Parse Content-Length
          auto cl_pos = raw_req.find("Content-Length:");
          if (cl_pos == std::string::npos) cl_pos = raw_req.find("content-length:");
          if (cl_pos != std::string::npos && cl_pos < header_end) {
            cl_pos += 15;
            while (cl_pos < header_end && (raw_req[cl_pos] == ' ' || raw_req[cl_pos] == '\t')) ++cl_pos;
            content_length = std::strtoul(raw_req.c_str() + cl_pos, nullptr, 10);
          }
        }
      }

      if (header_end != std::string::npos) {
        std::size_t body_len = raw_req.size() - (header_end + 4);
        if (body_len >= content_length) break;
      }
    }

    if (raw_req.empty()) {
      CLOSE_SOCKET(client_sock);
      continue;
    }

    // Parse method and path
    std::istringstream stream(raw_req);
    std::string method, path, proto;
    stream >> method >> path >> proto;

    std::string body;
    if (header_end != std::string::npos) {
      body = raw_req.substr(header_end + 4);
      if (body.size() > content_length) body.resize(content_length);
    }

    std::string resp_body;
    std::string status_line = "HTTP/1.1 200 OK";

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

    std::ostringstream resp_stream;
    resp_stream << status_line << "\r\n";
    resp_stream << "Content-Type: application/json\r\n";
    resp_stream << "Content-Length: " << resp_body.size() << "\r\n";
    resp_stream << "Connection: close\r\n";
    resp_stream << "\r\n";
    resp_stream << resp_body;

    std::string resp_str = resp_stream.str();
    send(client_sock, resp_str.data(), static_cast<int>(resp_str.size()), 0);
    CLOSE_SOCKET(client_sock);
  }
}

}  // namespace rtprotect::licensing
