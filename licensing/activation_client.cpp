// licensing/activation_client.cpp

#include "licensing/activation_client.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <vector>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>

#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "crypto/aead.h"
#include "crypto/kdf.h"
#include "licensing/countermeasure_config.h"
#include "licensing/hardware_id.h"
#include "licensing/trusted_time.h"
#include "tooling/simple_json.h"

namespace rtprotect::licensing {

namespace {

std::string BytesToHex(const std::uint8_t* data, std::size_t len) {
  std::ostringstream ss;
  for (std::size_t i = 0; i < len; ++i) {
    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
  }
  return ss.str();
}

bool HexToBytes(const std::string& hex, std::uint8_t* out, std::size_t expected_len) {
  if (hex.size() != expected_len * 2) return false;
  for (std::size_t i = 0; i < expected_len; ++i) {
    char h[3] = { hex[i * 2], hex[i * 2 + 1], '\0' };
    char* end = nullptr;
    long v = std::strtol(h, &end, 16);
    if (end != h + 2 || v < 0 || v > 255) return false;
    out[i] = static_cast<std::uint8_t>(v);
  }
  return true;
}

std::string EscapeJsonString(const std::string& str) {
  std::string out;
  out.reserve(str.size() * 2);
  for (char c : str) {
    if (c == '\\') out += "\\\\";
    else if (c == '"') out += "\\\"";
    else if (c == '\n') out += "\\n";
    else if (c == '\r') out += "\\r";
    else if (c == '\t') out += "\\t";
    else if (static_cast<unsigned char>(c) < 0x20) {
      char buf[8];
      std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
      out += buf;
    } else {
      out += c;
    }
  }
  return out;
}

}  // namespace

std::optional<ParsedUrl> ParseUrl(const std::string& url_str) {
  if (url_str.empty()) return std::nullopt;
  ParsedUrl res;
  std::string rem = url_str;
  if (rem.rfind("https://", 0) == 0) {
    res.is_https = true;
    res.port = 443;
    rem = rem.substr(8);
  } else if (rem.rfind("http://", 0) == 0) {
    res.is_https = false;
    res.port = 80;
    rem = rem.substr(7);
  } else {
    return std::nullopt; // Disallow unencrypted schemes or missing protocol
  }

  // Reject embedded credentials in authority URL
  if (rem.find('@') != std::string::npos) {
    return std::nullopt;
  }

  auto slash_pos = rem.find('/');
  std::string host_port;
  if (slash_pos != std::string::npos) {
    host_port = rem.substr(0, slash_pos);
    res.path = rem.substr(slash_pos);
  } else {
    host_port = rem;
    res.path = "/";
  }

  if (host_port.empty()) return std::nullopt;

  if (host_port.front() == '[') {
    // IPv6 bracketed literal: e.g. [::1]:8080 or [2001:db8::1]
    auto close_bracket = host_port.find(']');
    if (close_bracket == std::string::npos) return std::nullopt;
    res.host = host_port.substr(1, close_bracket - 1);
    if (close_bracket + 1 < host_port.size()) {
      if (host_port[close_bracket + 1] != ':') return std::nullopt;
      std::string pstr = host_port.substr(close_bracket + 2);
      char* end = nullptr;
      long p = std::strtol(pstr.c_str(), &end, 10);
      if (end != pstr.c_str() + pstr.size() || p <= 0 || p > 65535) return std::nullopt;
      res.port = static_cast<std::uint16_t>(p);
    }
  } else {
    auto colon_pos = host_port.find(':');
    if (colon_pos != std::string::npos) {
      res.host = host_port.substr(0, colon_pos);
      std::string pstr = host_port.substr(colon_pos + 1);
      char* end = nullptr;
      long p = std::strtol(pstr.c_str(), &end, 10);
      if (end != pstr.c_str() + pstr.size() || p <= 0 || p > 65535) return std::nullopt;
      res.port = static_cast<std::uint16_t>(p);
    } else {
      res.host = host_port;
    }
  }

  if (res.host.empty()) return std::nullopt;
  return res;
}

namespace {

std::optional<std::string> HttpPostWinHttp(const ParsedUrl& url, const std::string& path, const std::string& json_body, std::string* error_out) {
  HINTERNET hSession = WinHttpOpen(L"RTProtect-Activation-Client/2.0",
                                   WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                   WINHTTP_NO_PROXY_NAME,
                                   WINHTTP_NO_PROXY_BYPASS, 0);
  if (!hSession) {
    if (error_out) *error_out = "Failed to initialize WinHttp session";
    return std::nullopt;
  }

  std::wstring wHost(url.host.begin(), url.host.end());
  HINTERNET hConnect = WinHttpConnect(hSession, wHost.c_str(), url.port, 0);
  if (!hConnect) {
    WinHttpCloseHandle(hSession);
    if (error_out) *error_out = "Failed to connect to activation server at " + url.host;
    return std::nullopt;
  }

  std::string full_path = url.path;
  if (full_path.back() == '/' && !path.empty() && path.front() == '/') {
    full_path += path.substr(1);
  } else if (full_path.back() != '/' && !path.empty() && path.front() != '/') {
    full_path += "/" + path;
  } else if (!path.empty()) {
    full_path += path;
  }
  std::wstring wPath(full_path.begin(), full_path.end());

  DWORD flags = url.is_https ? WINHTTP_FLAG_SECURE : 0;
  HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", wPath.c_str(),
                                          nullptr, WINHTTP_NO_REFERER,
                                          WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
  if (!hRequest) {
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    if (error_out) *error_out = "Failed to open WinHttp request";
    return std::nullopt;
  }

  // Set timeout to 10 seconds
  WinHttpSetTimeouts(hRequest, 5000, 5000, 10000, 10000);

  LPCWSTR headers = L"Content-Type: application/json\r\n";
  BOOL sent = WinHttpSendRequest(hRequest, headers, static_cast<DWORD>(-1),
                                 const_cast<char*>(json_body.data()),
                                 static_cast<DWORD>(json_body.size()),
                                 static_cast<DWORD>(json_body.size()), 0);
  if (!sent) {
    DWORD err = GetLastError();
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    if (error_out) *error_out = "WinHttpSendRequest failed with error code: " + std::to_string(err);
    return std::nullopt;
  }

  if (!WinHttpReceiveResponse(hRequest, nullptr)) {
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    if (error_out) *error_out = "Failed to receive response from activation server";
    return std::nullopt;
  }

  DWORD status_code = 0;
  DWORD status_code_size = sizeof(status_code);
  if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                          WINHTTP_HEADER_NAME_BY_INDEX, &status_code, &status_code_size, WINHTTP_NO_HEADER_INDEX)) {
    if (status_code != 200) {
      WinHttpCloseHandle(hRequest);
      WinHttpCloseHandle(hConnect);
      WinHttpCloseHandle(hSession);
      if (error_out) *error_out = "Activation server returned HTTP status " + std::to_string(status_code);
      return std::nullopt;
    }
  } else {
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    if (error_out) *error_out = "Failed to query HTTP status code from server response";
    return std::nullopt;
  }

  std::string response_body;
  DWORD bytes_available = 0;
  while (WinHttpQueryDataAvailable(hRequest, &bytes_available) && bytes_available > 0) {
    std::vector<char> buf(bytes_available);
    DWORD bytes_read = 0;
    if (WinHttpReadData(hRequest, buf.data(), bytes_available, &bytes_read) && bytes_read > 0) {
      response_body.append(buf.data(), bytes_read);
    } else {
      break;
    }
  }

  WinHttpCloseHandle(hRequest);
  WinHttpCloseHandle(hConnect);
  WinHttpCloseHandle(hSession);
  return response_body;
}

std::optional<std::string> HttpPostSocket(const ParsedUrl& url, const std::string& path, const std::string& json_body, std::string* error_out) {
  SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s == INVALID_SOCKET) {
    if (error_out) *error_out = "Failed to create socket";
    return std::nullopt;
  }
  DWORD tv_ms = 8000;
  setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv_ms), sizeof(tv_ms));
  setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv_ms), sizeof(tv_ms));

  sockaddr_in server_addr{};
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(url.port);
  inet_pton(AF_INET, url.host.c_str(), &server_addr.sin_addr);

  if (connect(s, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) != 0) {
    closesocket(s);
    if (error_out) *error_out = "Socket connection failed to " + url.host + ":" + std::to_string(url.port);
    return std::nullopt;
  }

  std::string full_path = url.path;
  if (full_path.back() == '/' && !path.empty() && path.front() == '/') {
    full_path += path.substr(1);
  } else if (full_path.back() != '/' && !path.empty() && path.front() != '/') {
    full_path += "/" + path;
  } else if (!path.empty()) {
    full_path += path;
  }

  std::ostringstream req_stream;
  req_stream << "POST " << full_path << " HTTP/1.1\r\n";
  req_stream << "Host: " << url.host << ":" << url.port << "\r\n";
  req_stream << "Content-Type: application/json\r\n";
  req_stream << "Content-Length: " << json_body.size() << "\r\n";
  req_stream << "Connection: close\r\n";
  req_stream << "\r\n";
  req_stream << json_body;

  std::string req_str = req_stream.str();
  int total_sent = 0;
  int req_len = static_cast<int>(req_str.size());
  while (total_sent < req_len) {
    int n = send(s, req_str.data() + total_sent, req_len - total_sent, 0);
    if (n == SOCKET_ERROR) {
      int err = WSAGetLastError();
      if (err == WSAEINTR) continue;
      closesocket(s);
      if (error_out) *error_out = "Socket send error: " + std::to_string(err);
      return std::nullopt;
    }
    if (n <= 0) {
      closesocket(s);
      if (error_out) *error_out = "Socket connection closed during send to " + url.host;
      return std::nullopt;
    }
    total_sent += n;
  }

  std::string resp;
  char buf[4096];
  constexpr std::size_t kMaxResponseBytes = 512 * 1024;
  while (true) {
    int bytes = recv(s, buf, sizeof(buf), 0);
    if (bytes <= 0) break;
    resp.append(buf, bytes);
    if (resp.size() > kMaxResponseBytes) {
      closesocket(s);
      if (error_out) *error_out = "Server response exceeds 512KB safety limit";
      return std::nullopt;
    }
  }

  closesocket(s);

  auto first_line_end = resp.find("\r\n");
  if (first_line_end == std::string::npos) {
    if (error_out) *error_out = "Malformed HTTP status line";
    return std::nullopt;
  }
  std::string status_line = resp.substr(0, first_line_end);
  auto first_space = status_line.find(' ');
  int http_code = 0;
  if (first_space != std::string::npos && first_space + 4 <= status_line.size()) {
    http_code = std::atoi(status_line.substr(first_space + 1, 3).c_str());
  }

  auto body_pos = resp.find("\r\n\r\n");
  if (body_pos == std::string::npos) {
    if (error_out) *error_out = "Malformed HTTP response";
    return std::nullopt;
  }

  std::string body = resp.substr(body_pos + 4);
  if (http_code != 200) {
    if (error_out) *error_out = "Server returned HTTP status " + std::to_string(http_code) + (body.empty() ? "" : ": " + body);
    return std::nullopt;
  }
  return body;
}

// Native OpenSSL TLS HTTP client with strict certificate verification
std::optional<std::string> HttpPostTls(const ParsedUrl& url, const std::string& path, const std::string& json_body, std::string* error_out) {
  SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s == INVALID_SOCKET) {
    if (error_out) *error_out = "Failed to create socket for TLS";
    return std::nullopt;
  }
  DWORD tv_ms = 10000;
  setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv_ms), sizeof(tv_ms));
  setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv_ms), sizeof(tv_ms));

  struct addrinfo hints{}, *res = nullptr;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  std::string port_str = std::to_string(url.port == 0 ? 443 : url.port);
  if (getaddrinfo(url.host.c_str(), port_str.c_str(), &hints, &res) != 0 || !res) {
    closesocket(s);
    if (error_out) *error_out = "Failed to resolve TLS host: " + url.host;
    return std::nullopt;
  }

  if (connect(s, res->ai_addr, static_cast<int>(res->ai_addrlen)) != 0) {
    freeaddrinfo(res);
    closesocket(s);
    if (error_out) *error_out = "TLS socket connection failed to " + url.host + ":" + port_str;
    return std::nullopt;
  }
  freeaddrinfo(res);

  const SSL_METHOD* method = TLS_client_method();
  SSL_CTX* ctx = SSL_CTX_new(method);
  if (!ctx) {
    closesocket(s);
    if (error_out) *error_out = "Failed to initialize SSL_CTX";
    return std::nullopt;
  }

  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
  SSL_CTX_set_default_verify_paths(ctx);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);

  SSL* ssl = SSL_new(ctx);
  if (!ssl) {
    SSL_CTX_free(ctx);
    closesocket(s);
    if (error_out) *error_out = "Failed to create SSL instance";
    return std::nullopt;
  }

  if (SSL_set_tlsext_host_name(ssl, url.host.c_str()) != 1) {
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    closesocket(s);
    if (error_out) *error_out = "Failed to configure TLS SNI host name: " + url.host;
    return std::nullopt;
  }
  if (SSL_set1_host(ssl, url.host.c_str()) != 1) {
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    closesocket(s);
    if (error_out) *error_out = "Failed to configure TLS hostname validation: " + url.host;
    return std::nullopt;
  }
  SSL_set_fd(ssl, static_cast<int>(s));

  if (SSL_connect(ssl) <= 0) {
    long verify_err = SSL_get_verify_result(ssl);
    std::string err_desc = "TLS handshake failed";
    if (verify_err != X509_V_OK) {
      err_desc += ": certificate verification failed (" + std::string(X509_verify_cert_error_string(verify_err)) + ")";
    }
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    closesocket(s);
    if (error_out) *error_out = err_desc;
    return std::nullopt;
  }

  if (SSL_get_verify_result(ssl) != X509_V_OK) {
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    closesocket(s);
    if (error_out) *error_out = "TLS peer certificate verification failed";
    return std::nullopt;
  }

  std::string full_path = url.path;
  if (full_path.back() == '/' && !path.empty() && path.front() == '/') {
    full_path += path.substr(1);
  } else if (full_path.back() != '/' && !path.empty() && path.front() != '/') {
    full_path += "/" + path;
  } else if (!path.empty()) {
    full_path += path;
  }

  std::ostringstream req_stream;
  req_stream << "POST " << full_path << " HTTP/1.1\r\n";
  req_stream << "Host: " << url.host << ":" << port_str << "\r\n";
  req_stream << "Content-Type: application/json\r\n";
  req_stream << "Content-Length: " << json_body.size() << "\r\n";
  req_stream << "Connection: close\r\n";
  req_stream << "\r\n";
  req_stream << json_body;

  std::string req_str = req_stream.str();
  int total_sent = 0;
  int req_len = static_cast<int>(req_str.size());
  while (total_sent < req_len) {
    int n = SSL_write(ssl, req_str.data() + total_sent, req_len - total_sent);
    if (n <= 0) {
      int err = SSL_get_error(ssl, n);
      if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
        continue;
      }
      SSL_shutdown(ssl);
      SSL_free(ssl);
      SSL_CTX_free(ctx);
      closesocket(s);
      if (error_out) *error_out = "Failed to send complete request over TLS";
      return std::nullopt;
    }
    total_sent += n;
  }

  std::string resp;
  char buf[4096];
  constexpr std::size_t kMaxResponseBytes = 512 * 1024;
  while (true) {
    int bytes = SSL_read(ssl, buf, sizeof(buf));
    if (bytes <= 0) break;
    resp.append(buf, bytes);
    if (resp.size() > kMaxResponseBytes) {
      SSL_shutdown(ssl);
      SSL_free(ssl);
      SSL_CTX_free(ctx);
      closesocket(s);
      if (error_out) *error_out = "TLS response exceeds 512KB safety limit";
      return std::nullopt;
    }
  }

  SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  closesocket(s);

  auto first_line_end = resp.find("\r\n");
  if (first_line_end == std::string::npos) {
    if (error_out) *error_out = "Malformed HTTP status line over TLS";
    return std::nullopt;
  }
  std::string status_line = resp.substr(0, first_line_end);
  auto first_space = status_line.find(' ');
  int http_code = 0;
  if (first_space != std::string::npos && first_space + 4 <= status_line.size()) {
    http_code = std::atoi(status_line.substr(first_space + 1, 3).c_str());
  }

  auto body_pos = resp.find("\r\n\r\n");
  if (body_pos == std::string::npos) {
    if (error_out) *error_out = "Malformed HTTP response over TLS";
    return std::nullopt;
  }

  std::string body = resp.substr(body_pos + 4);
  if (http_code != 200) {
    if (error_out) *error_out = "Server returned HTTP status " + std::to_string(http_code) + (body.empty() ? "" : ": " + body);
    return std::nullopt;
  }
  return body;
}

std::optional<std::string> DispatchHttpPost(const std::string& base_url, const std::string& endpoint, const std::string& body, std::string* error_out) {
  auto url_opt = ParseUrl(base_url);
  if (!url_opt.has_value()) {
    if (error_out) *error_out = "Invalid activation server URL: " + base_url;
    return std::nullopt;
  }
  const auto& url = *url_opt;
  if (url.is_https) {
    auto winhttp_res = HttpPostWinHttp(url, endpoint, body, error_out);
    if (winhttp_res.has_value()) {
      return winhttp_res;
    }
    // Native OpenSSL TLS with strict peer certificate verification fallback
    return HttpPostTls(url, endpoint, body, error_out);
  }

  // Plain HTTP used ONLY when caller explicitly provided http:// on local loopback
  bool is_loopback = (url.host == "127.0.0.1" || url.host == "localhost" || url.host == "::1");
  const char* req_https_env = std::getenv("RTPROTECT_REQUIRE_HTTPS");
  bool require_https = req_https_env && (std::strcmp(req_https_env, "1") == 0 || std::strcmp(req_https_env, "true") == 0);
  if (!is_loopback || require_https) {
    if (error_out) *error_out = "Refusing insecure plain HTTP connection: " + base_url + " (HTTPS required)";
    return std::nullopt;
  }
  return HttpPostSocket(url, endpoint, body, error_out);
}

std::optional<crypto::Aes256Key> DeriveTransportKey(
    const std::string& license_key,
    const std::array<std::uint8_t, 32>& client_nonce,
    const std::array<std::uint8_t, 32>& server_nonce) {
  crypto::SecureBuffer sec_lic(reinterpret_cast<const std::uint8_t*>(license_key.data()), license_key.size());
  std::vector<std::uint8_t> salt;
  salt.reserve(64);
  salt.insert(salt.end(), client_nonce.begin(), client_nonce.end());
  salt.insert(salt.end(), server_nonce.begin(), server_nonce.end());
  std::string info = "rtprotect/transport/token-encryption/v1";
  auto derived = crypto::Hkdf::DeriveKey(sec_lic, salt, info, crypto::kAes256KeyLen);
  if (!derived.has_value()) return std::nullopt;
  return crypto::Aes256Key::FromBytes(derived->data(), derived->size());
}

}  // namespace

std::optional<ActivationToken> RequestOnlineActivation(
    const std::string& server_url,
    const std::string& license_key,
    const std::string& product_id,
    const integrity::Ed25519PublicKey& vendor_pubkey,
    std::string* error_out,
    const std::string& activation_credential,
    std::uint64_t client_timestamp) {
  std::string hwid = GetLocalHardwareId();

  if (client_timestamp == 0) {
    client_timestamp = static_cast<std::uint64_t>(std::time(nullptr));
  }

  std::array<std::uint8_t, 32> client_nonce{};
  if (RAND_bytes(client_nonce.data(), static_cast<int>(client_nonce.size())) != 1) {
    if (error_out) *error_out = "RNG failure generating challenge nonce";
    return std::nullopt;
  }

  std::ostringstream json_req;
  json_req << "{\n";
  json_req << "  \"license_key\": \"" << EscapeJsonString(license_key) << "\",\n";
  json_req << "  \"device_fingerprint\": \"" << EscapeJsonString(hwid) << "\",\n";
  json_req << "  \"product_id\": \"" << EscapeJsonString(product_id) << "\",\n";
  json_req << "  \"client_version\": \"2.0.0\",\n";
  json_req << "  \"client_timestamp\": " << client_timestamp << ",\n";
  if (!activation_credential.empty()) {
    json_req << "  \"activation_credential\": \"" << EscapeJsonString(activation_credential) << "\",\n";
  }
  json_req << "  \"client_nonce\": \"" << BytesToHex(client_nonce.data(), client_nonce.size()) << "\"\n";
  json_req << "}\n";

  auto resp_body = DispatchHttpPost(server_url, "/activate", json_req.str(), error_out);
  if (!resp_body.has_value()) return std::nullopt;

  auto root = tooling::JsonValue::Parse(*resp_body);
  if (!root.has_value() || !root->is_object()) {
    if (error_out) *error_out = "Malformed JSON response from activation authority";
    return std::nullopt;
  }

  const auto& obj = *root;
  std::string status = obj["status"].as_string();
  if (status != "Valid" && status != "valid") {
    std::string err = obj.contains("error") ? obj["error"].as_string() : "Activation rejected by server with status: " + status;
    if (error_out) *error_out = err;
    return std::nullopt;
  }

  std::string s_nonce_hex = obj["server_nonce"].as_string();
  std::string enc_token_hex = obj["encrypted_token"].as_string();
  if (s_nonce_hex.empty() || enc_token_hex.empty()) {
    if (error_out) *error_out = "Server response missing server_nonce or encrypted_token";
    return std::nullopt;
  }

  std::array<std::uint8_t, 32> server_nonce{};
  if (!HexToBytes(s_nonce_hex, server_nonce.data(), server_nonce.size())) {
    if (error_out) *error_out = "Malformed server_nonce in response";
    return std::nullopt;
  }

  auto session_key = DeriveTransportKey(!activation_credential.empty() ? activation_credential : license_key,
                                        client_nonce, server_nonce);
  if (!session_key.has_value()) {
    if (error_out) *error_out = "Failed to derive transport decryption key";
    return std::nullopt;
  }

  std::vector<std::uint8_t> wire_enc(enc_token_hex.size() / 2);
  if (!HexToBytes(enc_token_hex, wire_enc.data(), wire_enc.size())) {
    if (error_out) *error_out = "Malformed encrypted_token hex";
    return std::nullopt;
  }

  auto enc_msg = crypto::EncryptedMessage::Deserialize(wire_enc.data(), wire_enc.size());
  if (!enc_msg.has_value()) {
    if (error_out) *error_out = "Failed to deserialize encrypted message payload";
    return std::nullopt;
  }

  crypto::AeadError err = crypto::AeadError::kNone;
  auto plaintext = crypto::Decrypt(*session_key, *enc_msg, nullptr, 0, &err);
  if (!plaintext.has_value()) {
    if (error_out) *error_out = "Failed to decrypt activation token (tampered transport or incorrect key)";
    return std::nullopt;
  }

  auto token_opt = DeserializeActivationToken(plaintext->data(), plaintext->size());
  if (!token_opt.has_value()) {
    if (error_out) *error_out = "Failed to deserialize decrypted activation token";
    return std::nullopt;
  }

  const auto& token = *token_opt;
  if (!VerifyActivationTokenSignature(token, vendor_pubkey)) {
    if (error_out) *error_out = "Vendor Ed25519 signature on activation token failed verification";
    return std::nullopt;
  }

  // Anchor verified server timestamp for monotonic trusted time enforcement
  TrustedTime::AnchorServerTime(product_id, token.issued_at);

  // Dynamic Countermeasure Updates (Continuous Response Channel)
  if (obj.contains("countermeasure_config")) {
    std::string cm_hex = obj["countermeasure_config"].as_string();
    if (!cm_hex.empty() && cm_hex.size() % 2 == 0) {
      std::vector<std::uint8_t> cm_raw(cm_hex.size() / 2);
      if (HexToBytes(cm_hex, cm_raw.data(), cm_raw.size())) {
        auto cm_cfg = DeserializeCountermeasureConfig(cm_raw.data(), cm_raw.size());
        if (cm_cfg.has_value() && VerifyCountermeasureConfigSignature(*cm_cfg, vendor_pubkey)) {
          auto cur_cfg = LoadCountermeasureConfig(product_id);
          if (!cur_cfg.has_value() || cm_cfg->sequence_number >= cur_cfg->sequence_number) {
            SaveCountermeasureConfig(product_id, *cm_cfg);
            NotifyCountermeasureUpdate(*cm_cfg);
          }
        }
      }
    }
  }

  return token;
}

std::optional<ActivationToken> RequestOnlineRenewal(
    const std::string& server_url,
    const ActivationToken& current_token,
    const integrity::Ed25519PublicKey& vendor_pubkey,
    std::string* error_out) {
  std::string hwid = GetLocalHardwareId();

  std::array<std::uint8_t, 32> client_nonce{};
  if (RAND_bytes(client_nonce.data(), static_cast<int>(client_nonce.size())) != 1) {
    if (error_out) *error_out = "RNG failure generating challenge nonce";
    return std::nullopt;
  }

  auto raw_token = SerializeActivationToken(current_token);
  std::string token_hex = BytesToHex(raw_token.data(), raw_token.size());

  std::ostringstream json_req;
  json_req << "{\n";
  json_req << "  \"token\": \"" << EscapeJsonString(token_hex) << "\",\n";
  json_req << "  \"device_fingerprint\": \"" << EscapeJsonString(hwid) << "\",\n";
  json_req << "  \"client_nonce\": \"" << BytesToHex(client_nonce.data(), client_nonce.size()) << "\"\n";
  json_req << "}\n";

  auto resp_body = DispatchHttpPost(server_url, "/renew", json_req.str(), error_out);
  if (!resp_body.has_value()) return std::nullopt;

  auto root = tooling::JsonValue::Parse(*resp_body);
  if (!root.has_value() || !root->is_object()) {
    if (error_out) *error_out = "Malformed JSON renewal response";
    return std::nullopt;
  }

  const auto& obj = *root;
  std::string status = obj["status"].as_string();
  if (status != "Valid" && status != "valid") {
    std::string err = obj.contains("error") ? obj["error"].as_string() : "Renewal rejected by server with status: " + status;
    if (error_out) *error_out = err;
    return std::nullopt;
  }

  std::string s_nonce_hex = obj["server_nonce"].as_string();
  std::string enc_token_hex = obj["encrypted_token"].as_string();
  if (s_nonce_hex.empty() || enc_token_hex.empty()) {
    if (error_out) *error_out = "Server renewal response missing server_nonce or encrypted_token";
    return std::nullopt;
  }

  std::array<std::uint8_t, 32> server_nonce{};
  if (!HexToBytes(s_nonce_hex, server_nonce.data(), server_nonce.size())) {
    if (error_out) *error_out = "Malformed server_nonce in renewal response";
    return std::nullopt;
  }

  auto session_key = DeriveTransportKey(current_token.license_id, client_nonce, server_nonce);
  if (!session_key.has_value()) {
    if (error_out) *error_out = "Failed to derive transport decryption key";
    return std::nullopt;
  }

  std::vector<std::uint8_t> wire_enc(enc_token_hex.size() / 2);
  if (!HexToBytes(enc_token_hex, wire_enc.data(), wire_enc.size())) {
    if (error_out) *error_out = "Malformed encrypted_token hex";
    return std::nullopt;
  }

  auto enc_msg = crypto::EncryptedMessage::Deserialize(wire_enc.data(), wire_enc.size());
  if (!enc_msg.has_value()) {
    if (error_out) *error_out = "Failed to deserialize encrypted renewed token payload";
    return std::nullopt;
  }

  crypto::AeadError err = crypto::AeadError::kNone;
  auto plaintext = crypto::Decrypt(*session_key, *enc_msg, nullptr, 0, &err);
  if (!plaintext.has_value()) {
    if (error_out) *error_out = "Failed to decrypt renewed token";
    return std::nullopt;
  }

  auto token_opt = DeserializeActivationToken(plaintext->data(), plaintext->size());
  if (!token_opt.has_value()) {
    if (error_out) *error_out = "Failed to deserialize decrypted renewed activation token";
    return std::nullopt;
  }

  const auto& renewed = *token_opt;
  if (!VerifyActivationTokenSignature(renewed, vendor_pubkey)) {
    if (error_out) *error_out = "Vendor Ed25519 signature on renewed activation token failed verification";
    return std::nullopt;
  }

  // Anchor renewed server timestamp for monotonic trusted time enforcement
  TrustedTime::AnchorServerTime(renewed.license_id, renewed.issued_at);

  // Dynamic Countermeasure Updates (Continuous Response Channel)
  if (obj.contains("countermeasure_config")) {
    std::string cm_hex = obj["countermeasure_config"].as_string();
    if (!cm_hex.empty() && cm_hex.size() % 2 == 0) {
      std::vector<std::uint8_t> cm_raw(cm_hex.size() / 2);
      if (HexToBytes(cm_hex, cm_raw.data(), cm_raw.size())) {
        auto cm_cfg = DeserializeCountermeasureConfig(cm_raw.data(), cm_raw.size());
        if (cm_cfg.has_value() && VerifyCountermeasureConfigSignature(*cm_cfg, vendor_pubkey)) {
          auto cur_cfg = LoadCountermeasureConfig(renewed.license_id);
          if (!cur_cfg.has_value() || cm_cfg->sequence_number >= cur_cfg->sequence_number) {
            SaveCountermeasureConfig(renewed.license_id, *cm_cfg);
            NotifyCountermeasureUpdate(*cm_cfg);
          }
        }
      }
    }
  }

  return renewed;
}

bool RequestOnlineDeactivation(
    const std::string& server_url,
    const ActivationToken& current_token,
    std::string* error_out) {
  std::string hwid = GetLocalHardwareId();
  auto raw_token = SerializeActivationToken(current_token);
  std::string token_hex = BytesToHex(raw_token.data(), raw_token.size());

  std::ostringstream json_req;
  json_req << "{\n";
  json_req << "  \"token\": \"" << EscapeJsonString(token_hex) << "\",\n";
  json_req << "  \"device_fingerprint\": \"" << EscapeJsonString(hwid) << "\"\n";
  json_req << "}\n";

  auto resp_body = DispatchHttpPost(server_url, "/deactivate", json_req.str(), error_out);
  if (!resp_body.has_value()) return false;

  auto root = tooling::JsonValue::Parse(*resp_body);
  if (!root.has_value() || !root->is_object()) {
    if (error_out) *error_out = "Malformed JSON response from server";
    return false;
  }

  const auto& obj = *root;
  if (obj.contains("success") && obj["success"].as_bool()) return true;
  if (obj.contains("status") && obj["status"].as_string() == "deactivated") return true;

  if (error_out) {
    *error_out = obj.contains("error") ? obj["error"].as_string() : "Deactivation rejected by server";
  }
  return false;
}

}  // namespace rtprotect::licensing
