// licensing/activation_client.cpp

#include "licensing/activation_client.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <vector>

#include <openssl/rand.h>

#include "crypto/aead.h"
#include "crypto/kdf.h"
#include "licensing/hardware_id.h"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

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

std::optional<std::string> ExtractJsonField(const std::string& json, const std::string& field_name) {
  std::string pattern = "\"" + field_name + "\"";
  auto pos = json.find(pattern);
  if (pos == std::string::npos) return std::nullopt;
  pos += pattern.size();
  while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':' || json[pos] == '\t')) ++pos;
  if (pos >= json.size()) return std::nullopt;

  if (json[pos] == '"') {
    ++pos;
    std::string val;
    while (pos < json.size() && json[pos] != '"') {
      if (json[pos] == '\\' && pos + 1 < json.size()) {
        ++pos;
        if (json[pos] == '"') val += '"';
        else if (json[pos] == '\\') val += '\\';
        else if (json[pos] == 'n') val += '\n';
        else if (json[pos] == 'r') val += '\r';
        else if (json[pos] == 't') val += '\t';
        else val += json[pos];
      } else {
        val += json[pos];
      }
      ++pos;
    }
    return val;
  } else {
    // Non-string field (e.g. true/false/number)
    std::string val;
    while (pos < json.size() && json[pos] != ',' && json[pos] != '}' && json[pos] != '\r' && json[pos] != '\n' && json[pos] != ' ') {
      val += json[pos];
      ++pos;
    }
    return val;
  }
}

struct ParsedUrl {
  bool is_https = false;
  std::string host = "127.0.0.1";
  std::uint16_t port = 80;
  std::string path = "/";
};

ParsedUrl ParseUrl(const std::string& url_str) {
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

  auto colon_pos = host_port.find(':');
  if (colon_pos != std::string::npos) {
    res.host = host_port.substr(0, colon_pos);
    res.port = static_cast<std::uint16_t>(std::strtoul(host_port.c_str() + colon_pos + 1, nullptr, 10));
  } else {
    res.host = host_port;
  }

  return res;
}

#if defined(_WIN32)
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
#endif

std::optional<std::string> HttpPostSocket(const ParsedUrl& url, const std::string& path, const std::string& json_body, std::string* error_out) {
#if defined(_WIN32)
  SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s == INVALID_SOCKET) {
    if (error_out) *error_out = "Failed to create socket";
    return std::nullopt;
  }
#else
  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) {
    if (error_out) *error_out = "Failed to create socket";
    return std::nullopt;
  }
#endif

  sockaddr_in server_addr{};
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(url.port);
#if defined(_WIN32)
  inet_pton(AF_INET, url.host.c_str(), &server_addr.sin_addr);
#else
  inet_pton(AF_INET, url.host.c_str(), &server_addr.sin_addr);
#endif

  if (connect(s, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) != 0) {
#if defined(_WIN32)
    closesocket(s);
#else
    close(s);
#endif
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
  send(s, req_str.data(), static_cast<int>(req_str.size()), 0);

  std::string resp;
  char buf[4096];
  while (true) {
    int bytes = recv(s, buf, sizeof(buf), 0);
    if (bytes <= 0) break;
    resp.append(buf, bytes);
  }

#if defined(_WIN32)
  closesocket(s);
#else
  close(s);
#endif

  auto body_pos = resp.find("\r\n\r\n");
  if (body_pos == std::string::npos) {
    if (error_out) *error_out = "Malformed HTTP response";
    return std::nullopt;
  }

  return resp.substr(body_pos + 4);
}

std::optional<std::string> DispatchHttpPost(const std::string& base_url, const std::string& endpoint, const std::string& body, std::string* error_out) {
  ParsedUrl url = ParseUrl(base_url);
#if defined(_WIN32)
  if (url.is_https) {
    return HttpPostWinHttp(url, endpoint, body, error_out);
  }
#endif
  auto res = HttpPostSocket(url, endpoint, body, error_out);
  if (!res.has_value()) {
#if defined(_WIN32)
    return HttpPostWinHttp(url, endpoint, body, error_out);
#endif
  }
  return res;
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
    std::string* error_out) {
  std::string hwid = GetLocalHardwareId();

  std::array<std::uint8_t, 32> client_nonce{};
  if (RAND_bytes(client_nonce.data(), static_cast<int>(client_nonce.size())) != 1) {
    if (error_out) *error_out = "RNG failure generating challenge nonce";
    return std::nullopt;
  }

  std::ostringstream json_req;
  json_req << "{\n";
  json_req << "  \"license_key\": \"" << license_key << "\",\n";
  json_req << "  \"device_fingerprint\": \"" << hwid << "\",\n";
  json_req << "  \"product_id\": \"" << product_id << "\",\n";
  json_req << "  \"client_version\": \"2.0.0\",\n";
  json_req << "  \"client_nonce\": \"" << BytesToHex(client_nonce.data(), client_nonce.size()) << "\"\n";
  json_req << "}\n";

  auto resp_body = DispatchHttpPost(server_url, "/activate", json_req.str(), error_out);
  if (!resp_body.has_value()) return std::nullopt;

  auto status = ExtractJsonField(*resp_body, "status");
  if (!status.has_value() || *status != "Valid") {
    auto err = ExtractJsonField(*resp_body, "error");
    if (error_out) *error_out = err.value_or("Activation rejected by server with status: " + status.value_or("unknown"));
    return std::nullopt;
  }

  auto s_nonce_hex = ExtractJsonField(*resp_body, "server_nonce");
  auto enc_token_hex = ExtractJsonField(*resp_body, "encrypted_token");
  if (!s_nonce_hex || !enc_token_hex) {
    if (error_out) *error_out = "Server response missing server_nonce or encrypted_token";
    return std::nullopt;
  }

  std::array<std::uint8_t, 32> server_nonce{};
  if (!HexToBytes(*s_nonce_hex, server_nonce.data(), server_nonce.size())) {
    if (error_out) *error_out = "Malformed server_nonce in response";
    return std::nullopt;
  }

  auto session_key = DeriveTransportKey(license_key, client_nonce, server_nonce);
  if (!session_key.has_value()) {
    if (error_out) *error_out = "Failed to derive transport decryption key";
    return std::nullopt;
  }

  std::vector<std::uint8_t> wire_enc(enc_token_hex->size() / 2);
  if (!HexToBytes(*enc_token_hex, wire_enc.data(), wire_enc.size())) {
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
  json_req << "  \"token\": \"" << token_hex << "\",\n";
  json_req << "  \"device_fingerprint\": \"" << hwid << "\",\n";
  json_req << "  \"client_nonce\": \"" << BytesToHex(client_nonce.data(), client_nonce.size()) << "\"\n";
  json_req << "}\n";

  auto resp_body = DispatchHttpPost(server_url, "/renew", json_req.str(), error_out);
  if (!resp_body.has_value()) return std::nullopt;

  auto status = ExtractJsonField(*resp_body, "status");
  if (!status.has_value() || *status != "Valid") {
    auto err = ExtractJsonField(*resp_body, "error");
    if (error_out) *error_out = err.value_or("Renewal rejected by server with status: " + status.value_or("unknown"));
    return std::nullopt;
  }

  auto s_nonce_hex = ExtractJsonField(*resp_body, "server_nonce");
  auto enc_token_hex = ExtractJsonField(*resp_body, "encrypted_token");
  if (!s_nonce_hex || !enc_token_hex) {
    if (error_out) *error_out = "Server renewal response missing server_nonce or encrypted_token";
    return std::nullopt;
  }

  std::array<std::uint8_t, 32> server_nonce{};
  if (!HexToBytes(*s_nonce_hex, server_nonce.data(), server_nonce.size())) {
    if (error_out) *error_out = "Malformed server_nonce in renewal response";
    return std::nullopt;
  }

  auto session_key = DeriveTransportKey(current_token.license_id, client_nonce, server_nonce);
  if (!session_key.has_value()) {
    if (error_out) *error_out = "Failed to derive transport decryption key";
    return std::nullopt;
  }

  std::vector<std::uint8_t> wire_enc(enc_token_hex->size() / 2);
  if (!HexToBytes(*enc_token_hex, wire_enc.data(), wire_enc.size())) {
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
  json_req << "  \"token\": \"" << token_hex << "\",\n";
  json_req << "  \"device_fingerprint\": \"" << hwid << "\"\n";
  json_req << "}\n";

  auto resp_body = DispatchHttpPost(server_url, "/deactivate", json_req.str(), error_out);
  if (!resp_body.has_value()) return false;

  auto succ = ExtractJsonField(*resp_body, "success");
  if (succ && *succ == "true") return true;

  auto err = ExtractJsonField(*resp_body, "error");
  if (error_out) *error_out = err.value_or("Deactivation rejected by server");
  return false;
}

}  // namespace rtprotect::licensing
