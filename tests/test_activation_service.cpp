// tests/test_activation_service.cpp
//
// End-to-end unit and network integration tests for the RTProtect Activation Authority:
// Database persistence, /activate, /renew, /deactivate endpoints, seat concurrency enforcement,
// anti-replay nonces, ephemeral transport encryption, and HTTP network round-trips.

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>

#include <winsock2.h>
#include <ws2tcpip.h>

#include <openssl/rand.h>

#include "crypto/aead.h"
#include "crypto/kdf.h"
#include "integrity/keys.h"
#include "integrity/sha256.h"
#include "licensing/activation.h"
#include "licensing/activation_client.h"
#include "licensing/activation_database.h"
#include "licensing/activation_server.h"
#include "licensing/activation_server_http.h"
#include "licensing/activation_service.h"
#include "licensing/abuse_analytics.h"
#include "licensing/hardware_id.h"
#include "tests/micro_test.h"
#include "tooling/file_io.h"

using namespace rtprotect::licensing;
using namespace rtprotect::integrity;

namespace {

Ed25519KeyPair MakeKeyPair() {
  auto kp = GenerateEd25519KeyPair();
  MT_CHECK(kp.has_value());
  return std::move(*kp);
}

std::string MakeTempDbPath() {
  auto now = std::chrono::system_clock::now().time_since_epoch();
  auto ts = std::chrono::duration_cast<std::chrono::microseconds>(now).count();
  return (std::filesystem::temp_directory_path() / ("test_activations_" + std::to_string(ts) + ".db")).string();
}

std::string SendRawHttpRequest(std::uint16_t port, const std::string& request) {
  SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock == INVALID_SOCKET) return "";

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

  if (connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    closesocket(sock);
    return "";
  }

  send(sock, request.data(), static_cast<int>(request.size()), 0);

  std::string response;
  char buf[4096];
  while (true) {
    int bytes = recv(sock, buf, sizeof(buf), 0);
    if (bytes <= 0) break;
    response.append(buf, bytes);
  }

  closesocket(sock);
  return response;
}

}  // namespace

MT_TEST(Database_LicenseAndActivationLifecycle) {
  std::string db_path = MakeTempDbPath();
  std::error_code ec;
  std::filesystem::remove(db_path, ec);

  {
    ActivationDatabase db(db_path);

    LicenseRecord lic;
    lic.license_id = "lic-ent-db-001";
    lic.product_id = "com.test.product";
    lic.status = LicenseRecordStatus::kActive;
    lic.max_seats = 2;
    lic.created_at = 1700000000;
    lic.vm_root.fill(0xAA);

    MT_CHECK(db.RegisterLicense(lic));
    MT_CHECK(db.Save());

    // Activation records
    ActivationRecord act1{"lic-ent-db-001", "HWID-DEVICE-1", 1700000000, 1700000100, 1};
    ActivationRecord act2{"lic-ent-db-001", "HWID-DEVICE-2", 1700000200, 1700000300, 1};

    MT_CHECK(db.RecordActivation(act1));
    MT_CHECK(db.RecordActivation(act2));
    MT_CHECK(db.GetActiveSeatCount("lic-ent-db-001") == 2);

    // Nonces
    MT_CHECK(db.RecordNonce("0123456789abcdef", 1700086400));
    MT_CHECK(db.IsNonceUsed("0123456789abcdef"));
    MT_CHECK(!db.IsNonceUsed("nonexistent"));

    MT_CHECK(db.Save());
  }

  // Reload database from disk into a fresh instance
  {
    ActivationDatabase fresh_db(db_path);
    auto lic_opt = fresh_db.GetLicense("lic-ent-db-001");
    MT_CHECK(lic_opt.has_value());
    MT_CHECK(lic_opt->product_id == "com.test.product");
    MT_CHECK(lic_opt->max_seats == 2);
    MT_CHECK(lic_opt->status == LicenseRecordStatus::kActive);
    std::array<std::uint8_t, 32> expected_root{};
    expected_root.fill(0xAA);
    MT_CHECK(lic_opt->vm_root == expected_root);

    MT_CHECK(fresh_db.GetActiveSeatCount("lic-ent-db-001") == 2);
    MT_CHECK(fresh_db.IsNonceUsed("0123456789abcdef"));

    // Remove activation
    MT_CHECK(fresh_db.RemoveActivation("lic-ent-db-001", "HWID-DEVICE-1"));
    MT_CHECK(fresh_db.GetActiveSeatCount("lic-ent-db-001") == 1);
  }

  std::filesystem::remove(db_path, ec);
}

MT_TEST(Service_Activate_SuccessAndEphemeralEncryption) {
  std::string db_path = MakeTempDbPath();
  std::error_code ec;
  std::filesystem::remove(db_path, ec);

  auto kp = MakeKeyPair();
  ActivationDatabase db(db_path);

  LicenseRecord lic;
  lic.license_id = "lic-ent-service-001";
  lic.product_id = "com.vendor.app";
  lic.max_seats = 3;
  lic.created_at = 1700000000;
  lic.vm_root.fill(0x55);
  MT_CHECK(db.RegisterLicense(lic));

  ActivationService service(db, std::move(kp.private_key), kp.public_key);

  ActivateRequest req;
  req.license_key = "lic-ent-service-001";
  req.device_fingerprint = "HWID-PROD-DEVICE-A";
  req.product_id = "com.vendor.app";
  req.client_version = "2.0.0";
  req.client_nonce.fill(0x11);

  auto resp = service.ProcessActivate(req, 1700001000);
  MT_CHECK(resp.status == ActivationStatus::kValid);
  MT_CHECK(resp.token.has_value());
  MT_CHECK(resp.token->license_id == req.license_key);
  MT_CHECK(resp.token->device_fingerprint_hash == req.device_fingerprint);
  MT_CHECK(resp.token->vm_root == lic.vm_root); // Critical: vm_root matches database!
  MT_CHECK(resp.token->sequence_number == 1);

  // Verify token signature against vendor public key
  MT_CHECK(VerifyActivationTokenSignature(*resp.token, kp.public_key));

  // Verify transport encryption payload
  MT_CHECK(!resp.encrypted_token_hex.empty());

  std::filesystem::remove(db_path, ec);
}

MT_TEST(Service_Activate_SeatLimitEnforcement) {
  std::string db_path = MakeTempDbPath();
  std::error_code ec;
  std::filesystem::remove(db_path, ec);

  auto kp = MakeKeyPair();
  ActivationDatabase db(db_path);

  LicenseRecord lic;
  lic.license_id = "lic-limited-seats";
  lic.product_id = "com.vendor.limited";
  lic.max_seats = 2; // Strict 2-seat cap
  lic.created_at = 1700000000;
  lic.vm_root.fill(0x77);
  MT_CHECK(db.RegisterLicense(lic));

  ActivationService service(db, std::move(kp.private_key), kp.public_key);

  ActivateRequest req1{"lic-limited-seats", "HWID-DEVICE-1", "com.vendor.limited", "1.0", 1700000000, {}};
  req1.client_nonce.fill(0x01);
  auto resp1 = service.ProcessActivate(req1, 1700000000);
  MT_CHECK(resp1.status == ActivationStatus::kValid);

  ActivateRequest req2{"lic-limited-seats", "HWID-DEVICE-2", "com.vendor.limited", "1.0", 1700000000, {}};
  req2.client_nonce.fill(0x02);
  auto resp2 = service.ProcessActivate(req2, 1700000000);
  MT_CHECK(resp2.status == ActivationStatus::kValid);

  // Third device must be rejected with concurrency limit exceeded
  ActivateRequest req3{"lic-limited-seats", "HWID-DEVICE-3", "com.vendor.limited", "1.0", 1700000000, {}};
  req3.client_nonce.fill(0x03);
  auto resp3 = service.ProcessActivate(req3, 1700000000);
  MT_CHECK(resp3.status == ActivationStatus::kConcurrencyLimitExceeded);

  // Deactivate device 1
  DeactivateRequest deact_req;
  auto tok1_bytes = SerializeActivationToken(*resp1.token);
  deact_req.token_hex = "";
  for (auto b : tok1_bytes) {
    char h[3];
    std::snprintf(h, sizeof(h), "%02x", b);
    deact_req.token_hex += h;
  }
  deact_req.device_fingerprint = "HWID-DEVICE-1";

  auto deact_resp = service.ProcessDeactivate(deact_req, 1700000500);
  MT_CHECK(deact_resp.success);

  // Now device 3 can activate and claim the freed seat
  ActivateRequest req3_retry = req3;
  req3_retry.client_nonce.fill(0x04);
  auto resp3_retry = service.ProcessActivate(req3_retry, 1700000600);
  MT_CHECK(resp3_retry.status == ActivationStatus::kValid);

  std::filesystem::remove(db_path, ec);
}

MT_TEST(Service_Renew_SuccessAndPreservesVmRoot) {
  std::string db_path = MakeTempDbPath();
  std::error_code ec;
  std::filesystem::remove(db_path, ec);

  auto kp = MakeKeyPair();
  ActivationDatabase db(db_path);

  LicenseRecord lic;
  lic.license_id = "lic-renew-test";
  lic.product_id = "com.vendor.renew";
  lic.max_seats = 1;
  lic.created_at = 1700000000;
  lic.vm_root.fill(0x88);
  MT_CHECK(db.RegisterLicense(lic));

  ActivationService service(db, std::move(kp.private_key), kp.public_key);

  ActivateRequest act_req{"lic-renew-test", "HWID-RENEW-DEVICE", "com.vendor.renew", "1.0", 1700000000, {}};
  act_req.client_nonce.fill(0x10);
  auto act_resp = service.ProcessActivate(act_req, 1700000000);
  MT_CHECK(act_resp.status == ActivationStatus::kValid);

  // Prepare renewal request
  RenewRequest renew_req;
  auto tok_bytes = SerializeActivationToken(*act_resp.token);
  for (auto b : tok_bytes) {
    char h[3];
    std::snprintf(h, sizeof(h), "%02x", b);
    renew_req.token_hex += h;
  }
  renew_req.device_fingerprint = "HWID-RENEW-DEVICE";
  renew_req.client_nonce.fill(0x20);

  auto renew_resp = service.ProcessRenew(renew_req, 1700005000);
  MT_CHECK(renew_resp.status == ActivationStatus::kValid);
  MT_CHECK(renew_resp.token.has_value());
  MT_CHECK(renew_resp.token->vm_root == lic.vm_root); // Critical: vm_root must stay identical!
  MT_CHECK(renew_resp.token->sequence_number == 2);
  MT_CHECK(renew_resp.token->expires_at > act_resp.token->expires_at);

  // Anti-replay: renewing again with the same old token must be rejected
  auto replay_resp = service.ProcessRenew(renew_req, 1700006000);
  MT_CHECK(replay_resp.status == ActivationStatus::kNonceMismatch);

  std::filesystem::remove(db_path, ec);
}

MT_TEST(Service_Renew_RejectsRevokedLicense) {
  std::string db_path = MakeTempDbPath();
  std::error_code ec;
  std::filesystem::remove(db_path, ec);

  auto kp = MakeKeyPair();
  ActivationDatabase db(db_path);

  LicenseRecord lic;
  lic.license_id = "lic-chargeback";
  lic.product_id = "com.vendor.app";
  lic.max_seats = 1;
  lic.created_at = 1700000000;
  lic.vm_root.fill(0x99);
  MT_CHECK(db.RegisterLicense(lic));

  ActivationService service(db, std::move(kp.private_key), kp.public_key);

  ActivateRequest act_req{"lic-chargeback", "HWID-DEVICE-XYZ", "com.vendor.app", "1.0", 1700000000, {}};
  act_req.client_nonce.fill(0x30);
  auto act_resp = service.ProcessActivate(act_req, 1700000000);
  MT_CHECK(act_resp.status == ActivationStatus::kValid);

  // Revoke license on the server
  MT_CHECK(db.UpdateLicenseStatus("lic-chargeback", LicenseRecordStatus::kRevoked));

  // Subsequent renewal must fail
  RenewRequest renew_req;
  auto tok_bytes = SerializeActivationToken(*act_resp.token);
  for (auto b : tok_bytes) {
    char h[3];
    std::snprintf(h, sizeof(h), "%02x", b);
    renew_req.token_hex += h;
  }
  renew_req.device_fingerprint = "HWID-DEVICE-XYZ";
  renew_req.client_nonce.fill(0x31);

  auto renew_resp = service.ProcessRenew(renew_req, 1700001000);
  MT_CHECK(renew_resp.status == ActivationStatus::kRevoked);

  std::filesystem::remove(db_path, ec);
}

MT_TEST(HttpServer_Loopback_ActivateAndRenew) {
  std::string db_path = MakeTempDbPath();
  std::error_code ec;
  std::filesystem::remove(db_path, ec);

  auto kp = MakeKeyPair();
  ActivationDatabase db(db_path);

  LicenseRecord lic;
  lic.license_id = "lic-http-net-001";
  lic.product_id = "com.vendor.netapp";
  lic.max_seats = 2;
  lic.created_at = 1700000000;
  lic.vm_root.fill(0x3E);
  MT_CHECK(db.RegisterLicense(lic));

  ActivationService service(db, std::move(kp.private_key), kp.public_key);
  ActivationServerHttp server(service);

  // Start HTTP server on ephemeral dynamic port (port 0)
  MT_CHECK(server.Start(0, "127.0.0.1"));
  MT_CHECK(server.is_running());
  MT_CHECK(server.port() > 0);

  std::string server_url = server.base_url();

  // 1. Client calls RequestOnlineActivation over HTTP network
  std::string err;
  auto token_opt = RequestOnlineActivation(server_url, "lic-http-net-001", "com.vendor.netapp", kp.public_key, &err);
  MT_CHECK(token_opt.has_value());
  MT_CHECK(token_opt->license_id == "lic-http-net-001");
  MT_CHECK(token_opt->vm_root == lic.vm_root); // Critical: Network round-trip returned matching vm_root!

  // 2. Client calls RequestOnlineRenewal over HTTP network
  auto renewed_opt = RequestOnlineRenewal(server_url, *token_opt, kp.public_key, &err);
  MT_CHECK(renewed_opt.has_value());
  MT_CHECK(renewed_opt->vm_root == lic.vm_root);
  MT_CHECK(renewed_opt->sequence_number == 2);

  // 3. Client calls RequestOnlineDeactivation over HTTP network
  MT_CHECK(RequestOnlineDeactivation(server_url, *renewed_opt, &err));

  server.Stop();
  MT_CHECK(!server.is_running());

  std::filesystem::remove(db_path, ec);
}

MT_TEST(HttpServer_PayloadTooLarge_Rejected) {
  std::string db_path = MakeTempDbPath();
  std::error_code ec;
  std::filesystem::remove(db_path, ec);

  auto kp = MakeKeyPair();
  ActivationDatabase db(db_path);
  ActivationService service(db, std::move(kp.private_key), kp.public_key);
  ActivationServerHttp server(service);

  MT_CHECK(server.Start(0, "127.0.0.1"));
  std::string server_url = server.base_url();

  // Send an oversized payload > 64KB
  std::string huge_body(70000, 'X');
  std::string err;
  auto res = RequestOnlineActivation(server_url, huge_body, "com.vendor.app", kp.public_key, &err);
  // Must fail closed due to HTTP 413 Payload Too Large
  MT_CHECK(!res.has_value());

  server.Stop();
  std::filesystem::remove(db_path, ec);
}

MT_TEST(HttpServer_ConcurrentClients_NonBlocking) {
  std::string db_path = MakeTempDbPath();
  std::error_code ec;
  std::filesystem::remove(db_path, ec);

  auto kp = MakeKeyPair();
  ActivationDatabase db(db_path);

  // Register 10 distinct licenses
  for (int i = 0; i < 10; ++i) {
    LicenseRecord lic;
    lic.license_id = "lic-concur-" + std::to_string(i);
    lic.product_id = "com.vendor.concurapp";
    lic.max_seats = 5;
    lic.created_at = 1700000000;
    lic.vm_root.fill(static_cast<std::uint8_t>(i + 1));
    MT_CHECK(db.RegisterLicense(lic));
  }

  ActivationService service(db, std::move(kp.private_key), kp.public_key);
  ActivationServerHttp server(service);
  MT_CHECK(server.Start(0, "127.0.0.1"));
  std::string server_url = server.base_url();

  std::vector<std::thread> workers;
  std::atomic<int> success_count{0};

  for (int i = 0; i < 10; ++i) {
    workers.emplace_back([i, &server_url, &kp, &success_count]() {
      std::string err;
      std::string lic_id = "lic-concur-" + std::to_string(i);
      auto tok = RequestOnlineActivation(server_url, lic_id, "com.vendor.concurapp", kp.public_key, &err);
      if (tok.has_value() && tok->license_id == lic_id) {
        success_count++;
      }
    });
  }

  for (auto& w : workers) {
    if (w.joinable()) w.join();
  }

  MT_CHECK(success_count.load() == 10);

  server.Stop();
  std::filesystem::remove(db_path, ec);
}

MT_TEST(HttpServer_HostValidation_EnforcesTlsAndLoopbackSafety) {
  std::string db_path = MakeTempDbPath();
  std::error_code ec;
  std::filesystem::remove(db_path, ec);

  auto kp = MakeKeyPair();
  ActivationDatabase db(db_path);
  ActivationService service(db, std::move(kp.private_key), kp.public_key);
  ActivationServerHttp server(service);

  // 1. Must refuse to start unencrypted HTTP on non-loopback addresses by default
  MT_CHECK(!server.Start(0, "0.0.0.0"));
  MT_CHECK(!server.Start(0, "192.168.1.1"));

  // 2. Must refuse invalid or unresolvable hostnames (never defaults to 0.0.0.0)
  MT_CHECK(!server.Start(0, "invalid-host-no-ip"));

  // 3. Must successfully bind to localhost (resolved internally to 127.0.0.1)
  MT_CHECK(server.Start(0, "localhost"));
  MT_CHECK(server.is_running());
  MT_CHECK(server.port() > 0);
  server.Stop();

  // 4. Must successfully bind to 127.0.0.1
  MT_CHECK(server.Start(0, "127.0.0.1"));
  MT_CHECK(server.is_running());
  server.Stop();

  // 5. Insecure dev mode explicitly permits non-loopback binding if enabled
  server.SetAllowInsecureNonLoopback(true);
  // (0.0.0.0 is allowed only when insecure dev mode is explicitly granted)
  MT_CHECK(server.Start(0, "127.0.0.1"));
  server.Stop();

  std::filesystem::remove(db_path, ec);
}

MT_TEST(HttpClient_RejectsInsecureNonLoopbackHttp) {
  auto kp = MakeKeyPair();
  std::string err;

  // Plain HTTP connection to non-loopback host must be rejected by client
  auto tok = RequestOnlineActivation("http://192.168.1.100:8080", "lic-test", "prod-test", kp.public_key, &err);
  MT_CHECK(!tok.has_value());
  MT_CHECK(err.find("insecure plain HTTP") != std::string::npos);
}

MT_TEST(Service_ReplayProtection_StrictNonceEnforcement) {
  std::string db_path = MakeTempDbPath();
  std::error_code ec;
  std::filesystem::remove(db_path, ec);

  auto kp = MakeKeyPair();
  ActivationDatabase db(db_path);

  LicenseRecord lic;
  lic.license_id = "lic-nonce-strict";
  lic.product_id = "com.vendor.nonce";
  lic.max_seats = 1;
  lic.created_at = 1700000000;
  lic.vm_root.fill(0x55);
  MT_CHECK(db.RegisterLicense(lic));

  ActivationService service(db, std::move(kp.private_key), kp.public_key);

  // 1. All-zero client nonce must be rejected
  ActivateRequest req_zero{"lic-nonce-strict", "HWID-1", "com.vendor.nonce", "1.0", 1700000000, {}};
  req_zero.client_nonce.fill(0x00);
  auto resp_zero = service.ProcessActivate(req_zero, 1700000000);
  MT_CHECK(resp_zero.status == ActivationStatus::kMalformed);

  // 2. Valid nonce succeeds
  ActivateRequest req_valid = req_zero;
  req_valid.client_nonce.fill(0x42);
  auto resp_valid = service.ProcessActivate(req_valid, 1700000000);
  MT_CHECK(resp_valid.status == ActivationStatus::kValid);

  // 3. Exact replay of the same nonce must be atomically rejected
  auto resp_replay = service.ProcessActivate(req_valid, 1700000001);
  MT_CHECK(resp_replay.status == ActivationStatus::kNonceMismatch);

  std::filesystem::remove(db_path, ec);
}

MT_TEST(Service_Renew_RejectsExpiredTokenPastGrace) {
  std::string db_path = MakeTempDbPath();
  std::error_code ec;
  std::filesystem::remove(db_path, ec);

  auto kp = MakeKeyPair();
  ActivationDatabase db(db_path);

  LicenseRecord lic;
  lic.license_id = "lic-renew-grace";
  lic.product_id = "com.vendor.grace";
  lic.max_seats = 1;
  lic.created_at = 1700000000;
  lic.vm_root.fill(0x99);
  MT_CHECK(db.RegisterLicense(lic));

  ActivationService service(db, std::move(kp.private_key), kp.public_key);

  ActivateRequest req{"lic-renew-grace", "HWID-DEV-1", "com.vendor.grace", "1.0", 1700000000, {}};
  req.client_nonce.fill(0x11);
  auto resp = service.ProcessActivate(req, 1700000000);
  MT_CHECK(resp.status == ActivationStatus::kValid);
  MT_CHECK(resp.token.has_value());

  RenewRequest renew_req;
  auto tok_bytes = SerializeActivationToken(*resp.token);
  for (auto b : tok_bytes) {
    char h[3];
    std::snprintf(h, sizeof(h), "%02x", b);
    renew_req.token_hex += h;
  }
  renew_req.device_fingerprint = "HWID-DEV-1";
  renew_req.client_nonce.fill(0x22);

  // Attempt renewal at a timestamp beyond grace_expires_at (14d + 3d + 1s = 17d + 1s)
  std::uint64_t expired_time = resp.token->grace_expires_at + 100;
  auto renew_resp = service.ProcessRenew(renew_req, expired_time);
  MT_CHECK(renew_resp.status == ActivationStatus::kExpired);
  MT_CHECK(renew_resp.error_message.find("expired past its grace period") != std::string::npos);

  std::filesystem::remove(db_path, ec);
}

MT_TEST(Database_FailClosed_RejectsCorruptedStatus) {
  std::string db_path = MakeTempDbPath();
  std::error_code ec;
  std::filesystem::remove(db_path, ec);

  // Write database containing corrupted / unknown status
  std::string bad_db =
      "# Database with unknown status\n"
      "[licenses]\n"
      "lic-corrupted|prod-x|bogus_unknown_status|1|0000000000000000000000000000000000000000000000000000000000000000|1700000000\n"
      "lic-legit|prod-x|active|1|0000000000000000000000000000000000000000000000000000000000000000|1700000000\n";
  rtprotect::tooling::WriteFile(db_path, reinterpret_cast<const std::uint8_t*>(bad_db.data()), bad_db.size());

  ActivationDatabase db(db_path);

  // Malformed status must NOT be loaded or defaulted to kActive
  MT_CHECK(!db.GetLicense("lic-corrupted").has_value());

  // Legitimate active status must be loaded correctly
  auto legit = db.GetLicense("lic-legit");
  MT_CHECK(legit.has_value());
  MT_CHECK(legit->status == LicenseRecordStatus::kActive);

  std::filesystem::remove(db_path, ec);
}

MT_TEST(Service_RateLimiting_PerLicenseThrottling) {
  std::string db_path = MakeTempDbPath();
  std::error_code ec;
  std::filesystem::remove(db_path, ec);

  auto kp = MakeKeyPair();
  ActivationDatabase db(db_path);

  LicenseRecord lic;
  lic.license_id = "lic-ratelimit";
  lic.product_id = "com.vendor.ratelimit";
  lic.max_seats = 50;
  lic.created_at = 1700000000;
  lic.vm_root.fill(0x33);
  MT_CHECK(db.RegisterLicense(lic));

  ActivationService service(db, std::move(kp.private_key), kp.public_key);

  // Configure a strict license rate limiter for testing: burst 3, 0.1 tokens/sec
  service.license_rate_limiter().Configure(0.1, 3.0);

  int allowed = 0;
  int rejected = 0;

  for (int i = 0; i < 6; ++i) {
    ActivateRequest req{"lic-ratelimit", "HWID-" + std::to_string(i), "com.vendor.ratelimit", "1.0", 1700000000, {}};
    req.client_nonce[0] = static_cast<std::uint8_t>(i + 1);
    auto resp = service.ProcessActivate(req, 1700000000);
    if (resp.status == ActivationStatus::kValid) {
      allowed++;
    } else if (resp.status == ActivationStatus::kConcurrencyLimitExceeded &&
               resp.error_message.find("Rate limit exceeded") != std::string::npos) {
      rejected++;
    }
  }

  MT_CHECK(allowed == 3);
  MT_CHECK(rejected == 3);

  std::filesystem::remove(db_path, ec);
}

MT_TEST(Service_AuditEvents_And_SeatChurnRisk) {
  std::string db_path = MakeTempDbPath();
  std::error_code ec;
  std::filesystem::remove(db_path, ec);

  auto kp = MakeKeyPair();
  ActivationDatabase db(db_path);

  LicenseRecord lic;
  lic.license_id = "lic-churn-test";
  lic.product_id = "com.vendor.churn";
  lic.max_seats = 2;
  lic.created_at = 1700000000;
  lic.vm_root.fill(0x77);
  MT_CHECK(db.RegisterLicense(lic));

  ActivationService service(db, std::move(kp.private_key), kp.public_key);

  // 1. Initial risk should be 0.0
  MT_CHECK(service.ComputeSeatChurnRisk("lic-churn-test", 1700000000) == 0.0);

  // 2. Normal activations for 2 seats (within max_seats)
  ActivateRequest req1{"lic-churn-test", "HWID-A", "com.vendor.churn", "1.0", 1700000000, {}};
  req1.client_nonce[0] = 0x01;
  auto resp1 = service.ProcessActivate(req1, 1700000000);
  MT_CHECK(resp1.status == ActivationStatus::kValid);

  ActivateRequest req2{"lic-churn-test", "HWID-B", "com.vendor.churn", "1.0", 1700000000, {}};
  req2.client_nonce[0] = 0x02;
  auto resp2 = service.ProcessActivate(req2, 1700000000);
  MT_CHECK(resp2.status == ActivationStatus::kValid);

  // Still clean risk (2 devices / 2 seats = ratio 1.0)
  MT_CHECK(service.ComputeSeatChurnRisk("lic-churn-test", 1700000000) == 0.0);

  // 3. Third device attempt fails with concurrency limit -> generates seat limit event
  ActivateRequest req3{"lic-churn-test", "HWID-C", "com.vendor.churn", "1.0", 1700000000, {}};
  req3.client_nonce[0] = 0x03;
  auto resp3 = service.ProcessActivate(req3, 1700000000);
  MT_CHECK(resp3.status == ActivationStatus::kConcurrencyLimitExceeded);

  // Distinct devices is now 3 (A, B, C) and an abuse event was logged
  double churn_risk = service.ComputeSeatChurnRisk("lic-churn-test", 1700000000);
  MT_CHECK(churn_risk > 0.0);

  // 4. Verify structured events are recorded
  auto events = service.GetRecentEvents("lic-churn-test");
  MT_CHECK(events.size() == 3);
  MT_CHECK(events[0].type == ActivationEventType::kSeatLimitExceeded); // Most recent first
  MT_CHECK(events[1].type == ActivationEventType::kActivationSuccess);
  MT_CHECK(events[2].type == ActivationEventType::kActivationSuccess);

  std::filesystem::remove(db_path, ec);
}

MT_TEST(Service_RateLimiting_HandleActivateJson_PerIpAndLicense) {
  std::string db_path = MakeTempDbPath();
  std::error_code ec;
  std::filesystem::remove(db_path, ec);

  auto kp = MakeKeyPair();
  ActivationDatabase db(db_path);

  LicenseRecord lic;
  lic.license_id = "lic-json-ratelimit";
  lic.product_id = "com.vendor.jsonrate";
  lic.max_seats = 10;
  lic.created_at = 1700000000;
  lic.vm_root.fill(0x55);
  MT_CHECK(db.RegisterLicense(lic));

  ActivationService service(db, std::move(kp.private_key), kp.public_key);

  // Configure IP rate limiter to burst 2, 0.1 tokens/sec
  service.ip_rate_limiter().Configure(0.1, 2.0);

  std::string body1 = "{\n"
                      "  \"license_key\": \"lic-json-ratelimit\",\n"
                      "  \"device_fingerprint\": \"DEV-1\",\n"
                      "  \"product_id\": \"com.vendor.jsonrate\",\n"
                      "  \"client_nonce\": \"0101010101010101010101010101010101010101010101010101010101010101\"\n"
                      "}";

  // Request 1 from 192.168.1.100 -> OK
  auto resp1 = service.HandleActivateJson(body1, 1700000000, "192.168.1.100");
  MT_CHECK(resp1.find("\"status\": \"Valid\"") != std::string::npos);

  // Request 2 from 192.168.1.100 (new nonce) -> OK
  std::string body2 = "{\n"
                      "  \"license_key\": \"lic-json-ratelimit\",\n"
                      "  \"device_fingerprint\": \"DEV-1\",\n"
                      "  \"product_id\": \"com.vendor.jsonrate\",\n"
                      "  \"client_nonce\": \"0202020202020202020202020202020202020202020202020202020202020202\"\n"
                      "}";
  auto resp2 = service.HandleActivateJson(body2, 1700000000, "192.168.1.100");
  MT_CHECK(resp2.find("\"status\": \"Valid\"") != std::string::npos);

  // Request 3 from 192.168.1.100 -> Rate limited by IP
  std::string body3 = "{\n"
                      "  \"license_key\": \"lic-json-ratelimit\",\n"
                      "  \"device_fingerprint\": \"DEV-1\",\n"
                      "  \"product_id\": \"com.vendor.jsonrate\",\n"
                      "  \"client_nonce\": \"0303030303030303030303030303030303030303030303030303030303030303\"\n"
                      "}";
  auto resp3 = service.HandleActivateJson(body3, 1700000000, "192.168.1.100");
  MT_CHECK(resp3.find("\"status\": \"rate_limited\"") != std::string::npos);
  MT_CHECK(resp3.find("\"retry_after\":") != std::string::npos);

  // Now test License rate limiting: request from DIFFERENT IP (192.168.1.200), configure license rate limiter to burst 1
  service.license_rate_limiter().Configure(0.1, 1.0);
  auto resp_lic1 = service.HandleActivateJson(body3, 1700000000, "192.168.1.200");
  MT_CHECK(resp_lic1.find("\"status\": \"Valid\"") != std::string::npos);

  std::string body4 = "{\n"
                      "  \"license_key\": \"lic-json-ratelimit\",\n"
                      "  \"device_fingerprint\": \"DEV-1\",\n"
                      "  \"product_id\": \"com.vendor.jsonrate\",\n"
                      "  \"client_nonce\": \"0404040404040404040404040404040404040404040404040404040404040404\"\n"
                      "}";
  auto resp_lic2 = service.HandleActivateJson(body4, 1700000000, "192.168.1.200");
  MT_CHECK(resp_lic2.find("\"status\": \"rate_limited\"") != std::string::npos);
  MT_CHECK(resp_lic2.find("Rate limit exceeded for license key") != std::string::npos);

  std::filesystem::remove(db_path, ec);
}

MT_TEST(HttpServer_Events_AdminAuthRequired) {
  std::string db_path = MakeTempDbPath();
  std::error_code ec;
  std::filesystem::remove(db_path, ec);

  auto kp = MakeKeyPair();
  ActivationDatabase db(db_path);
  ActivationService service(db, std::move(kp.private_key), kp.public_key);
  ActivationServerHttp server(service);

  server.SetAdminAuthToken("super-secret-token-test-12345");
  MT_CHECK(server.Start(0, "127.0.0.1"));
  std::uint16_t port = server.port();

  // 1. GET /events without auth header -> 401 Unauthorized
  std::string req_no_auth = "GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
  std::string resp_no_auth = SendRawHttpRequest(port, req_no_auth);
  MT_CHECK(resp_no_auth.find("HTTP/1.1 401 Unauthorized") != std::string::npos);
  MT_CHECK(resp_no_auth.find("WWW-Authenticate: Bearer") != std::string::npos);

  // 2. GET /events with invalid X-Admin-Key -> 401 Unauthorized
  std::string req_bad_key = "GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Admin-Key: invalid-key\r\nConnection: close\r\n\r\n";
  std::string resp_bad_key = SendRawHttpRequest(port, req_bad_key);
  MT_CHECK(resp_bad_key.find("HTTP/1.1 401 Unauthorized") != std::string::npos);

  // 3. GET /events with valid X-Admin-Key -> 200 OK
  std::string req_good_key = "GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Admin-Key: super-secret-token-test-12345\r\nConnection: close\r\n\r\n";
  std::string resp_good_key = SendRawHttpRequest(port, req_good_key);
  MT_CHECK(resp_good_key.find("HTTP/1.1 200 OK") != std::string::npos);
  MT_CHECK(resp_good_key.find("\"events\":") != std::string::npos);

  // 4. GET /events with valid Authorization: Bearer -> 200 OK
  std::string req_bearer = "GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer super-secret-token-test-12345\r\nConnection: close\r\n\r\n";
  std::string resp_bearer = SendRawHttpRequest(port, req_bearer);
  MT_CHECK(resp_bearer.find("HTTP/1.1 200 OK") != std::string::npos);
  MT_CHECK(resp_bearer.find("\"events\":") != std::string::npos);

  server.Stop();
  std::filesystem::remove(db_path, ec);
}

MT_TEST(HttpServer_RateLimiting_ReturnsHttp429) {
  std::string db_path = MakeTempDbPath();
  std::error_code ec;
  std::filesystem::remove(db_path, ec);

  auto kp = MakeKeyPair();
  ActivationDatabase db(db_path);

  LicenseRecord lic;
  lic.license_id = "lic-http-429";
  lic.product_id = "com.vendor.http429";
  lic.max_seats = 10;
  lic.created_at = 1700000000;
  lic.vm_root.fill(0x66);
  MT_CHECK(db.RegisterLicense(lic));

  ActivationService service(db, std::move(kp.private_key), kp.public_key);
  ActivationServerHttp server(service);

  // Strict limiter: burst 1 token
  service.license_rate_limiter().Configure(0.1, 1.0);

  MT_CHECK(server.Start(0, "127.0.0.1"));
  std::uint16_t port = server.port();

  std::string body1 = "{\"license_key\":\"lic-http-429\",\"device_fingerprint\":\"D1\",\"product_id\":\"com.vendor.http429\",\"client_nonce\":\"0101010101010101010101010101010101010101010101010101010101010101\"}";
  std::string req1 = "POST /activate HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: " + std::to_string(body1.size()) + "\r\nConnection: close\r\n\r\n" + body1;
  std::string resp1 = SendRawHttpRequest(port, req1);
  MT_CHECK(resp1.find("HTTP/1.1 200 OK") != std::string::npos);

  std::string body2 = "{\"license_key\":\"lic-http-429\",\"device_fingerprint\":\"D1\",\"product_id\":\"com.vendor.http429\",\"client_nonce\":\"0202020202020202020202020202020202020202020202020202020202020202\"}";
  std::string req2 = "POST /activate HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: " + std::to_string(body2.size()) + "\r\nConnection: close\r\n\r\n" + body2;
  std::string resp2 = SendRawHttpRequest(port, req2);
  MT_CHECK(resp2.find("HTTP/1.1 429 Too Many Requests") != std::string::npos);
  MT_CHECK(resp2.find("Retry-After:") != std::string::npos);
  MT_CHECK(resp2.find("\"status\": \"rate_limited\"") != std::string::npos);

  server.Stop();
  std::filesystem::remove(db_path, ec);
}

MT_TEST(Database_EventsAndNonces_RestoredAfterRestart) {
  std::string db_path = MakeTempDbPath();
  std::error_code ec;
  std::filesystem::remove(db_path, ec);

  std::uint64_t now = 1700000000;
  {
    ActivationDatabase db(db_path);
    LicenseRecord lic;
    lic.license_id = "lic-restart-test";
    lic.product_id = "prod.test";
    lic.max_seats = 5;
    lic.status = LicenseRecordStatus::kActive;
    MT_CHECK(db.RegisterLicense(lic));

    // Record nonces
    MT_CHECK(db.ConsumeNonceIfUnused("nonce-restart-01", now + 3600, now));
    MT_CHECK(db.ConsumeNonceIfUnused("nonce-restart-02", now + 7200, now));

    // Record audit events
    MT_CHECK(db.RecordEvent({now, ActivationEventType::kActivationSuccess, "lic-restart-test", "HWID-1", "127.0.0.1", "Seat 1 activated"}));
    MT_CHECK(db.RecordEvent({now + 10, ActivationEventType::kRenewalSuccess, "lic-restart-test", "HWID-1", "127.0.0.1", "Seat 1 renewed"}));
    MT_CHECK(db.RecordEvent({now + 20, ActivationEventType::kDeactivation, "lic-restart-test", "HWID-1", "127.0.0.1", "Seat 1 deactivated"}));
    MT_CHECK(db.RecordEvent({now + 30, ActivationEventType::kReplayBlocked, "lic-restart-test", "HWID-1", "127.0.0.1", "Replay blocked"}));

    MT_CHECK(db.Save());
  }

  // Re-open fresh database instance from the same file
  {
    ActivationDatabase db2(db_path);
    auto lic_opt = db2.GetLicense("lic-restart-test");
    MT_CHECK(lic_opt.has_value());
    MT_CHECK(lic_opt->license_id == "lic-restart-test");

    // Nonces must still be marked as used
    MT_CHECK(db2.IsNonceUsed("nonce-restart-01"));
    MT_CHECK(db2.IsNonceUsed("nonce-restart-02"));
    MT_CHECK(!db2.ConsumeNonceIfUnused("nonce-restart-01", now + 3600, now));

    // Audit events must be completely restored
    auto events = db2.GetRecentEvents("lic-restart-test", 10);
    MT_CHECK(events.size() == 4);
    MT_CHECK(events[0].details == "Replay blocked");
    MT_CHECK(events[1].details == "Seat 1 deactivated");
    MT_CHECK(events[2].details == "Seat 1 renewed");
    MT_CHECK(events[3].details == "Seat 1 activated");

    // Seat churn risk must compute identically
    double risk = db2.ComputeSeatChurnRisk("lic-restart-test", now + 100);
    MT_CHECK(risk > 0.0);
  }

  std::filesystem::remove(db_path, ec);
}

MT_TEST(HttpServer_FramingSecurity_RejectsMalformedAndChunked) {
  std::string db_path = MakeTempDbPath();
  std::error_code ec;
  std::filesystem::remove(db_path, ec);

  auto kp = MakeKeyPair();
  ActivationDatabase db(db_path);
  ActivationService service(db, std::move(kp.private_key), kp.public_key);
  ActivationServerHttp server(service);

  MT_CHECK(server.Start(0, "127.0.0.1"));
  std::uint16_t port = server.port();

  // 1. Transfer-Encoding: chunked -> 501 Not Implemented
  std::string te_req = "POST /activate HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n";
  std::string te_resp = SendRawHttpRequest(port, te_req);
  MT_CHECK(te_resp.find("HTTP/1.1 501 Not Implemented") != std::string::npos);

  // 2. Duplicate Content-Length headers -> 400 Bad Request
  std::string dup_cl_req = "POST /activate HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 10\r\nContent-Length: 20\r\nConnection: close\r\n\r\n1234567890";
  std::string dup_cl_resp = SendRawHttpRequest(port, dup_cl_req);
  MT_CHECK(dup_cl_resp.find("HTTP/1.1 400 Bad Request") != std::string::npos);
  MT_CHECK(dup_cl_resp.find("Multiple Content-Length") != std::string::npos);

  // 3. Invalid non-numeric Content-Length -> 400 Bad Request
  std::string bad_cl_req = "POST /activate HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: abc\r\nConnection: close\r\n\r\n1234567890";
  std::string bad_cl_resp = SendRawHttpRequest(port, bad_cl_req);
  MT_CHECK(bad_cl_resp.find("HTTP/1.1 400 Bad Request") != std::string::npos);

  server.Stop();
  std::filesystem::remove(db_path, ec);
}

MT_TEST(SecurityAudit_ThreeDistinctKeysSeparation) {
  std::string db_path = MakeTempDbPath();
  std::error_code ec;
  std::filesystem::remove(db_path, ec);

  auto man_kp = MakeKeyPair(); // Key 1: Manifest signing
  auto lic_kp = MakeKeyPair(); // Key 2: License signing
  auto act_kp = MakeKeyPair(); // Key 3: Activation signing

  ActivationDatabase db(db_path);
  LicenseRecord lic;
  lic.license_id = "lic-3key-separation";
  lic.product_id = "com.vendor.keys";
  lic.max_seats = 2;
  lic.created_at = 1700000000;
  lic.vm_root.fill(0x77);
  MT_CHECK(db.RegisterLicense(lic));

  // Server initialized strictly with activation signing key
  ActivationService service(db, std::move(act_kp.private_key), act_kp.public_key);
  ActivationServerHttp server(service);
  MT_CHECK(server.Start(0, "127.0.0.1"));
  std::string server_url = server.base_url();

  // 1. Verifying against manifest key MUST FAIL
  std::string err;
  auto tok_wrong_man = RequestOnlineActivation(server_url, "lic-3key-separation", "com.vendor.keys", man_kp.public_key, &err);
  MT_CHECK(!tok_wrong_man.has_value());
  MT_CHECK(err.find("failed verification") != std::string::npos);

  // 2. Verifying against license key MUST FAIL
  auto tok_wrong_lic = RequestOnlineActivation(server_url, "lic-3key-separation", "com.vendor.keys", lic_kp.public_key, &err);
  MT_CHECK(!tok_wrong_lic.has_value());
  MT_CHECK(err.find("failed verification") != std::string::npos);

  // 3. Verifying against dedicated activation key MUST SUCCEED
  auto tok_valid = RequestOnlineActivation(server_url, "lic-3key-separation", "com.vendor.keys", act_kp.public_key, &err);
  MT_CHECK(tok_valid.has_value());
  MT_CHECK(tok_valid->license_id == "lic-3key-separation");
  MT_CHECK(tok_valid->vm_root == lic.vm_root);

  server.Stop();
  std::filesystem::remove(db_path, ec);
}

MT_TEST(SecurityAudit_ActivationCredential_RequiredAndEnforced) {
  std::string db_path = MakeTempDbPath();
  std::error_code ec;
  std::filesystem::remove(db_path, ec);

  auto act_kp = MakeKeyPair();
  ActivationDatabase db(db_path);

  LicenseRecord lic;
  lic.license_id = "lic-cred-auth-001";
  lic.product_id = "com.vendor.secured";
  lic.max_seats = 1;
  lic.created_at = 1700000000;
  lic.vm_root.fill(0x55);

  std::string secret = "SuperSecretActivationPassword#2026";
  auto cred_hash = rtprotect::integrity::Sha256(reinterpret_cast<const std::uint8_t*>(secret.data()), secret.size());
  MT_CHECK(cred_hash.has_value());
  lic.activation_credential_hash = "";
  for (auto b : *cred_hash) {
    char h[3];
    std::snprintf(h, sizeof(h), "%02x", b);
    lic.activation_credential_hash += h;
  }
  MT_CHECK(db.RegisterLicense(lic));

  ActivationService service(db, std::move(act_kp.private_key), act_kp.public_key);
  ActivationServerHttp server(service);
  MT_CHECK(server.Start(0, "127.0.0.1"));
  std::string server_url = server.base_url();

  // 1. Activation with wrong credential fails authentication
  std::string err;
  auto tok_bad = RequestOnlineActivation(server_url, "lic-cred-auth-001", "com.vendor.secured", act_kp.public_key, &err, "WrongPassword");
  MT_CHECK(!tok_bad.has_value());

  // 2. Activation with missing credential fails authentication
  auto tok_empty = RequestOnlineActivation(server_url, "lic-cred-auth-001", "com.vendor.secured", act_kp.public_key, &err, "");
  MT_CHECK(!tok_empty.has_value());

  // 3. Activation with correct credential succeeds
  auto tok_good = RequestOnlineActivation(server_url, "lic-cred-auth-001", "com.vendor.secured", act_kp.public_key, &err, secret);
  MT_CHECK(tok_good.has_value());
  MT_CHECK(tok_good->license_id == "lic-cred-auth-001");
  MT_CHECK(tok_good->vm_root == lic.vm_root);

  server.Stop();
  std::filesystem::remove(db_path, ec);
}

MT_TEST(SecurityAudit_SeatPreservation_OnFailedActivation) {
  std::string db_path = MakeTempDbPath();
  std::error_code ec;
  std::filesystem::remove(db_path, ec);

  auto act_kp = MakeKeyPair();
  ActivationDatabase db(db_path);

  LicenseRecord lic;
  lic.license_id = "lic-preserve-seat";
  lic.product_id = "com.vendor.preserve";
  lic.max_seats = 1;
  lic.created_at = 1700000000;
  lic.vm_root.fill(0x33);
  MT_CHECK(db.RegisterLicense(lic));

  ActivationService service(db, std::move(act_kp.private_key), act_kp.public_key);

  // 1. Device 1 successfully activates
  ActivateRequest req1{"lic-preserve-seat", "HWID-EXISTING-DEVICE", "com.vendor.preserve", "1.0", 1700000000, {}};
  req1.client_nonce.fill(0x01);
  auto resp1 = service.ProcessActivate(req1, 1700000000);
  MT_CHECK(resp1.status == ActivationStatus::kValid);
  MT_CHECK(resp1.token.has_value());
  std::uint64_t initial_seq = resp1.token->sequence_number;

  // Verify seat exists in DB
  auto act_rec = db.GetActivation("lic-preserve-seat", "HWID-EXISTING-DEVICE");
  MT_CHECK(act_rec.has_value());
  MT_CHECK(act_rec->sequence_number == initial_seq);

  // 2. Existing seat submits a failing activation attempt (duplicate nonce triggers replay rejection)
  ActivateRequest req_replay = req1; // Re-uses exact same nonce 0x01
  auto resp_replay = service.ProcessActivate(req_replay, 1700000010);
  MT_CHECK(resp_replay.status == ActivationStatus::kNonceMismatch);

  // 3. Critically: The existing seat MUST NOT be deleted or corrupted!
  auto act_rec_after = db.GetActivation("lic-preserve-seat", "HWID-EXISTING-DEVICE");
  MT_CHECK(act_rec_after.has_value());
  MT_CHECK(act_rec_after->sequence_number == initial_seq);
  MT_CHECK(act_rec_after->device_fingerprint == "HWID-EXISTING-DEVICE");

  std::filesystem::remove(db_path, ec);
}

MT_TEST(SecurityAudit_StaleSequenceRejection_RenewAndDeactivate) {
  std::string db_path = MakeTempDbPath();
  std::error_code ec;
  std::filesystem::remove(db_path, ec);

  auto act_kp = MakeKeyPair();
  ActivationDatabase db(db_path);

  LicenseRecord lic;
  lic.license_id = "lic-seq-audit";
  lic.product_id = "com.vendor.seq";
  lic.max_seats = 1;
  lic.created_at = 1700000000;
  lic.vm_root.fill(0x12);
  MT_CHECK(db.RegisterLicense(lic));

  ActivationService service(db, std::move(act_kp.private_key), act_kp.public_key);

  // 1. Activate initial token (sequence 1)
  ActivateRequest act_req{"lic-seq-audit", "HWID-SEQ-DEVICE", "com.vendor.seq", "1.0", 1700000000, {}};
  act_req.client_nonce.fill(0x10);
  auto act_resp = service.ProcessActivate(act_req, 1700000000);
  MT_CHECK(act_resp.status == ActivationStatus::kValid);
  MT_CHECK(act_resp.token->sequence_number == 1);
  ActivationToken tok_seq1 = *act_resp.token;

  // 2. Renew token (advances sequence to 2)
  RenewRequest renew_req;
  auto tok1_bytes = SerializeActivationToken(tok_seq1);
  for (auto b : tok1_bytes) {
    char h[3];
    std::snprintf(h, sizeof(h), "%02x", b);
    renew_req.token_hex += h;
  }
  renew_req.device_fingerprint = "HWID-SEQ-DEVICE";
  renew_req.client_nonce.fill(0x20);

  auto renew_resp = service.ProcessRenew(renew_req, 1700001000);
  MT_CHECK(renew_resp.status == ActivationStatus::kValid);
  MT_CHECK(renew_resp.token->sequence_number == 2);
  ActivationToken tok_seq2 = *renew_resp.token;

  // 3. Stale token (seq 1) renewal attempt MUST BE REJECTED
  renew_req.client_nonce.fill(0x21); // New fresh nonce, but stale token sequence 1
  auto stale_renew = service.ProcessRenew(renew_req, 1700002000);
  MT_CHECK(stale_renew.status == ActivationStatus::kNonceMismatch);

  // 4. Stale token (seq 1) deactivation attempt MUST BE REJECTED
  DeactivateRequest deact_stale;
  deact_stale.token_hex = renew_req.token_hex; // contains tok_seq1
  deact_stale.device_fingerprint = "HWID-SEQ-DEVICE";
  auto stale_deact = service.ProcessDeactivate(deact_stale, 1700003000);
  MT_CHECK(!stale_deact.success);

  // Active seat must still remain active in DB!
  auto cur_act = db.GetActivation("lic-seq-audit", "HWID-SEQ-DEVICE");
  MT_CHECK(cur_act.has_value());
  MT_CHECK(cur_act->sequence_number == 2);

  // 5. Deactivation with current token (seq 2) MUST SUCCEED
  DeactivateRequest deact_current;
  auto tok2_bytes = SerializeActivationToken(tok_seq2);
  for (auto b : tok2_bytes) {
    char h[3];
    std::snprintf(h, sizeof(h), "%02x", b);
    deact_current.token_hex += h;
  }
  deact_current.device_fingerprint = "HWID-SEQ-DEVICE";
  auto current_deact = service.ProcessDeactivate(deact_current, 1700004000);
  MT_CHECK(current_deact.success);

  // Seat is now removed
  auto after_deact = db.GetActivation("lic-seq-audit", "HWID-SEQ-DEVICE");
  MT_CHECK(!after_deact.has_value());

  std::filesystem::remove(db_path, ec);
}

MT_TEST(SecurityAudit_MandatoryActivationCredentials_ProductionMode) {
  std::string db_path = MakeTempDbPath();
  std::error_code ec;
  std::filesystem::remove(db_path, ec);

  auto act_kp = MakeKeyPair();
  ActivationDatabase db(db_path);

  // License 1: Credential-free license
  LicenseRecord lic_no_cred;
  lic_no_cred.license_id = "lic-no-cred-prod";
  lic_no_cred.product_id = "com.vendor.mandate";
  lic_no_cred.max_seats = 1;
  lic_no_cred.created_at = 1700000000;
  lic_no_cred.vm_root.fill(0x11);
  MT_CHECK(db.RegisterLicense(lic_no_cred));

  // License 2: License with credential
  std::string secret = "ProductionSecretPassphrase#9988";
  auto cred_hash = rtprotect::integrity::Sha256(reinterpret_cast<const std::uint8_t*>(secret.data()), secret.size());
  MT_CHECK(cred_hash.has_value());
  LicenseRecord lic_with_cred;
  lic_with_cred.license_id = "lic-with-cred-prod";
  lic_with_cred.product_id = "com.vendor.mandate";
  lic_with_cred.max_seats = 1;
  lic_with_cred.created_at = 1700000000;
  lic_with_cred.vm_root.fill(0x22);
  lic_with_cred.activation_credential_hash = "";
  for (auto b : *cred_hash) {
    char h[3];
    std::snprintf(h, sizeof(h), "%02x", b);
    lic_with_cred.activation_credential_hash += h;
  }
  MT_CHECK(db.RegisterLicense(lic_with_cred));

  ActivationService service(db, std::move(act_kp.private_key), act_kp.public_key);
  service.SetRequireActivationCredentials(true);
  MT_CHECK(service.require_activation_credentials());

  // 1. Attempting to activate credential-free license in production mode MUST BE REJECTED
  ActivateRequest req_no_cred{"lic-no-cred-prod", "HWID-PROD-DEV1", "com.vendor.mandate", "1.0", 1700000000, {}};
  req_no_cred.client_nonce.fill(0x01);
  auto resp_no_cred = service.ProcessActivate(req_no_cred, 1700000000);
  MT_CHECK(resp_no_cred.status == ActivationStatus::kMalformed);
  MT_CHECK(resp_no_cred.error_message.find("lacks mandatory activation credential") != std::string::npos);

  // 2. Attempting to activate lic_with_cred with missing credential MUST BE REJECTED
  ActivateRequest req_empty_cred{"lic-with-cred-prod", "HWID-PROD-DEV1", "com.vendor.mandate", "1.0", 1700000000, {}};
  req_empty_cred.client_nonce.fill(0x02);
  auto resp_empty_cred = service.ProcessActivate(req_empty_cred, 1700000000);
  MT_CHECK(resp_empty_cred.status == ActivationStatus::kMalformed);
  MT_CHECK(resp_empty_cred.error_message.find("Activation credential is required") != std::string::npos);

  // 3. Attempting to activate lic_with_cred with wrong credential MUST BE REJECTED
  ActivateRequest req_wrong_cred{"lic-with-cred-prod", "HWID-PROD-DEV1", "com.vendor.mandate", "1.0", 1700000000, {}, "127.0.0.1", "WrongPassphrase123"};
  req_wrong_cred.client_nonce.fill(0x03);
  auto resp_wrong_cred = service.ProcessActivate(req_wrong_cred, 1700000000);
  MT_CHECK(resp_wrong_cred.status == ActivationStatus::kLicenseMismatch);
  MT_CHECK(resp_wrong_cred.error_message.find("Invalid activation credential") != std::string::npos);

  // 4. Activating with correct credential MUST SUCCEED
  ActivateRequest req_valid{"lic-with-cred-prod", "HWID-PROD-DEV1", "com.vendor.mandate", "1.0", 1700000000, {}, "127.0.0.1", secret};
  req_valid.client_nonce.fill(0x04);
  auto resp_valid = service.ProcessActivate(req_valid, 1700000000);
  MT_CHECK(resp_valid.status == ActivationStatus::kValid);
  MT_CHECK(!resp_valid.encrypted_token_hex.empty());

  std::filesystem::remove(db_path, ec);
}

MT_TEST(AbuseAnalytics_AnomalyDetectionAndScoring) {
  std::string db_path = MakeTempDbPath();
  std::error_code ec;
  std::filesystem::remove(db_path, ec);

  ActivationDatabase db(db_path);

  // 1. Normal License (1 seat, 1 device, normal activation)
  LicenseRecord lic_normal;
  lic_normal.license_id = "lic-normal";
  lic_normal.product_id = "com.vendor.product";
  lic_normal.max_seats = 1;
  lic_normal.created_at = 1700000000;
  lic_normal.vm_root.fill(0x11);
  MT_CHECK(db.RegisterLicense(lic_normal));
  MT_CHECK(db.RecordActivation(ActivationRecord{"lic-normal", "DEV-NORM-1", 1700001000, 1700001000, 1}));
  db.RecordEvent(ActivationEvent{1700001000, ActivationEventType::kActivationSuccess, "lic-normal", "DEV-NORM-1", "192.168.1.50", "Success"});

  // 2. Shared-Key License (1 seat, but 5 distinct devices across multiple subnets and replays)
  LicenseRecord lic_shared;
  lic_shared.license_id = "lic-shared-abuse";
  lic_shared.product_id = "com.vendor.product";
  lic_shared.max_seats = 1;
  lic_shared.created_at = 1700000000;
  lic_shared.vm_root.fill(0x22);
  MT_CHECK(db.RegisterLicense(lic_shared));
  for (int i = 1; i <= 5; ++i) {
    std::string dev = "PIRATE-DEV-" + std::to_string(i);
    std::string ip = "10." + std::to_string(i) + ".1.100";
    db.RecordEvent(ActivationEvent{1700001000ULL + i * 10, ActivationEventType::kActivationSuccess, "lic-shared-abuse", dev, ip, "Activation"});
    db.RecordEvent(ActivationEvent{1700001000ULL + i * 10 + 1, ActivationEventType::kReplayBlocked, "lic-shared-abuse", dev, ip, "Replay"});
    db.RecordEvent(ActivationEvent{1700001000ULL + i * 10 + 2, ActivationEventType::kSeatLimitExceeded, "lic-shared-abuse", dev, ip, "Exceeded"});
  }

  // 3. Rapid Churn License (1 seat, 6 deactivations in window)
  LicenseRecord lic_churn;
  lic_churn.license_id = "lic-churn-abuse";
  lic_churn.product_id = "com.vendor.product";
  lic_churn.max_seats = 1;
  lic_churn.created_at = 1700000000;
  lic_churn.vm_root.fill(0x33);
  MT_CHECK(db.RegisterLicense(lic_churn));
  for (int i = 1; i <= 6; ++i) {
    db.RecordEvent(ActivationEvent{1700001000ULL + i * 10, ActivationEventType::kDeactivation, "lic-churn-abuse", "DEV-CHURN", "192.168.1.10", "Deactivated"});
  }

  // Analyze normal license
  auto rep_normal = AbuseAnalyticsEngine::AnalyzeLicense(db, "lic-normal", 1700002000, 86400);
  MT_CHECK(rep_normal.severity == RiskSeverity::kLow);
  MT_CHECK(rep_normal.action == RecommendedAction::kAllow);
  MT_CHECK(rep_normal.anomaly_flags.empty());

  // Analyze shared abuse license
  auto rep_shared = AbuseAnalyticsEngine::AnalyzeLicense(db, "lic-shared-abuse", 1700002000, 86400);
  MT_CHECK(rep_shared.severity == RiskSeverity::kCritical || rep_shared.severity == RiskSeverity::kHigh);
  MT_CHECK(rep_shared.action == RecommendedAction::kSuspendLicense || rep_shared.action == RecommendedAction::kFlagForReview);
  MT_CHECK(rep_shared.risk_score >= 0.5);

  bool found_shared_flag = false;
  bool found_subnet_flag = false;
  bool found_replay_flag = false;
  for (const auto& f : rep_shared.anomaly_flags) {
    if (f.flag_code == "SHARED_KEY_SYNDROME") found_shared_flag = true;
    if (f.flag_code == "SUBNET_DISPERSION") found_subnet_flag = true;
    if (f.flag_code == "REPLAY_OR_BRUTE_FORCE_SPIKE") found_replay_flag = true;
  }
  MT_CHECK(found_shared_flag);
  MT_CHECK(found_subnet_flag);
  MT_CHECK(found_replay_flag);

  // Analyze churn abuse license
  auto rep_churn = AbuseAnalyticsEngine::AnalyzeLicense(db, "lic-churn-abuse", 1700002000, 86400);
  bool found_churn_flag = false;
  for (const auto& f : rep_churn.anomaly_flags) {
    if (f.flag_code == "RAPID_SEAT_CHURN") found_churn_flag = true;
  }
  MT_CHECK(found_churn_flag);

  // Analyze full database
  auto summary = AbuseAnalyticsEngine::Analyze(db, 1700002000, 86400);
  MT_CHECK(summary.total_licenses_analyzed == 3);
  MT_CHECK(summary.low_risk_count == 1);
  MT_CHECK(summary.flagged_licenses.size() >= 2);

  // Test JSON serialization
  std::string json = AbuseAnalyticsEngine::ToJson(summary);
  MT_CHECK(json.find("\"total_licenses_analyzed\": 3") != std::string::npos);
  MT_CHECK(json.find("\"flagged_licenses\": [") != std::string::npos);
  MT_CHECK(json.find("SHARED_KEY_SYNDROME") != std::string::npos);

  std::filesystem::remove(db_path, ec);
}

MT_TEST(AbuseAnalytics_EdgeCasesAndHardenedScoring) {
  // 1. Verify Subnet Extraction across IPv4, IPv6 compressed, and loopback
  MT_CHECK(rtprotect::licensing::internal::ExtractSubnet("192.168.1.100") == "192.168.1.0/24");
  MT_CHECK(rtprotect::licensing::internal::ExtractSubnet("10.50.2.1") == "10.50.2.0/24");
  MT_CHECK(rtprotect::licensing::internal::ExtractSubnet("127.0.0.1") == "127.0.0.0/8");
  MT_CHECK(rtprotect::licensing::internal::ExtractSubnet("localhost") == "127.0.0.0/8");
  MT_CHECK(rtprotect::licensing::internal::ExtractSubnet("::1") == "127.0.0.0/8");
  MT_CHECK(rtprotect::licensing::internal::ExtractSubnet("") == "127.0.0.0/8");
  MT_CHECK(rtprotect::licensing::internal::ExtractSubnet("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == "2001:0db8:85a3::/48");
  MT_CHECK(rtprotect::licensing::internal::ExtractSubnet("2001:db8::1") == "2001:db8::/48");
  MT_CHECK(rtprotect::licensing::internal::ExtractSubnet("fe80::1") == "fe80::/48");
  MT_CHECK(rtprotect::licensing::internal::ExtractSubnet("fe80::2") == "fe80::/48");

  std::string db_path = MakeTempDbPath();
  std::error_code ec;
  std::filesystem::remove(db_path, ec);

  ActivationDatabase db(db_path);

  // 2. Activation and Renewal Failure Burst Detection
  LicenseRecord lic_burst;
  lic_burst.license_id = "lic-burst";
  lic_burst.product_id = "com.vendor.product";
  lic_burst.max_seats = 1;
  lic_burst.created_at = 1700000000;
  lic_burst.vm_root.fill(0x55);
  MT_CHECK(db.RegisterLicense(lic_burst));

  for (int i = 1; i <= 4; ++i) {
    db.RecordEvent(ActivationEvent{1700001000ULL + i, ActivationEventType::kActivationFailed, "lic-burst", "DEV-STUFF", "192.168.1.50", "Invalid cred"});
  }
  db.RecordEvent(ActivationEvent{1700001010ULL, ActivationEventType::kRenewalFailed, "lic-burst", "DEV-STUFF", "192.168.1.50", "Token expired"});
  db.RecordEvent(ActivationEvent{1700001011ULL, ActivationEventType::kRenewalFailed, "lic-burst", "DEV-STUFF", "192.168.1.50", "Token tampered"});

  auto rep_burst = AbuseAnalyticsEngine::AnalyzeLicense(db, "lic-burst", 1700002000, 86400);
  bool found_burst_flag = false;
  for (const auto& f : rep_burst.anomaly_flags) {
    if (f.flag_code == "ACTIVATION_FAILURE_BURST") {
      found_burst_flag = true;
      MT_CHECK(f.score_impact > 0.20);
    }
  }
  MT_CHECK(found_burst_flag);
  MT_CHECK(rep_burst.abuse_events_count == 6);

  // 3. Revoked License with Activity
  LicenseRecord lic_revoked;
  lic_revoked.license_id = "lic-revoked";
  lic_revoked.product_id = "com.vendor.product";
  lic_revoked.status = LicenseRecordStatus::kRevoked;
  lic_revoked.max_seats = 1;
  lic_revoked.created_at = 1700000000;
  lic_revoked.vm_root.fill(0x66);
  MT_CHECK(db.RegisterLicense(lic_revoked));
  db.RecordEvent(ActivationEvent{1700001050ULL, ActivationEventType::kActivationFailed, "lic-revoked", "DEV-PIRATE", "10.0.0.1", "Revoked"});

  auto rep_revoked = AbuseAnalyticsEngine::AnalyzeLicense(db, "lic-revoked", 1700002000, 86400);
  MT_CHECK(rep_revoked.action == RecommendedAction::kSuspendLicense);
  bool found_revoked_flag = false;
  for (const auto& f : rep_revoked.anomaly_flags) {
    if (f.flag_code == "REVOKED_LICENSE_ACTIVITY") {
      found_revoked_flag = true;
    }
  }
  MT_CHECK(found_revoked_flag);

  // 4. Multi-seat Churn Proportional Scaling
  LicenseRecord lic_multi;
  lic_multi.license_id = "lic-multi";
  lic_multi.product_id = "com.vendor.product";
  lic_multi.max_seats = 10;
  lic_multi.created_at = 1700000000;
  lic_multi.vm_root.fill(0x77);
  MT_CHECK(db.RegisterLicense(lic_multi));
  // 31 deactivations on 10 seats (threshold is 30, excess is 1)
  for (int i = 1; i <= 31; ++i) {
    db.RecordEvent(ActivationEvent{1700001000ULL + i, ActivationEventType::kDeactivation, "lic-multi", "DEV-" + std::to_string(i), "192.168.1.1", "Deactivated"});
  }
  auto rep_multi = AbuseAnalyticsEngine::AnalyzeLicense(db, "lic-multi", 1700002000, 86400);
  bool found_churn = false;
  for (const auto& f : rep_multi.anomaly_flags) {
    if (f.flag_code == "RAPID_SEAT_CHURN") {
      found_churn = true;
      // Normalized churn ratio of 3.1 on 10 seats yields ~0.155 impact, NOT max capped 0.25
      MT_CHECK(f.score_impact >= 0.150 && f.score_impact <= 0.160);
    }
  }
  MT_CHECK(found_churn);

  // 5. Unknown License handling
  // Clean inquiry with no events/sessions: LOW severity, ALLOW action
  auto rep_unknown = AbuseAnalyticsEngine::AnalyzeLicense(db, "lic-nonexistent", 1700002000, 86400);
  MT_CHECK(rep_unknown.severity == RiskSeverity::kLow);
  MT_CHECK(rep_unknown.action == RecommendedAction::kAllow);

  // Unregistered license with telemetry events: UNREGISTERED_LICENSE_ACTIVITY, SUSPEND_LICENSE
  db.RecordEvent(ActivationEvent{1700001080ULL, ActivationEventType::kActivationFailed, "lic-unregistered-active", "DEV-FAKE", "192.168.1.1", "Invalid"});
  auto rep_unreg_active = AbuseAnalyticsEngine::AnalyzeLicense(db, "lic-unregistered-active", 1700002000, 86400);
  MT_CHECK(rep_unreg_active.action == RecommendedAction::kSuspendLicense);
  bool found_unreg_flag = false;
  for (const auto& f : rep_unreg_active.anomaly_flags) {
    if (f.flag_code == "UNREGISTERED_LICENSE_ACTIVITY") {
      found_unreg_flag = true;
      MT_CHECK(f.score_impact >= 0.30);
    }
  }
  MT_CHECK(found_unreg_flag);

  // 6. Future Timestamp Events Ignored
  db.RecordEvent(ActivationEvent{1700009999ULL, ActivationEventType::kReplayBlocked, "lic-burst", "DEV-FUTURE", "192.168.1.1", "Future"});
  auto rep_future = AbuseAnalyticsEngine::AnalyzeLicense(db, "lic-burst", 1700002000, 86400);
  // Replay count should still be 0 within the evaluation time 1700002000
  bool found_replay = false;
  for (const auto& f : rep_future.anomaly_flags) {
    if (f.flag_code == "REPLAY_OR_BRUTE_FORCE_SPIKE") found_replay = true;
  }
  MT_CHECK(!found_replay);

  std::filesystem::remove(db_path, ec);
}

MT_TEST(Database_ReserveSeatAtomic_StalePurgeRollback) {
  std::string db_path = MakeTempDbPath();
  std::error_code ec;
  std::filesystem::remove(db_path, ec);

  ActivationDatabase db(db_path);

  LicenseRecord lic;
  lic.license_id = "lic-purge-test";
  lic.product_id = "com.vendor.product";
  lic.max_seats = 2;
  lic.created_at = 1700000000;
  lic.vm_root.fill(0x88);
  MT_CHECK(db.RegisterLicense(lic));

  // Seed two activations at timestamp 1000
  MT_CHECK(db.RecordActivation(ActivationRecord{"lic-purge-test", "DEV-STALE-1", 1000, 1000, 1}));
  MT_CHECK(db.RecordActivation(ActivationRecord{"lic-purge-test", "DEV-STALE-2", 1000, 1000, 1}));
  MT_CHECK(db.GetActivations("lic-purge-test").size() == 2);

  // 1. Attempt reservation with capacity 0 (guaranteed capacity rejection in step 3)
  // Even though stale timeout (500s) has elapsed at current_time=2000, rejection MUST rollback in-memory purge
  auto res_fail = db.ReserveSeatAtomic("lic-purge-test", "DEV-NEW", 0, 2000, 500);
  MT_CHECK(!res_fail.success);
  // Both stale activations must remain intact in memory
  auto in_mem_acts = db.GetActivations("lic-purge-test");
  MT_CHECK(in_mem_acts.size() == 2);
  MT_CHECK(in_mem_acts[0].device_fingerprint == "DEV-STALE-1");
  MT_CHECK(in_mem_acts[1].device_fingerprint == "DEV-STALE-2");

  // 2. Successful reservation with capacity 2 at current_time=2000
  // Stale activations are purged and new seat is persisted
  auto res_ok = db.ReserveSeatAtomic("lic-purge-test", "DEV-NEW", 2, 2000, 500);
  MT_CHECK(res_ok.success);
  MT_CHECK(res_ok.is_new_seat);
  auto post_acts = db.GetActivations("lic-purge-test");
  MT_CHECK(post_acts.size() == 1);
  MT_CHECK(post_acts[0].device_fingerprint == "DEV-NEW");

  // 3. Verify on-disk persistence matches in-memory state
  ActivationDatabase db_disk(db_path);
  auto disk_acts = db_disk.GetActivations("lic-purge-test");
  MT_CHECK(disk_acts.size() == 1);
  MT_CHECK(disk_acts[0].device_fingerprint == "DEV-NEW");

  std::filesystem::remove(db_path, ec);
}

MT_TEST(HttpServer_Analytics_AdminAuthRequired) {
  std::string db_path = MakeTempDbPath();
  std::error_code ec;
  std::filesystem::remove(db_path, ec);

  auto kp = MakeKeyPair();
  ActivationDatabase db(db_path);

  LicenseRecord lic;
  lic.license_id = "lic-analytics-http";
  lic.product_id = "com.vendor.analytics";
  lic.max_seats = 1;
  lic.created_at = 1700000000;
  lic.vm_root.fill(0x44);
  MT_CHECK(db.RegisterLicense(lic));

  ActivationService service(db, std::move(kp.private_key), kp.public_key);
  ActivationServerHttp server(service);

  server.SetAdminAuthToken("admin-secret-analytics-token");
  MT_CHECK(server.Start(0, "127.0.0.1"));
  std::uint16_t port = server.port();

  // 1. GET /analytics without auth header -> 401 Unauthorized
  std::string req_no_auth = "GET /analytics HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
  std::string resp_no_auth = SendRawHttpRequest(port, req_no_auth);
  MT_CHECK(resp_no_auth.find("HTTP/1.1 401 Unauthorized") != std::string::npos);
  MT_CHECK(resp_no_auth.find("WWW-Authenticate: Bearer") != std::string::npos);

  // 2. GET /analytics with invalid X-Admin-Key -> 401 Unauthorized
  std::string req_bad_key = "GET /analytics HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Admin-Key: invalid-key\r\nConnection: close\r\n\r\n";
  std::string resp_bad_key = SendRawHttpRequest(port, req_bad_key);
  MT_CHECK(resp_bad_key.find("HTTP/1.1 401 Unauthorized") != std::string::npos);

  // 3. GET /analytics with valid Authorization: Bearer -> 200 OK
  std::string req_bearer = "GET /analytics HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer admin-secret-analytics-token\r\nConnection: close\r\n\r\n";
  std::string resp_bearer = SendRawHttpRequest(port, req_bearer);
  MT_CHECK(resp_bearer.find("HTTP/1.1 200 OK") != std::string::npos);
  MT_CHECK(resp_bearer.find("\"total_licenses_analyzed\":") != std::string::npos);
  MT_CHECK(resp_bearer.find("\"flagged_licenses\":") != std::string::npos);

  server.Stop();
  std::filesystem::remove(db_path, ec);
}

MT_TEST(Database_EnvelopeEncryption_VmRoot) {
  std::string db_path = MakeTempDbPath();
  std::error_code ec;
  std::filesystem::remove(db_path, ec);

  std::array<std::uint8_t, 32> expected_root{};
  for (std::size_t i = 0; i < 32; ++i) expected_root[i] = static_cast<std::uint8_t>(0xC0 + i);

  {
    ActivationDatabase db(db_path);
    LicenseRecord lic;
    lic.license_id = "lic-envelope-enc";
    lic.product_id = "com.vendor.envelope";
    lic.max_seats = 1;
    lic.created_at = 1700000000;
    lic.vm_root = expected_root;
    MT_CHECK(db.RegisterLicense(lic));
    MT_CHECK(db.Save());
  }

  // 1. Verify file on disk contains "enc:" envelope encryption format and NOT plaintext root
  auto file_bytes = rtprotect::tooling::ReadFile(db_path);
  MT_CHECK(file_bytes.has_value());
  std::string content(reinterpret_cast<const char*>(file_bytes->data()), file_bytes->size());
  MT_CHECK(content.find("lic-envelope-enc|com.vendor.envelope|active|1|enc:") != std::string::npos);

  // 2. Load from disk and verify vm_root matches original
  {
    ActivationDatabase db2(db_path);
    auto lic2 = db2.GetLicense("lic-envelope-enc");
    MT_CHECK(lic2.has_value());
    MT_CHECK(lic2->vm_root == expected_root);
  }

  // 3. Test explicit custom encryption key
  std::array<std::uint8_t, 32> custom_key_bytes{};
  for (std::size_t i = 0; i < 32; ++i) custom_key_bytes[i] = static_cast<std::uint8_t>(0x7A ^ i);
  auto custom_key = rtprotect::crypto::Aes256Key::FromBytes(custom_key_bytes.data(), custom_key_bytes.size());
  MT_CHECK(custom_key.has_value());

  std::string db_path2 = MakeTempDbPath();
  std::filesystem::remove(db_path2, ec);
  {
    ActivationDatabase db_custom(db_path2, &(*custom_key));
    LicenseRecord lic;
    lic.license_id = "lic-custom-enc";
    lic.product_id = "com.vendor.custom";
    lic.max_seats = 1;
    lic.created_at = 1700000000;
    lic.vm_root = expected_root;
    MT_CHECK(db_custom.RegisterLicense(lic));
    MT_CHECK(db_custom.Save());
  }
  {
    ActivationDatabase db_custom_load(db_path2, &(*custom_key));
    auto lic_load = db_custom_load.GetLicense("lic-custom-enc");
    MT_CHECK(lic_load.has_value());
    MT_CHECK(lic_load->vm_root == expected_root);
  }

  std::filesystem::remove(db_path, ec);
  std::filesystem::remove(db_path2, ec);
}

MT_TEST(Database_DuplicateLicenseRegistration_Rejected) {
  std::string db_path = MakeTempDbPath();
  std::error_code ec;
  std::filesystem::remove(db_path, ec);

  ActivationDatabase db(db_path);
  LicenseRecord lic;
  lic.license_id = "lic-dup-reject";
  lic.product_id = "com.vendor.dup";
  lic.max_seats = 1;
  lic.created_at = 1700000000;
  lic.vm_root.fill(0x11);
  MT_CHECK(db.RegisterLicense(lic));

  // Revoke the license
  MT_CHECK(db.UpdateLicenseStatus("lic-dup-reject", LicenseRecordStatus::kRevoked));
  auto lic_revoked = db.GetLicense("lic-dup-reject");
  MT_CHECK(lic_revoked.has_value());
  MT_CHECK(lic_revoked->status == LicenseRecordStatus::kRevoked);

  // Attempt to re-register the same license ID (default allow_overwrite = false) -> MUST FAIL
  LicenseRecord lic_new;
  lic_new.license_id = "lic-dup-reject";
  lic_new.product_id = "com.vendor.dup";
  lic_new.status = LicenseRecordStatus::kActive;
  lic_new.max_seats = 5;
  lic_new.created_at = 1700000001;
  lic_new.vm_root.fill(0x22);
  MT_CHECK(!db.RegisterLicense(lic_new, false));

  // Status must remain Revoked
  auto lic_check = db.GetLicense("lic-dup-reject");
  MT_CHECK(lic_check.has_value());
  MT_CHECK(lic_check->status == LicenseRecordStatus::kRevoked);

  // Explicit allow_overwrite permitted only with explicit opt-in
  MT_CHECK(db.RegisterLicense(lic_new, true));
  auto lic_overwritten = db.GetLicense("lic-dup-reject");
  MT_CHECK(lic_overwritten.has_value());
  MT_CHECK(lic_overwritten->status == LicenseRecordStatus::kActive);
  MT_CHECK(lic_overwritten->max_seats == 5);

  std::filesystem::remove(db_path, ec);
}

MT_TEST(Database_RollbackSeatAtomic_RaceConditionSafety) {
  std::string db_path = MakeTempDbPath();
  std::error_code ec;
  std::filesystem::remove(db_path, ec);

  ActivationDatabase db(db_path);
  LicenseRecord lic;
  lic.license_id = "lic-race-test";
  lic.product_id = "com.vendor.race";
  lic.max_seats = 2;
  lic.created_at = 1700000000;
  lic.vm_root.fill(0x99);
  MT_CHECK(db.RegisterLicense(lic));

  // 1. Initial reservation: sequence 1
  auto res1 = db.ReserveSeatAtomic("lic-race-test", "DEV-RACE-1", 2, 1700000000);
  MT_CHECK(res1.success);
  MT_CHECK(res1.is_new_seat);
  MT_CHECK(res1.sequence_number == 1);

  // 2. Concurrent renewal arrives and advances sequence 1 -> 2
  auto res2 = db.ReserveSeatAtomic("lic-race-test", "DEV-RACE-1", 2, 1700000050);
  MT_CHECK(res2.success);
  MT_CHECK(!res2.is_new_seat);
  MT_CHECK(res2.sequence_number == 2);
  MT_CHECK(res2.previous_sequence_number == 1);

  // 3. Stale rollback for request 1 (which had sequence 1) is attempted -> MUST BE REJECTED
  bool rolled_back = db.RollbackSeatAtomic("lic-race-test", "DEV-RACE-1", res1);
  MT_CHECK(!rolled_back); // Refuses to corrupt or erase sequence 2!

  // Verify seat still exists and remains at sequence 2
  auto act = db.GetActivation("lic-race-test", "DEV-RACE-1");
  MT_CHECK(act.has_value());
  MT_CHECK(act->sequence_number == 2);

  // 4. Valid rollback for current reservation (sequence 2) -> Rolls back to sequence 1
  MT_CHECK(db.RollbackSeatAtomic("lic-race-test", "DEV-RACE-1", res2));
  act = db.GetActivation("lic-race-test", "DEV-RACE-1");
  MT_CHECK(act.has_value());
  MT_CHECK(act->sequence_number == 1);

  std::filesystem::remove(db_path, ec);
}

MT_TEST(Database_CommitRenewalAndDeactivationAtomic) {
  std::string db_path = MakeTempDbPath();
  std::error_code ec;
  std::filesystem::remove(db_path, ec);

  ActivationDatabase db(db_path);
  LicenseRecord lic;
  lic.license_id = "lic-atomic-test";
  lic.product_id = "com.vendor.atomic";
  lic.max_seats = 1;
  lic.created_at = 1700000000;
  lic.vm_root.fill(0x33);
  MT_CHECK(db.RegisterLicense(lic));

  auto res = db.ReserveSeatAtomic("lic-atomic-test", "DEV-ATOMIC", 1, 1700000000);
  MT_CHECK(res.success);

  // 1. Commit renewal atomically
  ActivationRecord renewed_act;
  renewed_act.license_id = "lic-atomic-test";
  renewed_act.device_fingerprint = "DEV-ATOMIC";
  renewed_act.last_seen = 1700000100;
  renewed_act.sequence_number = 2;

  MT_CHECK(db.CommitRenewalAtomic("client_nonce_111", 1700086400,
                                  "server_nonce_111", 1702592000,
                                  renewed_act, 1, 1700000100));

  // Nonces are recorded
  MT_CHECK(db.IsNonceUsed("client_nonce_111"));
  MT_CHECK(db.IsNonceUsed("server_nonce_111"));

  // Seat is bumped
  auto act = db.GetActivation("lic-atomic-test", "DEV-ATOMIC");
  MT_CHECK(act.has_value());
  MT_CHECK(act->sequence_number == 2);

  // Replay of same nonces fails
  renewed_act.sequence_number = 3;
  MT_CHECK(!db.CommitRenewalAtomic("client_nonce_111", 1700086400,
                                   "server_nonce_222", 1702592000,
                                   renewed_act, 2, 1700000100));

  // Sequence mismatch fails
  MT_CHECK(!db.CommitRenewalAtomic("client_nonce_333", 1700086400,
                                   "server_nonce_333", 1702592000,
                                   renewed_act, 5, 1700000100));

  // 2. Commit deactivation atomically
  MT_CHECK(db.CommitDeactivationAtomic("lic-atomic-test", "DEV-ATOMIC", 2,
                                      "deact_nonce_444", 1702592000, 1700000200));
  MT_CHECK(db.IsNonceUsed("deact_nonce_444"));
  MT_CHECK(!db.GetActivation("lic-atomic-test", "DEV-ATOMIC").has_value());

  std::filesystem::remove(db_path, ec);
}

MT_MAIN()
