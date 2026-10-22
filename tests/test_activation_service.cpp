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

#include <openssl/rand.h>

#include "crypto/aead.h"
#include "crypto/kdf.h"
#include "integrity/keys.h"
#include "licensing/activation.h"
#include "licensing/activation_client.h"
#include "licensing/activation_database.h"
#include "licensing/activation_server.h"
#include "licensing/activation_server_http.h"
#include "licensing/activation_service.h"
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

MT_MAIN()
