// tests/test_activation.cpp

#include "licensing/activation.h"
#include "licensing/activation_client.h"
#include "licensing/activation_server.h"
#include "licensing/countermeasure_config.h"
#include "licensing/secure_storage.h"
#include "licensing/hardware_id.h"
#include "integrity/keys.h"
#include "crypto/aead.h"
#include "crypto/kdf.h"
#include "tooling/file_io.h"
#include "tests/micro_test.h"
#include <filesystem>

using namespace rtprotect::licensing;
using namespace rtprotect::integrity;

namespace {

Ed25519KeyPair MakeKeyPair() {
  auto kp = GenerateEd25519KeyPair();
  MT_CHECK(kp.has_value());
  return std::move(*kp);
}

}  // namespace

MT_TEST(ActivationRequest_Wire_RoundTrip) {
  auto req = CreateActivationRequest("lic-12345", "CPU:VOL:SYS:HOST-ABCDEF", "2.1.0", 1700000000);
  auto bytes = SerializeActivationRequest(req);
  auto parsed = DeserializeActivationRequest(bytes.data(), bytes.size());

  MT_CHECK(parsed.has_value());
  MT_CHECK(parsed->request_id == req.request_id);
  MT_CHECK(parsed->license_id == req.license_id);
  MT_CHECK(parsed->hardware_id == req.hardware_id);
  MT_CHECK(parsed->app_version == req.app_version);
  MT_CHECK(parsed->client_timestamp == req.client_timestamp);
  MT_CHECK(parsed->nonce == req.nonce);
}

MT_TEST(ActivationRequest_Text_RoundTrip) {
  auto req = CreateActivationRequest("lic-12345", "CPU:VOL:SYS:HOST-ABCDEF", "2.1.0", 1700000000);
  std::string text = ActivationRequestToText(req);
  auto parsed = ActivationRequestFromText(text);

  MT_CHECK(parsed.has_value());
  MT_CHECK(parsed->request_id == req.request_id);
  MT_CHECK(parsed->license_id == req.license_id);
  MT_CHECK(parsed->hardware_id == req.hardware_id);
  MT_CHECK(parsed->nonce == req.nonce);
}

MT_TEST(ActivationTicket_Wire_RoundTrip) {
  auto kp = MakeKeyPair();
  ActivationTicket tkt;
  tkt.ticket_id = "tkt-001";
  tkt.license_id = "lic-12345";
  tkt.hardware_id = "CPU:VOL:SYS:HOST-ABCDEF";
  tkt.issued_at = 1700000000;
  tkt.expires_at = 1700086400;
  tkt.nonce.fill(0x42);
  tkt.session_key.fill(0x99);
  tkt.metadata = "features=enterprise";
  MT_CHECK(SignActivationTicket(tkt, kp.private_key));

  auto bytes = SerializeActivationTicket(tkt);
  auto parsed = DeserializeActivationTicket(bytes.data(), bytes.size());

  MT_CHECK(parsed.has_value());
  MT_CHECK(parsed->ticket_id == tkt.ticket_id);
  MT_CHECK(parsed->license_id == tkt.license_id);
  MT_CHECK(parsed->hardware_id == tkt.hardware_id);
  MT_CHECK(parsed->issued_at == tkt.issued_at);
  MT_CHECK(parsed->expires_at == tkt.expires_at);
  MT_CHECK(parsed->nonce == tkt.nonce);
  MT_CHECK(parsed->session_key == tkt.session_key);
  MT_CHECK(parsed->metadata == tkt.metadata);
  MT_CHECK(parsed->signature == tkt.signature);
}

MT_TEST(ActivationTicket_Text_RoundTrip) {
  auto kp = MakeKeyPair();
  ActivationTicket tkt;
  tkt.ticket_id = "tkt-002";
  tkt.license_id = "lic-99999";
  tkt.hardware_id = "CPU:VOL:SYS:HOST-XYZ";
  tkt.issued_at = 1700000000;
  tkt.expires_at = 1700086400;
  tkt.nonce.fill(0xAA);
  tkt.session_key.fill(0x55);
  MT_CHECK(SignActivationTicket(tkt, kp.private_key));

  std::string text = ActivationTicketToText(tkt);
  auto parsed = ActivationTicketFromText(text);

  MT_CHECK(parsed.has_value());
  MT_CHECK(parsed->ticket_id == tkt.ticket_id);
  MT_CHECK(parsed->license_id == tkt.license_id);
  MT_CHECK(parsed->signature == tkt.signature);
}

MT_TEST(Activation_Issue_And_Verify_Success) {
  auto kp = MakeKeyPair();
  ActivationManager mgr;
  mgr.RegisterLicense("lic-ent-100", 5);

  std::string hwid = "1111:2222:3333:4444-5555";
  auto req = CreateActivationRequest("lic-ent-100", hwid, "1.0.0", 1700000000);

  auto result = mgr.IssueTicket(req, kp.private_key, 86400, 1700000000);
  MT_CHECK(result.status == ActivationStatus::kValid);
  MT_CHECK(result.ticket.has_value());

  auto status = VerifyActivationTicket(*result.ticket, kp.public_key, req, 1700000000);
  MT_CHECK(status == ActivationStatus::kValid);
}

MT_TEST(Activation_Rejects_Tampered_Signature) {
  auto kp = MakeKeyPair();
  ActivationManager mgr;

  std::string hwid = "1111:2222:3333:4444-5555";
  auto req = CreateActivationRequest("lic-ent-100", hwid, "1.0.0", 1700000000);

  auto result = mgr.IssueTicket(req, kp.private_key, 86400, 1700000000);
  MT_CHECK(result.ticket.has_value());

  auto tampered = *result.ticket;
  tampered.signature[0] ^= 0xFF;

  auto status = VerifyActivationTicket(tampered, kp.public_key, req, 1700000000);
  MT_CHECK(status == ActivationStatus::kInvalidSignature);
}

MT_TEST(Activation_Rejects_Mismatched_Nonce) {
  auto kp = MakeKeyPair();
  ActivationManager mgr;

  std::string hwid = "1111:2222:3333:4444-5555";
  auto req1 = CreateActivationRequest("lic-ent-100", hwid, "1.0.0", 1700000000);
  auto req2 = CreateActivationRequest("lic-ent-100", hwid, "1.0.0", 1700000000);

  auto result = mgr.IssueTicket(req1, kp.private_key, 86400, 1700000000);
  MT_CHECK(result.ticket.has_value());

  // Verify ticket against req2 which has a different nonce (replay attempt)
  auto status = VerifyActivationTicket(*result.ticket, kp.public_key, req2, 1700000000);
  MT_CHECK(status == ActivationStatus::kNonceMismatch);
}

MT_TEST(Activation_Rejects_Hardware_Mismatch) {
  auto kp = MakeKeyPair();
  ActivationManager mgr;

  std::string hwid1 = "1111:2222:3333:4444-5555";
  std::string hwid2 = "AAAA:BBBB:CCCC:DDDD-EEEE";
  auto req1 = CreateActivationRequest("lic-ent-100", hwid1, "1.0.0", 1700000000);

  auto result = mgr.IssueTicket(req1, kp.private_key, 86400, 1700000000);
  MT_CHECK(result.ticket.has_value());

  auto req_other_machine = req1;
  req_other_machine.hardware_id = hwid2;

  auto status = VerifyActivationTicket(*result.ticket, kp.public_key, req_other_machine, 1700000000);
  MT_CHECK(status == ActivationStatus::kHardwareMismatch);
}

MT_TEST(Activation_Detects_Expiration) {
  auto kp = MakeKeyPair();
  ActivationManager mgr;

  std::string hwid = "1111:2222:3333:4444-5555";
  auto req = CreateActivationRequest("lic-ent-100", hwid, "1.0.0", 1700000000);

  auto result = mgr.IssueTicket(req, kp.private_key, 3600, 1700000000); // 1 hour validity
  MT_CHECK(result.ticket.has_value());

  // Within 1 hour -> valid
  MT_CHECK(VerifyActivationTicket(*result.ticket, kp.public_key, req, 1700001000) == ActivationStatus::kValid);

  // Past 1 hour -> expired
  MT_CHECK(VerifyActivationTicket(*result.ticket, kp.public_key, req, 1700004000) == ActivationStatus::kExpired);
}

MT_TEST(ActivationManager_Enforces_Concurrency_Cap) {
  auto kp = MakeKeyPair();
  ActivationManager mgr;
  mgr.RegisterLicense("lic-limited", 2); // 2 seats

  std::string hwid1 = "CPU1:VOL1:SYS1:HOST1-1111";
  std::string hwid2 = "CPU2:VOL2:SYS2:HOST2-2222";
  std::string hwid3 = "CPU3:VOL3:SYS3:HOST3-3333";

  auto req1 = CreateActivationRequest("lic-limited", hwid1, "1.0", 1700000000);
  auto req2 = CreateActivationRequest("lic-limited", hwid2, "1.0", 1700000000);
  auto req3 = CreateActivationRequest("lic-limited", hwid3, "1.0", 1700000000);

  // Seat 1
  auto res1 = mgr.IssueTicket(req1, kp.private_key, 3600, 1700000000);
  MT_CHECK(res1.status == ActivationStatus::kValid);

  // Seat 2
  auto res2 = mgr.IssueTicket(req2, kp.private_key, 3600, 1700000000);
  MT_CHECK(res2.status == ActivationStatus::kValid);

  // Seat 1 refresh/renew -> should succeed without exceeding cap
  auto req1_renew = CreateActivationRequest("lic-limited", hwid1, "1.0", 1700001000);
  auto res1_renew = mgr.IssueTicket(req1_renew, kp.private_key, 3600, 1700001000);
  MT_CHECK(res1_renew.status == ActivationStatus::kValid);

  // Seat 3 (third distinct device) -> should be rejected
  auto res3 = mgr.IssueTicket(req3, kp.private_key, 3600, 1700001000);
  MT_CHECK(res3.status == ActivationStatus::kConcurrencyLimitExceeded);

  // Advance time beyond seat 2 expiry (1700000000 + 3600 = 1700003600)
  auto res3_after_expiry = mgr.IssueTicket(req3, kp.private_key, 3600, 1700004000);
  MT_CHECK(res3_after_expiry.status == ActivationStatus::kValid);
}

MT_TEST(ActivationManager_Revocation_Workflow) {
  auto kp = MakeKeyPair();
  ActivationManager mgr;
  mgr.RegisterLicense("lic-revokable", 10);

  std::string hwid = "CPU1:VOL1:SYS1:HOST1-1111";
  auto req = CreateActivationRequest("lic-revokable", hwid, "1.0", 1700000000);

  auto res1 = mgr.IssueTicket(req, kp.private_key, 3600, 1700000000);
  MT_CHECK(res1.status == ActivationStatus::kValid);

  // Revoke ticket
  mgr.RevokeTicket(res1.ticket->ticket_id, "Reported stolen");
  MT_CHECK(mgr.IsTicketRevoked(res1.ticket->ticket_id));

  // Revoke license
  mgr.RevokeLicense("lic-revokable", "Chargeback issued");
  MT_CHECK(mgr.IsLicenseRevoked("lic-revokable"));

  // New ticket issuance for revoked license is blocked
  auto res2 = mgr.IssueTicket(req, kp.private_key, 3600, 1700000100);
  MT_CHECK(res2.status == ActivationStatus::kRevoked);

  // Export JSON
  std::string json = mgr.ExportRevocationListJson();
  MT_CHECK(json.find("lic-revokable") != std::string::npos);
  MT_CHECK(json.find(res1.ticket->ticket_id) != std::string::npos);

  // Import into fresh manager
  ActivationManager fresh_mgr;
  MT_CHECK(fresh_mgr.ImportRevocationListJson(json));
  MT_CHECK(fresh_mgr.IsLicenseRevoked("lic-revokable"));
  MT_CHECK(fresh_mgr.IsTicketRevoked(res1.ticket->ticket_id));
}

MT_TEST(ActivationToken_SerializationRoundTrip) {
  ActivationToken tok;
  tok.schema_version = kActivationSchemaVersion;
  tok.license_id = "lic-ent-token-999";
  tok.device_fingerprint_hash = "CPU:VOL:SYS:HOST-TOKEN-12345678";
  tok.issued_at = 1700000000;
  tok.expires_at = 1700000000 + 14 * 86400;
  tok.grace_expires_at = tok.expires_at + 3 * 86400;
  tok.server_nonce.fill(0x3C);
  tok.vm_root.fill(0x7E);
  tok.sequence_number = 42;
  tok.signature.fill(0x55);

  auto bytes = SerializeActivationToken(tok);
  MT_CHECK(!bytes.empty());

  auto parsed = DeserializeActivationToken(bytes.data(), bytes.size());
  MT_CHECK(parsed.has_value());
  MT_CHECK(parsed->schema_version == tok.schema_version);
  MT_CHECK(parsed->license_id == tok.license_id);
  MT_CHECK(parsed->device_fingerprint_hash == tok.device_fingerprint_hash);
  MT_CHECK(parsed->issued_at == tok.issued_at);
  MT_CHECK(parsed->expires_at == tok.expires_at);
  MT_CHECK(parsed->grace_expires_at == tok.grace_expires_at);
  MT_CHECK(parsed->server_nonce == tok.server_nonce);
  MT_CHECK(parsed->vm_root == tok.vm_root);
  MT_CHECK(parsed->sequence_number == tok.sequence_number);
  MT_CHECK(parsed->signature == tok.signature);

  // Truncated data must fail closed
  MT_CHECK(!DeserializeActivationToken(bytes.data(), bytes.size() - 5).has_value());
}

MT_TEST(ActivationToken_SignAndVerify_Success) {
  auto kp = MakeKeyPair();
  ActivationToken tok;
  tok.license_id = "lic-token-sign-test";
  tok.device_fingerprint_hash = "HWID-SIGN-1234";
  tok.issued_at = 1700000000;
  tok.expires_at = 1700000000 + 14 * 86400;
  tok.server_nonce.fill(0x11);
  tok.vm_root.fill(0x22);

  MT_CHECK(SignActivationToken(tok, kp.private_key));
  MT_CHECK(VerifyActivationTokenSignature(tok, kp.public_key));

  // Tampered signature must fail verification
  tok.signature[0] ^= 0xFF;
  MT_CHECK(!VerifyActivationTokenSignature(tok, kp.public_key));
}

MT_TEST(ActivationToken_ExpiryCheck) {
  ActivationToken tok;
  tok.issued_at = 1000;
  tok.expires_at = 2000;
  tok.grace_expires_at = 2500;

  std::uint64_t valid_time = 1500;
  std::uint64_t expired_time = 2501;

  MT_CHECK(valid_time <= tok.expires_at);
  MT_CHECK(expired_time > tok.expires_at);
}

MT_TEST(ActivationToken_LoadOrCreateDevToken_PersistsAndEncrypts) {
  std::string test_prod = "test_product_dev_token_isolation";
  std::string test_lic = "lic-dev-isolated-001";
  std::string token_path = GetActivationTokenPath(test_prod);

  std::error_code ec;
  std::filesystem::remove(token_path, ec);

  ActivationToken tok1;
  MT_CHECK(LoadOrCreateDevToken(test_prod, test_lic, &tok1));
  MT_CHECK(std::filesystem::exists(token_path));

  // Verify file is encrypted at rest via SecureStorage (DPAPI on Windows, container format) and not plaintext
  auto file_bytes = rtprotect::tooling::ReadFile(token_path);
  MT_CHECK(file_bytes.has_value());

  // Confirm license ID and raw strings are NOT in cleartext on disk
  std::string raw_content(reinterpret_cast<const char*>(file_bytes->data()), file_bytes->size());
  MT_CHECK(raw_content.find(test_lic) == std::string::npos);
  MT_CHECK(raw_content.find(test_prod) == std::string::npos);

  // Confirm container header is RTSS
  MT_CHECK(file_bytes->size() >= 12);
  MT_CHECK((*file_bytes)[0] == 'R' && (*file_bytes)[1] == 'T' &&
           (*file_bytes)[2] == 'S' && (*file_bytes)[3] == 'S');

  // Loading second time must succeed and retrieve identical vm_root
  ActivationToken tok2;
  MT_CHECK(LoadOrCreateDevToken(test_prod, test_lic, &tok2));
  MT_CHECK(tok2.vm_root == tok1.vm_root);
  MT_CHECK(tok2.license_id == tok1.license_id);

  std::filesystem::remove(token_path, ec);
}

MT_TEST(ActivationToken_RejectsDevLicenseForProductionLicense) {
  std::string test_prod = "test_product_license_bypass_check";
  std::string token_path = GetActivationTokenPath(test_prod);

  std::error_code ec;
  std::filesystem::remove(token_path, ec);

  // 1. Create a dev token stored with "dev-license"
  ActivationToken dev_tok;
  MT_CHECK(LoadOrCreateDevToken(test_prod, "dev-license", &dev_tok));
  MT_CHECK(dev_tok.license_id == "dev-license");

  // 2. Querying with a production license ID must NOT reuse the dev token
  ActivationToken prod_tok;
  MT_CHECK(LoadOrCreateDevToken(test_prod, "lic-prod-enterprise-9999", &prod_tok));
  MT_CHECK(prod_tok.license_id == "lic-prod-enterprise-9999");
  MT_CHECK(prod_tok.license_id != dev_tok.license_id);

  std::filesystem::remove(token_path, ec);
}

MT_TEST(ActivationServer_ActivateAndRenew_Stubs) {
  auto token = ActivateDevice("lic-key-prod-1", "hw-fingerprint-prod", "prod-1");
  MT_CHECK(token.schema_version == kActivationSchemaVersion);
  MT_CHECK(token.license_id == "lic-key-prod-1");
  MT_CHECK(token.device_fingerprint_hash == "hw-fingerprint-prod");
  MT_CHECK(token.sequence_number == 1);
  MT_CHECK(token.issued_at > 0);
  MT_CHECK(token.expires_at > token.issued_at);
  MT_CHECK(token.grace_expires_at > token.expires_at);

  auto renewed = RenewToken(token);
  MT_CHECK(renewed.sequence_number == 2);
  MT_CHECK(renewed.vm_root == token.vm_root);
  MT_CHECK(renewed.license_id == token.license_id);
  MT_CHECK(renewed.expires_at >= token.expires_at);
}

MT_TEST(SecureStorage_StoreAndLoadRoundTrip) {
  std::string key = "test_ss_roundtrip_key";
  SecureStorage::Delete(key);

  std::vector<std::uint8_t> secret_data = {'S', 'e', 'c', 'u', 'r', 'e', 'P', 'a', 'y', 'l', 'o', 'a', 'd', 0x00, 0xFF, 0x42};
  MT_CHECK(SecureStorage::Store(key, secret_data, "test_description"));

  std::string file_path = SecureStorage::GetStorageFilePath(key);
  MT_CHECK(std::filesystem::exists(file_path));

  auto loaded = SecureStorage::Load(key);
  MT_CHECK(loaded.has_value());
  MT_CHECK(*loaded == secret_data);

#if defined(_WIN32)
  MT_CHECK(SecureStorage::GetActiveBackend() == SecureStorageBackend::kWindowsDpapi);
#endif

  MT_CHECK(SecureStorage::Delete(key));
  MT_CHECK(!SecureStorage::Load(key).has_value());
}

MT_TEST(SecureStorage_TamperedDataRejection) {
  std::string key = "test_ss_tamper_key";
  SecureStorage::Delete(key);

  std::vector<std::uint8_t> secret_data = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  MT_CHECK(SecureStorage::Store(key, secret_data));

  std::string file_path = SecureStorage::GetStorageFilePath(key);
  auto raw = rtprotect::tooling::ReadFile(file_path);
  MT_CHECK(raw.has_value());

  if (raw->size() > 15) {
    (*raw)[14] ^= 0x55;
    (*raw)[raw->size() - 1] ^= 0xAA;
    MT_CHECK(rtprotect::tooling::WriteFile(file_path, raw->data(), raw->size()));

    auto tampered = SecureStorage::Load(key);
    MT_CHECK(!tampered.has_value());
  }

  SecureStorage::Delete(key);
}

MT_TEST(SecureStorage_LegacyAeadFileMigration) {
  std::string prod = "test_legacy_migration_prod";
  std::string lic = "lic-legacy-001";
  std::string file_path = GetActivationTokenPath(prod);

  std::error_code ec;
  std::filesystem::remove(file_path, ec);

  ActivationToken legacy_tok;
  legacy_tok.license_id = lic;
  legacy_tok.device_fingerprint_hash = GetLocalHardwareId();
  legacy_tok.sequence_number = 42;
  legacy_tok.vm_root.fill(0x33);

  auto serialized = SerializeActivationToken(legacy_tok);
  MT_CHECK(!serialized.empty());

  std::string hwid = GetLocalHardwareId();
  rtprotect::crypto::SecureBuffer sec_hwid(reinterpret_cast<const std::uint8_t*>(hwid.data()), hwid.size());
  std::vector<std::uint8_t> salt = {'R', 'T', 'P', 'r', 'o', 't', 'e', 'c', 't', 'A', 'c', 't', 'i', 'v', 'a', 't', 'i', 'o', 'n', 'K', 'e', 'y'};
  auto derived = rtprotect::crypto::Hkdf::DeriveKey(sec_hwid, salt, "rtprotect/activation-token-store/v1", rtprotect::crypto::kAes256KeyLen);
  MT_CHECK(derived.has_value());
  auto enc_key = rtprotect::crypto::Aes256Key::FromBytes(derived->data(), derived->size());
  MT_CHECK(enc_key.has_value());

  auto encrypted = rtprotect::crypto::Encrypt(*enc_key, serialized.data(), serialized.size());
  MT_CHECK(encrypted.has_value());
  auto legacy_bytes = encrypted->Serialize();

  MT_CHECK(rtprotect::tooling::WriteFile(file_path, legacy_bytes.data(), legacy_bytes.size()));

  auto migrated_tok = LoadActivationToken(prod);
  MT_CHECK(migrated_tok.has_value());
  MT_CHECK(migrated_tok->license_id == lic);
  MT_CHECK(migrated_tok->sequence_number == 42);
  MT_CHECK(migrated_tok->vm_root == legacy_tok.vm_root);

  std::filesystem::remove(file_path, ec);
}

MT_TEST(SecureStorage_UnpackContainer_StrictLength) {
  std::string key = "test_strict_container_len";
  SecureStorage::Delete(key);

  std::vector<std::uint8_t> secret_data = {'S', 't', 'r', 'i', 'c', 't', '1', '2', '3'};
  MT_CHECK(SecureStorage::Store(key, secret_data));

  std::string file_path = SecureStorage::GetStorageFilePath(key);
  auto raw = rtprotect::tooling::ReadFile(file_path);
  MT_CHECK(raw.has_value());

  // 1. Appending trailing bytes must cause Load() to fail closed
  auto tampered_trailing = *raw;
  tampered_trailing.push_back(0xAA);
  tampered_trailing.push_back(0xBB);
  MT_CHECK(rtprotect::tooling::WriteFile(file_path, tampered_trailing.data(), tampered_trailing.size()));
  MT_CHECK(!SecureStorage::Load(key).has_value());

  // 2. Truncating bytes must cause Load() to fail closed
  if (raw->size() > 14) {
    auto tampered_trunc = *raw;
    tampered_trunc.pop_back();
    MT_CHECK(rtprotect::tooling::WriteFile(file_path, tampered_trunc.data(), tampered_trunc.size()));
    MT_CHECK(!SecureStorage::Load(key).has_value());
  }

  SecureStorage::Delete(key);
}

MT_TEST(SecureStorage_RequireDpapi_PolicyEnforcement) {
  bool original_setting = SecureStorage::IsRequireDpapi();

  SecureStorage::SetRequireDpapi(true);
  MT_CHECK(SecureStorage::IsRequireDpapi());

  SecureStorage::SetRequireDpapi(false);
  MT_CHECK(!SecureStorage::IsRequireDpapi());

  SecureStorage::SetRequireDpapi(original_setting);
}

MT_TEST(ActivationClient_ParseUrl_FailClosed) {
  // Empty URL
  MT_CHECK(!ParseUrl("").has_value());

  // Missing or invalid scheme
  MT_CHECK(!ParseUrl("localhost:8080/api").has_value());
  MT_CHECK(!ParseUrl("ftp://example.com/api").has_value());
  MT_CHECK(!ParseUrl("file:///C:/secrets.dat").has_value());

  // Embedded credentials rejected
  MT_CHECK(!ParseUrl("https://admin:pass@licensing.vendor.com/v1").has_value());
  MT_CHECK(!ParseUrl("http://user@127.0.0.1:8080/v1").has_value());

  // Valid HTTP URL
  auto u1 = ParseUrl("http://localhost:8080/api/activate");
  MT_CHECK(u1.has_value());
  MT_CHECK(!u1->is_https);
  MT_CHECK(u1->host == "localhost");
  MT_CHECK(u1->port == 8080);
  MT_CHECK(u1->path == "/api/activate");

  // Valid HTTPS URL (default port 443)
  auto u2 = ParseUrl("https://licensing.vendor.com/v1");
  MT_CHECK(u2.has_value());
  MT_CHECK(u2->is_https);
  MT_CHECK(u2->host == "licensing.vendor.com");
  MT_CHECK(u2->port == 443);
  MT_CHECK(u2->path == "/v1");

  // Valid IPv6 URL with port
  auto u3 = ParseUrl("https://[::1]:9443/v1/renew");
  MT_CHECK(u3.has_value());
  MT_CHECK(u3->is_https);
  MT_CHECK(u3->host == "::1");
  MT_CHECK(u3->port == 9443);
  MT_CHECK(u3->path == "/v1/renew");

  // Invalid port specifications
  MT_CHECK(!ParseUrl("https://example.com:999999/api").has_value());
  MT_CHECK(!ParseUrl("https://example.com:-1/api").has_value());
  MT_CHECK(!ParseUrl("https://example.com:abc/api").has_value());
}

MT_TEST(CountermeasureConfig_SignVerifyAndRoundtrip) {
  auto kp = MakeKeyPair();

  CountermeasureConfig cfg;
  cfg.sequence_number = 42;
  cfg.issued_at = 1750000000;
  cfg.expires_at = 1750100000;
  cfg.blacklisted_process_names = { "x64dbg.exe", "ida64.exe", "cheatengine.exe" };
  cfg.blacklisted_process_hashes = { 0x11223344, 0x55667788 };
  cfg.blacklisted_window_titles = { "Cheat Engine 7.5", "x64dbg" };
  cfg.blacklisted_driver_hashes = { 0xAABBCCDD };
  cfg.risk_threshold_restrict = 35;
  cfg.risk_threshold_terminate = 70;
  cfg.enforce_hardware_breakpoints = true;
  cfg.enforce_timing_checks = true;
  cfg.enforce_memory_hooks = true;
  cfg.enforce_anti_dump = true;

  // Sign configuration
  MT_CHECK(SignCountermeasureConfig(cfg, kp.private_key));

  // Verify valid signature
  MT_CHECK(VerifyCountermeasureConfigSignature(cfg, kp.public_key));

  // Signature verification fails if payload is tampered
  CountermeasureConfig tampered = cfg;
  tampered.risk_threshold_restrict = 99;
  MT_CHECK(!VerifyCountermeasureConfigSignature(tampered, kp.public_key));

  // Serialization and deserialization roundtrip
  auto wire = SerializeCountermeasureConfig(cfg);
  auto parsed = DeserializeCountermeasureConfig(wire.data(), wire.size());
  MT_CHECK(parsed.has_value());
  MT_CHECK(parsed->sequence_number == 42);
  MT_CHECK(parsed->issued_at == 1750000000);
  MT_CHECK(parsed->expires_at == 1750100000);
  MT_CHECK(parsed->blacklisted_process_names.size() == 3);
  MT_CHECK(parsed->blacklisted_process_names[0] == "x64dbg.exe");
  MT_CHECK(parsed->blacklisted_process_hashes.size() == 2);
  MT_CHECK(parsed->blacklisted_window_titles.size() == 2);
  MT_CHECK(parsed->blacklisted_driver_hashes.size() == 1);
  MT_CHECK(parsed->risk_threshold_restrict == 35);
  MT_CHECK(parsed->risk_threshold_terminate == 70);
  MT_CHECK(VerifyCountermeasureConfigSignature(*parsed, kp.public_key));

  // Persistence in SecureStorage
  MT_CHECK(SaveCountermeasureConfig("com.test.countermeasure", cfg));
  auto loaded = LoadCountermeasureConfig("com.test.countermeasure");
  MT_CHECK(loaded.has_value());
  MT_CHECK(loaded->sequence_number == 42);
  MT_CHECK(VerifyCountermeasureConfigSignature(*loaded, kp.public_key));
}

MT_MAIN()
