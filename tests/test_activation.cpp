// tests/test_activation.cpp

#include "licensing/activation.h"
#include "licensing/activation_server.h"
#include "integrity/keys.h"
#include "tests/micro_test.h"

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

MT_MAIN()
