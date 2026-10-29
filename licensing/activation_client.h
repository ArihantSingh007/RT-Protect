// licensing/activation_client.h
//
// Client-side online activation transport and response verification.
// Communicates with RTProtect Activation Authority over HTTP/HTTPS,
// decrypts ephemeral transport payloads, and verifies Ed25519 vendor signatures.

#pragma once

#include <optional>
#include <string>

#include "integrity/keys.h"
#include "licensing/activation.h"

namespace rtprotect::licensing {

struct ParsedUrl {
  bool is_https = false;
  std::string host;
  std::uint16_t port = 80;
  std::string path = "/";
};

// Parses and validates an HTTP/HTTPS authority URL, failing closed on invalid syntax,
// missing protocols, or embedded authentication credentials.
std::optional<ParsedUrl> ParseUrl(const std::string& url_str);

// Requests online device activation from the vendor authority server.
// Returns an installation-bound ActivationToken containing the authorized vm_root.
std::optional<ActivationToken> RequestOnlineActivation(
    const std::string& server_url,
    const std::string& license_key,
    const std::string& product_id,
    const integrity::Ed25519PublicKey& vendor_pubkey,
    std::string* error_out = nullptr,
    const std::string& activation_credential = "",
    std::uint64_t client_timestamp = 0,
    const integrity::Ed25519PublicKey* cm_pubkey = nullptr);

// Requests a pre-authorized time-boxed offline token grant from the vendor authority server while online.
// offline_days is bounded between 1 and 30 days (default 14 days).
// The returned token is verified with vendor_pubkey, saved locally via SaveActivationToken,
// and permits offline runtime authorization until expires_at without network connectivity.
std::optional<ActivationToken> RequestOfflineGrant(
    const std::string& server_url,
    const std::string& license_key,
    const std::string& product_id,
    const integrity::Ed25519PublicKey& vendor_pubkey,
    std::uint32_t offline_days = 14,
    std::string* error_out = nullptr,
    const std::string& activation_credential = "",
    std::uint64_t client_timestamp = 0,
    const integrity::Ed25519PublicKey* cm_pubkey = nullptr);

// Requests online token lease renewal from the vendor authority server.
// Returns renewed token with bumped expiration and identical vm_root.
std::optional<ActivationToken> RequestOnlineRenewal(
    const std::string& server_url,
    const ActivationToken& current_token,
    const integrity::Ed25519PublicKey& vendor_pubkey,
    std::string* error_out = nullptr,
    const std::string& product_id = "",
    const integrity::Ed25519PublicKey* cm_pubkey = nullptr);

// Requests voluntary seat deactivation, freeing up the seat on the server.
bool RequestOnlineDeactivation(
    const std::string& server_url,
    const ActivationToken& current_token,
    std::string* error_out = nullptr);

}  // namespace rtprotect::licensing
