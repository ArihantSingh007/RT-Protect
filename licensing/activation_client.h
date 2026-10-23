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

// Requests online device activation from the vendor authority server.
// Returns an installation-bound ActivationToken containing the authorized vm_root.
std::optional<ActivationToken> RequestOnlineActivation(
    const std::string& server_url,
    const std::string& license_key,
    const std::string& product_id,
    const integrity::Ed25519PublicKey& vendor_pubkey,
    std::string* error_out = nullptr,
    const std::string& activation_credential = "",
    std::uint64_t client_timestamp = 0);

// Requests online token lease renewal from the vendor authority server.
// Returns renewed token with bumped expiration and identical vm_root.
std::optional<ActivationToken> RequestOnlineRenewal(
    const std::string& server_url,
    const ActivationToken& current_token,
    const integrity::Ed25519PublicKey& vendor_pubkey,
    std::string* error_out = nullptr);

// Requests voluntary seat deactivation, freeing up the seat on the server.
bool RequestOnlineDeactivation(
    const std::string& server_url,
    const ActivationToken& current_token,
    std::string* error_out = nullptr);

}  // namespace rtprotect::licensing
