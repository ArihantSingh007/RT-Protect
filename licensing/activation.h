// licensing/activation.h
//
// Online activation ticket client-side request generation, ticket deserialization,
// signature verification, and temporal/hardware validation.
//
// Short-lived activation tickets bind an authorized license to a specific device
// for a bounded temporal window (e.g. 24 hours to 7 days), enabling dynamic
// concurrency caps and instant server-side revocation.

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "integrity/keys.h"
#include "licensing/hardware_id.h"

namespace rtprotect::licensing {

inline constexpr std::uint32_t kActivationRequestMagic = 0x52545051;  // 'RTPQ'
inline constexpr std::uint32_t kActivationTicketMagic  = 0x52545054;  // 'RTPT'
inline constexpr std::uint32_t kActivationTokenMagic   = 0x5254504B;  // 'RTPK'
inline constexpr std::uint32_t kActivationSchemaVersion = 1;
inline constexpr std::size_t kMaxActivationFieldLen = 512;
inline constexpr std::size_t kActivationNonceLen = 32;
inline constexpr std::size_t kActivationSessionKeyLen = 32;

enum class ActivationStatus {
  kValid = 0,
  kInvalidSignature,
  kExpired,
  kNotYetValid,
  kRevoked,
  kHardwareMismatch,
  kLicenseMismatch,
  kNonceMismatch,
  kConcurrencyLimitExceeded,
  kMalformed,
  kClockRollbackDetected
};

const char* ToString(ActivationStatus status);

struct ActivationRequest {
  std::uint32_t schema_version = kActivationSchemaVersion;
  std::string request_id;                                // Unique request identifier
  std::string license_id;                                // Bound license ID
  std::string hardware_id;                               // Requesting device HWID
  std::string app_version;                               // E.g. "2.0.0"
  std::uint64_t client_timestamp = 0;                    // Unix timestamp seconds
  std::array<std::uint8_t, kActivationNonceLen> nonce{}; // Cryptographic challenge nonce
};

struct ActivationTicket {
  std::uint32_t schema_version = kActivationSchemaVersion;
  std::string ticket_id;                                            // Unique ticket ID
  std::string license_id;                                           // Authorized license ID
  std::string hardware_id;                                          // Authorized device HWID
  std::uint64_t issued_at = 0;                                      // Unix timestamp seconds
  std::uint64_t expires_at = 0;                                     // Unix timestamp seconds
  std::array<std::uint8_t, kActivationNonceLen> nonce{};            // Mirrored challenge nonce
  std::array<std::uint8_t, kActivationSessionKeyLen> session_key{}; // Session encryption key
  std::string metadata;                                             // Optional ticket payload
  integrity::Ed25519Signature signature{};                          // Ed25519 vendor signature
};

// Generates an activation request with a cryptographically secure random nonce.
ActivationRequest CreateActivationRequest(const std::string& license_id,
                                          const std::string& hardware_id,
                                          const std::string& app_version = "1.0.0",
                                          std::uint64_t client_timestamp = 0);

// Serialization and deserialization for wire protocol
std::vector<std::uint8_t> SerializeActivationRequest(const ActivationRequest& req);
std::optional<ActivationRequest> DeserializeActivationRequest(const std::uint8_t* data, std::size_t len);

std::vector<std::uint8_t> SerializeActivationTicketForSigning(const ActivationTicket& ticket);
std::vector<std::uint8_t> SerializeActivationTicket(const ActivationTicket& ticket);
std::optional<ActivationTicket> DeserializeActivationTicket(const std::uint8_t* data, std::size_t len);

// Human-readable / JSON-like text export/import
std::string ActivationRequestToText(const ActivationRequest& req);
std::optional<ActivationRequest> ActivationRequestFromText(const std::string& text);

std::string ActivationTicketToText(const ActivationTicket& ticket);
std::optional<ActivationTicket> ActivationTicketFromText(const std::string& text);

// Client-side verification of an activation ticket against public key, expected request,
// and current system clock.
ActivationStatus VerifyActivationTicket(const ActivationTicket& ticket,
                                        const integrity::Ed25519PublicKey& pubkey,
                                        const ActivationRequest& req,
                                        std::uint64_t current_time,
                                        double min_hw_match_score = 0.75,
                                        const HardwareSimilarityWeights* hw_weights = nullptr);

// Local installation-bound activation token containing vm_root.
// Kept in encrypted local token storage, never exposed in cleartext manifests or .rodata.
struct ActivationToken {
  std::uint32_t schema_version = kActivationSchemaVersion;
  std::string license_id;
  std::string device_fingerprint_hash;
  std::uint64_t issued_at = 0;
  std::uint64_t expires_at = 0;
  std::uint64_t grace_expires_at = 0;
  std::array<std::uint8_t, 32> server_nonce{};
  std::array<std::uint8_t, 32> vm_root{};
  std::uint64_t sequence_number = 1;
  integrity::Ed25519Signature signature{};
};

// Activation token wire serialization / deserialization / cryptographic verification
std::vector<std::uint8_t> SerializeActivationTokenForSigning(const ActivationToken& token);
std::vector<std::uint8_t> SerializeActivationToken(const ActivationToken& token);
std::optional<ActivationToken> DeserializeActivationToken(const std::uint8_t* data, std::size_t len);

bool VerifyActivationTokenSignature(const ActivationToken& token, const integrity::Ed25519PublicKey& pubkey);

// Local activation token store path resolution and dev token loader/creator
std::string GetActivationTokenPath(const std::string& product_id);
bool LoadOrCreateDevToken(const std::string& product_id,
                          const std::string& license_id,
                          ActivationToken* out_token);

}  // namespace rtprotect::licensing
