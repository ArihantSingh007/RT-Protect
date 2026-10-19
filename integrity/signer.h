// integrity/signer.h
//
// BUILD-TIME ONLY. Nothing in this file should be linked into, or run as
// part of, the distributed client application -- it exists for an offline
// release-signing tool (Phase 7's `tooling/` CLI will call this) and for
// test fixtures that need a validly-signed manifest. See keys.h's file
// header and docs/THREAT_MODEL.md §7 for why this boundary matters: the
// private key this function consumes must never be reachable by the
// adversary this project's threat model assumes, which means it must never
// be reachable by the shipped binary at all.

#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "integrity/keys.h"

namespace rtprotect::integrity {

// Signs `manifest_bytes` (the output of SerializeManifest) with `private_key`.
// Returns the 64-byte Ed25519 signature, or std::nullopt on an internal
// OpenSSL failure.
std::optional<std::array<std::uint8_t, kEd25519SignatureLen>> SignManifestBytes(
    const std::vector<std::uint8_t>& manifest_bytes, const Ed25519PrivateKey& private_key);

}  // namespace rtprotect::integrity
