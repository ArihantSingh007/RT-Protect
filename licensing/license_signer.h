// licensing/license_signer.h
//
// Buildtools / server-side only: generates digital signatures for licenses.
// NEVER linked into client-distributed applications.

#pragma once

#include "integrity/keys.h"
#include "licensing/license.h"

namespace rtprotect::licensing {

// Signs `license` using the vendor's private key and populates `license.signature`.
// Returns true on success, false if key is invalid or signing failed.
bool SignLicense(License& license, const integrity::Ed25519PrivateKey& privkey);

}  // namespace rtprotect::licensing
