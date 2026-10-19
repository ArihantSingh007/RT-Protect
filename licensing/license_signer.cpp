// licensing/license_signer.cpp

#include "licensing/license_signer.h"
#include "integrity/signer.h"

namespace rtprotect::licensing {

bool SignLicense(License& license, const integrity::Ed25519PrivateKey& privkey) {
  auto bytes_to_sign = SerializeLicenseForSigning(license);
  auto sig = integrity::SignManifestBytes(bytes_to_sign, privkey);
  if (!sig.has_value()) return false;
  license.signature = *sig;
  return true;
}

}  // namespace rtprotect::licensing
