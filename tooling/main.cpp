// tooling/main.cpp
//
// rtprotect-tool: a command-line driver for the library built in Phases
// 1-4, so the project has an actual executable that exercises key
// generation, signing, manifest building/verification, and resource
// encryption against real files on disk -- not only from unit tests.
//
// NOTE ON SCOPE: this tool itself is a developer/release-pipeline
// utility, analogous to `openssl`'s CLI bundling both "generate a private
// key" and "verify a signature" in one binary. The trust boundary this
// project cares about (see integrity/CMakeLists.txt's header comment and
// docs/THREAT_MODEL.md §7) is about what the DISTRIBUTED APPLICATION
// embeds -- examples/protected_checksum.h never links
// rtprotect_integrity_buildtools, and that boundary is unaffected by this
// tool also existing. This tool is not meant to be shipped as part of any
// protected application; it's run by a developer/release pipeline, the
// same way a release engineer runs `openssl` or `signtool` locally without
// those tools becoming part of the product being signed.

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <openssl/crypto.h>

#include "crypto/aead.h"
#include "integrity/keys.h"
#include "integrity/manifest.h"
#include "integrity/sha256.h"
#include "integrity/signer.h"
#include "integrity/verifier.h"
#include "tooling/file_io.h"

using namespace rtprotect;
using namespace rtprotect::tooling;

namespace {

void PrintUsage() {
  std::fprintf(stderr,
      "rtprotect-tool -- rtprotect project CLI (developer/release-pipeline tool)\n\n"
      "Usage:\n"
      "  rtprotect-tool genkey-ed25519 <priv-out> <pub-out>\n"
      "  rtprotect-tool genkey-aes <key-out>\n"
      "  rtprotect-tool hash <file>\n"
      "  rtprotect-tool encrypt <key-file> <input-file> <output-file>\n"
      "  rtprotect-tool decrypt <key-file> <input-file> <output-file>\n"
      "  rtprotect-tool manifest-build <manifest-out> <version> <resource-name>=<resource-file> [...]\n"
      "  rtprotect-tool manifest-sign <manifest-file> <priv-key-file> <signature-out>\n"
      "  rtprotect-tool manifest-verify <manifest-file> <signature-file> <pub-key-file> <resource-name> <resource-file>\n");
}

int CmdGenkeyEd25519(int argc, char** argv) {
  if (argc != 4) { PrintUsage(); return 2; }
  auto kp = integrity::GenerateEd25519KeyPair();
  if (!kp.has_value()) {
    std::fprintf(stderr, "error: key generation failed\n");
    return 1;
  }
  if (!WriteSecretFile(argv[2], kp->private_key.data(), kp->private_key.size()) ||
      !WriteFile(argv[3], kp->public_key.data(), kp->public_key.size())) {
    std::fprintf(stderr, "error: failed to write key file(s)\n");
    return 1;
  }
  std::fprintf(stderr,
      "Wrote Ed25519 keypair.\n"
      "  Private key: %s  -- KEEP OFFLINE. Never embed in, or ship as part of,\n"
      "                     a distributed application (see docs/THREAT_MODEL.md Sec.7).\n"
      "  Public key:  %s  -- safe to embed in a client application.\n",
      argv[2], argv[3]);
  return 0;
}

int CmdGenkeyAes(int argc, char** argv) {
  if (argc != 3) { PrintUsage(); return 2; }
  auto key = crypto::Aes256Key::Generate();
  if (!WriteSecretFile(argv[2], key.bytes().data(), key.bytes().size())) {
    std::fprintf(stderr, "error: failed to write key file\n");
    return 1;
  }
  std::fprintf(stderr, "Wrote AES-256 key: %s -- keep this secret.\n", argv[2]);
  return 0;
}

int CmdHash(int argc, char** argv) {
  if (argc != 3) { PrintUsage(); return 2; }
  auto data = ReadFile(argv[2]);
  if (!data.has_value()) {
    std::fprintf(stderr, "error: could not read %s\n", argv[2]);
    return 1;
  }
  auto digest = integrity::Sha256(data->data(), data->size());
  if (!digest.has_value()) {
    std::fprintf(stderr, "error: hashing failed\n");
    return 1;
  }
  std::printf("%s  %s\n", ToHex(digest->data(), digest->size()).c_str(), argv[2]);
  return 0;
}

int CmdEncrypt(int argc, char** argv) {
  if (argc != 5) { PrintUsage(); return 2; }
  auto key_bytes = ReadFile(argv[2]);
  auto plaintext = ReadFile(argv[3]);
  if (!key_bytes.has_value() || !plaintext.has_value()) {
    std::fprintf(stderr, "error: could not read key or input file\n");
    return 1;
  }
  auto key = crypto::Aes256Key::FromBytes(key_bytes->data(), key_bytes->size());
  // Wipe the raw key bytes read from disk now that they've been copied
  // into the wipe-on-destroy crypto::Aes256Key/SecureBuffer -- same
  // reasoning as the Ed25519 private-key fix in CmdManifestSign above.
  // Done unconditionally (both success and failure of FromBytes), per the
  // project's standing rule to wipe temporary secret data on every path,
  // not only the success path.
  if (!key_bytes->empty()) OPENSSL_cleanse(key_bytes->data(), key_bytes->size());
  if (!key.has_value()) {
    std::fprintf(stderr, "error: key file is not exactly %zu bytes\n", crypto::kAes256KeyLen);
    return 1;
  }
  auto enc = crypto::Encrypt(*key, plaintext->data(), plaintext->size());
  if (!enc.has_value()) {
    std::fprintf(stderr, "error: encryption failed\n");
    return 1;
  }
  auto wire = enc->Serialize();
  if (!WriteFile(argv[4], wire)) {
    std::fprintf(stderr, "error: could not write output file\n");
    return 1;
  }
  std::fprintf(stderr, "Encrypted %s -> %s (%zu bytes plaintext, %zu bytes ciphertext blob)\n",
               argv[3], argv[4], plaintext->size(), wire.size());
  return 0;
}

int CmdDecrypt(int argc, char** argv) {
  if (argc != 5) { PrintUsage(); return 2; }
  auto key_bytes = ReadFile(argv[2]);
  auto blob = ReadFile(argv[3]);
  if (!key_bytes.has_value() || !blob.has_value()) {
    std::fprintf(stderr, "error: could not read key or input file\n");
    return 1;
  }
  auto key = crypto::Aes256Key::FromBytes(key_bytes->data(), key_bytes->size());
  if (!key_bytes->empty()) OPENSSL_cleanse(key_bytes->data(), key_bytes->size());
  if (!key.has_value()) {
    std::fprintf(stderr, "error: key file is not exactly %zu bytes\n", crypto::kAes256KeyLen);
    return 1;
  }
  auto msg = crypto::EncryptedMessage::Deserialize(blob->data(), blob->size());
  if (!msg.has_value()) {
    std::fprintf(stderr, "error: input file is not a valid encrypted blob\n");
    return 1;
  }
  crypto::AeadError aead_err = crypto::AeadError::kNone;
  auto plaintext = crypto::Decrypt(*key, *msg, nullptr, 0, &aead_err);
  if (!plaintext.has_value()) {
    std::fprintf(stderr, "error: decryption failed: %s\n", crypto::ToString(aead_err));
    return 1;
  }
  if (!WriteFile(argv[4], *plaintext)) {
    std::fprintf(stderr, "error: could not write output file\n");
    return 1;
  }
  std::fprintf(stderr, "Decrypted %s -> %s (%zu bytes)\n", argv[3], argv[4], plaintext->size());
  return 0;
}

int CmdManifestBuild(int argc, char** argv) {
  if (argc < 5) { PrintUsage(); return 2; }
  integrity::Manifest manifest;
  manifest.release_version = argv[3];

  for (int i = 4; i < argc; ++i) {
    std::string arg = argv[i];
    auto eq = arg.find('=');
    if (eq == std::string::npos) {
      std::fprintf(stderr, "error: expected <resource-name>=<resource-file>, got '%s'\n",
                   arg.c_str());
      return 2;
    }
    std::string name = arg.substr(0, eq);
    std::string path = arg.substr(eq + 1);
    auto data = ReadFile(path);
    if (!data.has_value()) {
      std::fprintf(stderr, "error: could not read resource file %s\n", path.c_str());
      return 1;
    }
    if (!manifest.AddResource(name, data->data(), data->size())) {
      std::fprintf(stderr, "error: could not add resource %s to manifest\n", name.c_str());
      return 1;
    }
    std::fprintf(stderr, "  added %-20s %8zu bytes  sha256=%s\n", name.c_str(), data->size(),
                 ToHex(manifest.Find(name)->sha256.data(), manifest.Find(name)->sha256.size())
                     .c_str());
  }

  auto wire = integrity::SerializeManifest(manifest);
  if (!WriteFile(argv[2], wire)) {
    std::fprintf(stderr, "error: could not write manifest file\n");
    return 1;
  }
  std::fprintf(stderr, "Wrote manifest %s (version %s, %zu resource(s), %zu bytes)\n", argv[2],
               manifest.release_version.c_str(), manifest.resources.size(), wire.size());
  return 0;
}

int CmdManifestSign(int argc, char** argv) {
  if (argc != 5) { PrintUsage(); return 2; }
  auto manifest_bytes = ReadFile(argv[2]);
  auto priv_bytes = ReadFile(argv[3]);
  if (!manifest_bytes.has_value() || !priv_bytes.has_value()) {
    std::fprintf(stderr, "error: could not read manifest or private key file\n");
    return 1;
  }
  auto priv = integrity::Ed25519PrivateKey::FromBytes(priv_bytes->data(), priv_bytes->size());
  // Wipe the raw bytes read from disk now that they've been copied into
  // the wipe-on-destroy Ed25519PrivateKey -- `priv_bytes` is an ordinary
  // std::vector<uint8_t> (from ReadFile(), which has no reason to be
  // secret-aware for its many non-secret callers, e.g. reading a
  // manifest) and would otherwise sit, unwiped, in whatever heap memory
  // it occupies for the rest of this function's stack frame and beyond,
  // once freed.
  if (!priv_bytes->empty()) OPENSSL_cleanse(priv_bytes->data(), priv_bytes->size());
  if (!priv.has_value()) {
    std::fprintf(stderr, "error: private key file is not exactly %zu bytes\n",
                 integrity::kEd25519PrivateKeyLen);
    return 1;
  }

  auto sig = integrity::SignManifestBytes(*manifest_bytes, *priv);
  if (!sig.has_value()) {
    std::fprintf(stderr, "error: signing failed\n");
    return 1;
  }
  if (!WriteFile(argv[4], sig->data(), sig->size())) {
    std::fprintf(stderr, "error: could not write signature file\n");
    return 1;
  }
  std::fprintf(stderr, "Signed %s -> %s\n", argv[2], argv[4]);
  return 0;
}

int CmdManifestVerify(int argc, char** argv) {
  if (argc != 7) { PrintUsage(); return 2; }
  auto manifest_bytes = ReadFile(argv[2]);
  auto sig_bytes = ReadFile(argv[3]);
  auto pub_bytes = ReadFile(argv[4]);
  std::string resource_name = argv[5];
  auto resource_bytes = ReadFile(argv[6]);

  if (!manifest_bytes.has_value() || !sig_bytes.has_value() || !pub_bytes.has_value() ||
      !resource_bytes.has_value()) {
    std::fprintf(stderr, "error: could not read one or more input files\n");
    return 1;
  }
  if (sig_bytes->size() != integrity::kEd25519SignatureLen) {
    std::fprintf(stderr, "error: signature file is not exactly %zu bytes\n",
                 integrity::kEd25519SignatureLen);
    return 1;
  }
  if (pub_bytes->size() != integrity::kEd25519PublicKeyLen) {
    std::fprintf(stderr, "error: public key file is not exactly %zu bytes\n",
                 integrity::kEd25519PublicKeyLen);
    return 1;
  }

  std::array<std::uint8_t, integrity::kEd25519SignatureLen> sig;
  std::copy(sig_bytes->begin(), sig_bytes->end(), sig.begin());
  integrity::Ed25519PublicKey pub;
  std::copy(pub_bytes->begin(), pub_bytes->end(), pub.begin());

  auto err = integrity::VerifyAndCheckResource(*manifest_bytes, sig, pub, resource_name,
                                                resource_bytes->data(), resource_bytes->size());
  if (err != integrity::IntegrityError::kNone) {
    std::fprintf(stderr, "FAILED: %s\n", integrity::ToString(err));
    return 1;
  }
  std::fprintf(stderr, "OK: %s matches the signed manifest.\n", resource_name.c_str());
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    PrintUsage();
    return 2;
  }
  std::string cmd = argv[1];

  if (cmd == "genkey-ed25519") return CmdGenkeyEd25519(argc, argv);
  if (cmd == "genkey-aes") return CmdGenkeyAes(argc, argv);
  if (cmd == "hash") return CmdHash(argc, argv);
  if (cmd == "encrypt") return CmdEncrypt(argc, argv);
  if (cmd == "decrypt") return CmdDecrypt(argc, argv);
  if (cmd == "manifest-build") return CmdManifestBuild(argc, argv);
  if (cmd == "manifest-sign") return CmdManifestSign(argc, argv);
  if (cmd == "manifest-verify") return CmdManifestVerify(argc, argv);

  std::fprintf(stderr, "error: unknown command '%s'\n\n", cmd.c_str());
  PrintUsage();
  return 2;
}
