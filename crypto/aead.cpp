#include "crypto/aead.h"

#include <cstring>
#include <stdexcept>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace rtprotect::crypto {

namespace {

// RAII wrapper so every early-return path still frees the EVP_CIPHER_CTX.
struct CipherCtx {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  ~CipherCtx() {
    if (ctx) EVP_CIPHER_CTX_free(ctx);
  }
};

// Wipes `buf` via OPENSSL_cleanse on destruction UNLESS Release() has been
// called. Exists so every exit path out of Decrypt() -- not just the one
// the original implementation remembered to guard -- reliably wipes any
// partially- or fully-decrypted (but not yet authenticated) plaintext
// before it's discarded, per the project's "use RAII and focused
// abstractions rather than scattering fragile manual cleanup calls"
// standard (see crypto/secure_buffer.h for the same principle applied to
// buffer ownership). A hand-maintained OPENSSL_cleanse() call at the top
// of every failure branch is exactly the kind of fragile pattern this
// class replaces: it's easy to add a new failure branch later and forget
// the cleanse call, which is precisely what happened in this file's
// earlier version (two of three Decrypt() failure paths after
// EVP_DecryptUpdate had already written data into `plaintext` did not
// wipe it before returning).
class PlaintextWipeGuard {
 public:
  explicit PlaintextWipeGuard(std::vector<std::uint8_t>& buf) : buf_(&buf) {}
  ~PlaintextWipeGuard() {
    if (buf_ && !buf_->empty()) OPENSSL_cleanse(buf_->data(), buf_->size());
  }
  PlaintextWipeGuard(const PlaintextWipeGuard&) = delete;
  PlaintextWipeGuard& operator=(const PlaintextWipeGuard&) = delete;

  // Call on the success path: the caller is taking ownership of the
  // (now-authenticated) plaintext, so the guard must not wipe it.
  void Release() { buf_ = nullptr; }

 private:
  std::vector<std::uint8_t>* buf_;
};

// Returns `ptr + offset`, except returns nullptr untouched when ptr is
// nullptr -- avoids forming `nullptr + 0`, which is pointer arithmetic on
// a null pointer. Whether `(T*)nullptr + 0` is itself undefined behavior
// has been debated across C++ standard revisions, and no sanitizer
// available in this project's build/test environment flags it in practice
// (checked empirically with `-fsanitize=undefined -fsanitize=pointer-overflow`
// against this exact pattern before writing this guard), but forming it is
// trivially avoidable, so this project does, rather than relying on it
// happening to be harmless on every toolchain this code might ever be
// compiled with.
std::uint8_t* SafeOffset(std::uint8_t* ptr, int offset) {
  return ptr ? ptr + offset : nullptr;
}

}  // namespace

const char* ToString(AeadError error) {
  switch (error) {
    case AeadError::kNone:
      return "none";
    case AeadError::kInvalidKeyLength:
      return "invalid key length (must be 32 bytes)";
    case AeadError::kInvalidNonceLength:
      return "invalid nonce length (must be 12 bytes)";
    case AeadError::kInputTooShort:
      return "ciphertext shorter than authentication tag";
    case AeadError::kAuthenticationFailed:
      return "authentication failed: ciphertext, AAD, or key is wrong";
    case AeadError::kOpenSslInternalError:
      return "internal OpenSSL error";
    case AeadError::kMessageTooLarge:
      return "plaintext, ciphertext, or AAD exceeds kMaxAeadMessageLen";
  }
  return "unknown AeadError";
}

std::optional<Aes256Key> Aes256Key::FromBytes(const std::uint8_t* data,
                                               std::size_t len) {
  if (len != kAes256KeyLen || data == nullptr) {
    return std::nullopt;
  }
  return Aes256Key(SecureBuffer(data, len));
}

Aes256Key Aes256Key::Generate() {
  SecureBuffer buf(kAes256KeyLen);
  if (RAND_bytes(buf.data(), static_cast<int>(kAes256KeyLen)) != 1) {
    // OpenSSL's documented behavior: RAND_bytes failing means the process's
    // entropy source is broken. There is no safe fallback -- continuing
    // would silently produce a predictable "random" key. This is one of the
    // few places in this codebase where we treat a failure as fatal rather
    // than returning an error code, deliberately.
    throw std::runtime_error("RAND_bytes failed: CSPRNG unavailable");
  }
  return Aes256Key(std::move(buf));
}

GcmNonce GcmNonce::Generate() {
  GcmNonce nonce{};
  if (RAND_bytes(nonce.bytes, static_cast<int>(kGcmNonceLen)) != 1) {
    throw std::runtime_error("RAND_bytes failed: CSPRNG unavailable");
  }
  return nonce;
}

std::vector<std::uint8_t> EncryptedMessage::Serialize() const {
  std::vector<std::uint8_t> out;
  out.reserve(kGcmNonceLen + ciphertext.size() + kGcmTagLen);
  out.insert(out.end(), nonce.bytes, nonce.bytes + kGcmNonceLen);
  out.insert(out.end(), ciphertext.begin(), ciphertext.end());
  out.insert(out.end(), tag, tag + kGcmTagLen);
  return out;
}

std::optional<EncryptedMessage> EncryptedMessage::Deserialize(
    const std::uint8_t* data, std::size_t len) {
  if (len < kGcmNonceLen + kGcmTagLen) {
    return std::nullopt;  // too short to even contain nonce + tag
  }
  EncryptedMessage msg;
  std::memcpy(msg.nonce.bytes, data, kGcmNonceLen);
  std::size_t ct_len = len - kGcmNonceLen - kGcmTagLen;
  msg.ciphertext.assign(data + kGcmNonceLen, data + kGcmNonceLen + ct_len);
  std::memcpy(msg.tag, data + kGcmNonceLen + ct_len, kGcmTagLen);
  return msg;
}

std::optional<EncryptedMessage> Encrypt(const Aes256Key& key,
                                         const std::uint8_t* plaintext,
                                         std::size_t plaintext_len,
                                         const std::uint8_t* aad,
                                         std::size_t aad_len) {
  if (key.bytes().size() != kAes256KeyLen) {
    return std::nullopt;
  }
  // Checked BEFORE any length is narrowed to `int` below -- see
  // kMaxAeadMessageLen's comment in aead.h for why this specific bound and
  // why it matters for correctness, not just resource limits.
  if (plaintext_len > kMaxAeadMessageLen || aad_len > kMaxAeadMessageLen) {
    return std::nullopt;
  }

  EncryptedMessage msg;
  msg.nonce = GcmNonce::Generate();
  msg.ciphertext.resize(plaintext_len);

  CipherCtx cc;
  if (!cc.ctx) return std::nullopt;

  if (EVP_EncryptInit_ex(cc.ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
    return std::nullopt;
  }
  if (EVP_CIPHER_CTX_ctrl(cc.ctx, EVP_CTRL_GCM_SET_IVLEN, kGcmNonceLen, nullptr) != 1) {
    return std::nullopt;
  }
  if (EVP_EncryptInit_ex(cc.ctx, nullptr, nullptr, key.bytes().data(), msg.nonce.bytes) != 1) {
    return std::nullopt;
  }

  int out_len = 0;
  if (aad != nullptr && aad_len > 0) {
    if (EVP_EncryptUpdate(cc.ctx, nullptr, &out_len, aad, static_cast<int>(aad_len)) != 1) {
      return std::nullopt;
    }
  }

  if (plaintext_len > 0) {
    if (EVP_EncryptUpdate(cc.ctx, msg.ciphertext.data(), &out_len, plaintext,
                           static_cast<int>(plaintext_len)) != 1) {
      return std::nullopt;
    }
  }

  int final_len = 0;
  // GCM is a stream-cipher mode; EncryptFinal never emits additional
  // ciphertext bytes, but we still call it to finalize the tag computation.
  // SafeOffset avoids forming `nullptr + 0` when ciphertext is empty (see
  // that function's comment) -- msg.ciphertext.data() can be nullptr for a
  // zero-length vector.
  if (EVP_EncryptFinal_ex(cc.ctx, SafeOffset(msg.ciphertext.data(), out_len), &final_len) != 1) {
    return std::nullopt;
  }

  if (EVP_CIPHER_CTX_ctrl(cc.ctx, EVP_CTRL_GCM_GET_TAG, kGcmTagLen, msg.tag) != 1) {
    return std::nullopt;
  }

  return msg;
}

std::optional<std::vector<std::uint8_t>> Decrypt(const Aes256Key& key,
                                                   const EncryptedMessage& msg,
                                                   const std::uint8_t* aad,
                                                   std::size_t aad_len,
                                                   AeadError* out_error) {
  auto fail = [&](AeadError e) -> std::optional<std::vector<std::uint8_t>> {
    if (out_error) *out_error = e;
    return std::nullopt;
  };

  if (key.bytes().size() != kAes256KeyLen) {
    return fail(AeadError::kInvalidKeyLength);
  }
  // Same reasoning as Encrypt() -- checked before any length is narrowed
  // to `int` below.
  if (msg.ciphertext.size() > kMaxAeadMessageLen || aad_len > kMaxAeadMessageLen) {
    return fail(AeadError::kMessageTooLarge);
  }

  CipherCtx cc;
  if (!cc.ctx) return fail(AeadError::kOpenSslInternalError);

  if (EVP_DecryptInit_ex(cc.ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
    return fail(AeadError::kOpenSslInternalError);
  }
  if (EVP_CIPHER_CTX_ctrl(cc.ctx, EVP_CTRL_GCM_SET_IVLEN, kGcmNonceLen, nullptr) != 1) {
    return fail(AeadError::kOpenSslInternalError);
  }
  if (EVP_DecryptInit_ex(cc.ctx, nullptr, nullptr, key.bytes().data(), msg.nonce.bytes) != 1) {
    return fail(AeadError::kOpenSslInternalError);
  }

  int out_len = 0;
  if (aad != nullptr && aad_len > 0) {
    if (EVP_DecryptUpdate(cc.ctx, nullptr, &out_len, aad, static_cast<int>(aad_len)) != 1) {
      return fail(AeadError::kOpenSslInternalError);
    }
  }

  std::vector<std::uint8_t> plaintext(msg.ciphertext.size());
  // From this point on, `plaintext` may hold decrypted-but-NOT-YET-
  // AUTHENTICATED bytes. PlaintextWipeGuard wipes it on every exit path
  // (including every `return fail(...)` below, via the lambda capturing
  // nothing extra -- the guard's destructor runs regardless of which
  // return statement is taken) unless Release() is called on the one
  // success path at the end. This replaces the earlier version's
  // hand-placed single cleanse call, which only covered the
  // authentication-failure path and silently missed the SET_TAG-failure
  // and internal-error-after-DecryptUpdate paths -- both of which can also
  // leave partially-decrypted plaintext in this buffer.
  PlaintextWipeGuard wipe_guard(plaintext);

  if (!msg.ciphertext.empty()) {
    if (EVP_DecryptUpdate(cc.ctx, plaintext.data(), &out_len, msg.ciphertext.data(),
                           static_cast<int>(msg.ciphertext.size())) != 1) {
      return fail(AeadError::kOpenSslInternalError);
    }
  }

  // Set the expected tag before finalizing -- OpenSSL compares it internally
  // during EVP_DecryptFinal_ex using a constant-time comparison.
  if (EVP_CIPHER_CTX_ctrl(cc.ctx, EVP_CTRL_GCM_SET_TAG, kGcmTagLen,
                           const_cast<std::uint8_t*>(msg.tag)) != 1) {
    return fail(AeadError::kOpenSslInternalError);
  }

  int final_len = 0;
  int ret = EVP_DecryptFinal_ex(cc.ctx, SafeOffset(plaintext.data(), out_len), &final_len);
  if (ret <= 0) {
    // Authentication failed. wipe_guard's destructor wipes `plaintext`
    // when this function returns -- it must never be returned or leaked
    // to the caller, and must not sit in freed heap memory unwiped.
    return fail(AeadError::kAuthenticationFailed);
  }

  // Success: the plaintext is now authenticated. Release the guard so its
  // destructor does NOT wipe the buffer the caller is about to receive.
  wipe_guard.Release();
  if (out_error) *out_error = AeadError::kNone;
  return plaintext;
}

}  // namespace rtprotect::crypto
