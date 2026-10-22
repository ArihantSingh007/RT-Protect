// obfuscation/obfuscated_string.h
//
// Compile-time string "encryption" (a reversible XOR keystream derived from
// a compile-time seed, not a cryptographic cipher -- see the limitation
// note below) so that string literals embedded in source do not appear as
// cleartext bytes in the compiled binary's data sections, where they would
// otherwise be trivially found by running `strings` on the executable or
// opening it in a hex editor.
//
// WHAT THIS ACTUALLY ACHIEVES (verified empirically, not assumed -- see
// docs/OBFUSCATION.md for the actual `strings`/`nm` output this claim is
// based on): a literal passed through RTPROTECT_OBFUSCATE does not appear
// as a contiguous readable string in the compiled binary. This defeats
// casual static analysis -- running `strings`, opening the binary in a hex
// editor, or any tool that scans for printable ASCII runs without
// executing or disassembling code.
//
// WHAT THIS DOES NOT ACHIEVE, stated as plainly as docs/THREAT_MODEL.md
// requires: the decryption key is derived entirely from compile-time
// constants (the call site's line number and a translation-unit-local
// counter) that are embedded as immediate operands directly in the
// decryption routine shipped in the same binary. Anyone who disassembles
// or decompiles that routine -- which is ordinary, un-obfuscated compiled
// C++, see docs/OBFUSCATION.md's note that this phase does not obfuscate
// its own obfuscation code -- can read the key and recover the string in
// seconds. This technique raises the cost of *automated, passive* string
// harvesting; it does nothing against a human reverse engineer willing to
// look at the function that uses the string. Never use this for anything
// where recovery would be a security failure (e.g. do not "obfuscate" a
// private key or password this way instead of not shipping it at all).

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace rtprotect::obfuscation {

// Wipes `n` bytes at `p`. Implemented locally (rather than reusing
// crypto::SecureBuffer's OPENSSL_cleanse) so this header has zero
// dependencies outside the standard library -- obfuscation/ and crypto/
// are deliberately decoupled, per docs/ARCHITECTURE.md's note on keeping
// sensitive logic separable across modules (brief §4). The `volatile`
// pointer prevents the compiler from proving the writes are dead and
// eliminating them, the same concern OPENSSL_cleanse addresses.
inline void SecureWipe(void* p, std::size_t n) {
  volatile unsigned char* vp = static_cast<volatile unsigned char*>(p);
  for (std::size_t i = 0; i < n; ++i) vp[i] = 0;
}

// A simple constexpr mixing function (SplitMix64's finalizer) used only to
// turn a 64-bit seed plus a byte index into a pseudo-random keystream byte
// at COMPILE time. This is explicitly not claimed to be cryptographically
// secure -- see the file header above for what security property is and
// isn't being claimed.
constexpr std::uint8_t KeystreamByte(unsigned long long seed, std::size_t index) {
  unsigned long long v = seed ^ (static_cast<unsigned long long>(index) * 0x9E3779B97F4A7C15ULL);
  v ^= v >> 33;
  v *= 0xff51afd7ed558ccdULL;
  v ^= v >> 33;
  v *= 0xc4ceb9fe1a85ec53ULL;
  v ^= v >> 33;
  return static_cast<std::uint8_t>(v & 0xFF);
}

template <std::size_t N>
class ObfuscatedString {
 public:
  // N includes the implicit null terminator, as for any string-literal
  // array argument (sizeof("abc") == 4). The constructor is constexpr so
  // that, when called from a constant-evaluated context (see
  // RTPROTECT_OBFUSCATE below), the encryption happens entirely at compile
  // time -- only the resulting `cipher_` bytes and `seed_` need to exist in
  // the compiled output, not the original plaintext array.
  constexpr ObfuscatedString(const char (&str)[N], unsigned long long seed) : seed_(seed) {
    for (std::size_t i = 0; i < N; ++i) {
      cipher_[i] = static_cast<std::uint8_t>(str[i]) ^ KeystreamByte(seed_, i);
    }
  }

  // Decrypts into `out`, which must have room for N bytes (the last of
  // which will be the restored null terminator).
  void Decrypt(char* out) const {
    for (std::size_t i = 0; i < N; ++i) {
      out[i] = static_cast<char>(cipher_[i] ^ KeystreamByte(seed_, i));
    }
  }

  static constexpr std::size_t size() { return N; }

 private:
  std::uint8_t cipher_[N]{};
  unsigned long long seed_;
};

template <std::size_t N>
constexpr ObfuscatedString<N> MakeObfuscated(const char (&str)[N], unsigned long long seed) {
  return ObfuscatedString<N>(str, seed);
}

// RAII holder for the decrypted plaintext: decrypts into a fixed-size stack
// buffer on construction, wipes it on destruction. This bounds the
// plaintext's lifetime to the enclosing scope, the same principle as
// crypto::SecureBuffer (see docs/THREAT_MODEL.md §6) applied to this
// module's own, much weaker, secret.
template <std::size_t N>
class RevealedString {
 public:
  explicit RevealedString(const ObfuscatedString<N>& obf) { obf.Decrypt(buf_); }
  ~RevealedString() { SecureWipe(buf_, N); }

  RevealedString(const RevealedString&) = delete;
  RevealedString& operator=(const RevealedString&) = delete;

  const char* c_str() const { return buf_; }
  operator const char*() const { return buf_; }
  operator std::string() const { return std::string(buf_, N - 1); }
  std::size_t size() const { return N - 1; }  // excludes the null terminator

 private:
  char buf_[N]{};
};

}  // namespace rtprotect::obfuscation

// Builds an ObfuscatedString from a literal at the call site, deriving the
// compile-time seed from the call site's line number and a
// translation-unit-local counter (__COUNTER__) so that two obfuscated
// literals in the same file never accidentally share a seed. This must be
// a macro (not a function) specifically so __LINE__ and __COUNTER__ expand
// to the call site's values, not some shared location inside this header.
#define RTPROTECT_OBFUSCATE(str)                                                    \
  (::rtprotect::obfuscation::MakeObfuscated(                                        \
      (str), (0x9E3779B97F4A7C15ULL ^                                               \
              (static_cast<unsigned long long>(__LINE__) * 2654435761ULL) ^         \
              static_cast<unsigned long long>(__COUNTER__))))

#define OBFUSCATED_STRING(str)                                                      \
  ([]() -> const char* {                                                            \
    static constexpr auto s_obf = RTPROTECT_OBFUSCATE(str);                         \
    static char s_buf[s_obf.size()];                                                \
    static const bool s_init = []() {                                               \
      s_obf.Decrypt(s_buf);                                                         \
      return true;                                                                  \
    }();                                                                            \
    (void)s_init;                                                                   \
    return s_buf;                                                                   \
  }())

#define RTPROTECT_STRING(str) OBFUSCATED_STRING(str)
