#include "integrity/sha256.h"

#include <fstream>
#include <vector>
#include <openssl/evp.h>

namespace rtprotect::integrity {

std::optional<Sha256Digest> Sha256(const std::uint8_t* data, std::size_t len) {
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) return std::nullopt;

  Sha256Digest digest{};
  unsigned int out_len = 0;
  bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
            EVP_DigestUpdate(ctx, data, len) == 1 &&
            EVP_DigestFinal_ex(ctx, digest.data(), &out_len) == 1;
  EVP_MD_CTX_free(ctx);

  if (!ok || out_len != kSha256DigestLen) return std::nullopt;
  return digest;
}

std::optional<Sha256Digest> Sha256File(const std::string& path, std::uint64_t* out_file_size) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return std::nullopt;

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) return std::nullopt;

  if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
    EVP_MD_CTX_free(ctx);
    return std::nullopt;
  }

  constexpr std::size_t kChunkSize = 64 * 1024;  // 64 KB streaming buffer
  std::vector<char> buffer(kChunkSize);
  std::uint64_t total_bytes = 0;

  while (f.read(buffer.data(), buffer.size()) || f.gcount() > 0) {
    std::streamsize bytes_read = f.gcount();
    if (bytes_read <= 0) break;
    if (EVP_DigestUpdate(ctx, buffer.data(), static_cast<std::size_t>(bytes_read)) != 1) {
      EVP_MD_CTX_free(ctx);
      return std::nullopt;
    }
    total_bytes += static_cast<std::uint64_t>(bytes_read);
  }

  if (f.bad()) {
    EVP_MD_CTX_free(ctx);
    return std::nullopt;
  }

  Sha256Digest digest{};
  unsigned int out_len = 0;
  bool ok = (EVP_DigestFinal_ex(ctx, digest.data(), &out_len) == 1 && out_len == kSha256DigestLen);
  EVP_MD_CTX_free(ctx);

  if (!ok) return std::nullopt;
  if (out_file_size) *out_file_size = total_bytes;
  return digest;
}

}  // namespace rtprotect::integrity
