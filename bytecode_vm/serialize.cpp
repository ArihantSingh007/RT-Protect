#include "bytecode_vm/serialize.h"

#include <cstring>

namespace rtprotect::vm {

namespace {

void PutU32(std::vector<std::uint8_t>& out, std::uint32_t v) {
  out.push_back(static_cast<std::uint8_t>(v & 0xFF));
  out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
  out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
  out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFF));
}

bool GetU32(const std::uint8_t* p, std::size_t remaining, std::uint32_t* out) {
  if (remaining < 4) return false;
  *out = static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
         (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
  return true;
}

void PutI64(std::vector<std::uint8_t>& out, std::int64_t v) {
  std::uint64_t u;
  std::memcpy(&u, &v, 8);
  for (int i = 0; i < 8; ++i) out.push_back(static_cast<std::uint8_t>((u >> (8 * i)) & 0xFF));
}

bool GetI64(const std::uint8_t* p, std::size_t remaining, std::int64_t* out) {
  if (remaining < 8) return false;
  std::uint64_t u = 0;
  for (int i = 0; i < 8; ++i) u |= static_cast<std::uint64_t>(p[i]) << (8 * i);
  std::memcpy(out, &u, 8);
  return true;
}

}  // namespace

// Wire format: num_locals(1) | code_len(u32) | code(code_len) |
//              const_count(u32) | constants(const_count * 8 bytes, i64 LE)
std::vector<std::uint8_t> Serialize(const Program& program) {
  std::vector<std::uint8_t> out;
  out.reserve(1 + 4 + program.code.size() + 4 + program.constants.size() * 8);

  out.push_back(program.num_locals);
  PutU32(out, static_cast<std::uint32_t>(program.code.size()));
  out.insert(out.end(), program.code.begin(), program.code.end());
  PutU32(out, static_cast<std::uint32_t>(program.constants.size()));
  for (std::int64_t c : program.constants) PutI64(out, c);

  return out;
}

std::optional<Program> Deserialize(const std::uint8_t* data, std::size_t len) {
  if (len < 1 + 4) return std::nullopt;
  std::size_t pos = 0;

  Program p;
  p.num_locals = data[pos];
  pos += 1;

  std::uint32_t code_len = 0;
  if (!GetU32(data + pos, len - pos, &code_len)) return std::nullopt;
  pos += 4;

  if (pos + code_len > len) return std::nullopt;  // claimed length exceeds buffer
  if (code_len > kMaxCodeBytes) return std::nullopt;
  p.code.assign(data + pos, data + pos + code_len);
  pos += code_len;

  std::uint32_t const_count = 0;
  if (!GetU32(data + pos, len - pos, &const_count)) return std::nullopt;
  pos += 4;

  if (const_count > kMaxConstants) return std::nullopt;
  if (pos + static_cast<std::size_t>(const_count) * 8 != len) {
    // Require the buffer to be exactly consumed -- trailing garbage after a
    // claimed-valid structure is itself a sign of a malformed/tampered blob.
    return std::nullopt;
  }
  p.constants.reserve(const_count);
  for (std::uint32_t i = 0; i < const_count; ++i) {
    std::int64_t v = 0;
    if (!GetI64(data + pos, len - pos, &v)) return std::nullopt;
    p.constants.push_back(v);
    pos += 8;
  }

  return p;
}

}  // namespace rtprotect::vm
