// tests/test_opcode_map.cpp

#include "bytecode_vm/opcode_map.h"
#include <algorithm>
#include "tests/micro_test.h"

using namespace rtprotect::vm;

MT_TEST(OpcodeMap_DefaultMap_MatchesStandardOpcodes) {
  OpcodeMap def;
  MT_CHECK(def.Encode(Opcode::kPushConst) == 0x01);
  MT_CHECK(def.Encode(Opcode::kRet) == 0x50);

  auto decoded = def.Decode(0x01);
  MT_CHECK(decoded.has_value());
  MT_CHECK(*decoded == Opcode::kPushConst);

  MT_CHECK(!def.Decode(0x00).has_value());
  MT_CHECK(!def.Decode(0xFE).has_value());
}

MT_TEST(OpcodeMap_FromSeed_ProducesBijection) {
  OpcodeMap m = OpcodeMap::FromSeed(42);

  std::vector<Opcode> all = {
    Opcode::kPushConst, Opcode::kPushLocal, Opcode::kStoreLocal, Opcode::kDup, Opcode::kPop,
    Opcode::kAdd, Opcode::kSub, Opcode::kMul, Opcode::kDiv, Opcode::kMod,
    Opcode::kAnd, Opcode::kOr, Opcode::kXor, Opcode::kNot,
    Opcode::kCmpEq, Opcode::kCmpLt, Opcode::kCmpGt,
    Opcode::kJmp, Opcode::kJz, Opcode::kJnz, Opcode::kRet
  };

  std::vector<std::uint8_t> used_bytes;
  for (Opcode op : all) {
    std::uint8_t byte = m.Encode(op);
    used_bytes.push_back(byte);

    auto dec = m.Decode(byte);
    MT_CHECK(dec.has_value());
    MT_CHECK(*dec == op);
  }

  // Verify all 21 bytes are unique
  std::sort(used_bytes.begin(), used_bytes.end());
  auto it = std::unique(used_bytes.begin(), used_bytes.end());
  MT_CHECK(it == used_bytes.end());
}

MT_TEST(OpcodeMap_DifferentSeeds_ProduceDifferentMappings) {
  OpcodeMap m1 = OpcodeMap::FromSeed(111);
  OpcodeMap m2 = OpcodeMap::FromSeed(999);

  bool any_difference = false;
  std::uint8_t b1 = m1.Encode(Opcode::kPushConst);
  std::uint8_t b2 = m2.Encode(Opcode::kPushConst);
  if (b1 != b2) any_difference = true;

  MT_CHECK(any_difference);
}

MT_MAIN()
