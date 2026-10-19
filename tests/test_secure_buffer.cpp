// tests/test_secure_buffer.cpp
//
// Functional correctness for crypto/secure_buffer.h's rewrite (raw-buffer
// backed instead of std::vector-backed, specifically to fix the
// wipe-before-free-on-growth gap described in that file's class-level
// comment). Wiping itself can't be directly observed from a portable,
// well-defined C++ test (peeking at freed memory is itself undefined
// behavior) -- what CAN be verified directly is: every documented content/
// size contract still holds, AND (see the project's build instructions)
// this whole suite passes cleanly under AddressSanitizer, which would
// catch a double-free, leak, or out-of-bounds access introduced by
// replacing std::vector's allocator with manual new[]/delete[].

#include "crypto/secure_buffer.h"

#include <cstring>

#include "tests/micro_test.h"

using namespace rtprotect::crypto;

MT_TEST(SecureBuffer_SizeConstructor_ZeroInitializes) {
  SecureBuffer buf(16);
  MT_CHECK(buf.size() == 16);
  bool all_zero = true;
  for (std::size_t i = 0; i < buf.size(); ++i) {
    if (buf.data()[i] != 0) all_zero = false;
  }
  MT_CHECK(all_zero);
}

MT_TEST(SecureBuffer_PointerConstructor_CopiesContent) {
  std::uint8_t src[] = {1, 2, 3, 4, 5};
  SecureBuffer buf(src, sizeof(src));
  MT_CHECK(buf.size() == 5);
  MT_CHECK(std::memcmp(buf.data(), src, 5) == 0);
  // Must be an independent copy, not aliasing src.
  src[0] = 0xFF;
  MT_CHECK(buf.data()[0] == 1);
}

MT_TEST(SecureBuffer_EmptyBuffer_SafeToConstructAndDestroy) {
  SecureBuffer buf(static_cast<std::size_t>(0));
  MT_CHECK(buf.empty());
  MT_CHECK(buf.size() == 0);
}

MT_TEST(SecureBuffer_MoveConstruct_TransfersOwnership) {
  std::uint8_t src[] = {9, 8, 7};
  SecureBuffer a(src, 3);
  SecureBuffer b(std::move(a));
  MT_CHECK(b.size() == 3);
  MT_CHECK(std::memcmp(b.data(), src, 3) == 0);
  // Moved-from object must be in a valid, empty state (safe to destroy).
  MT_CHECK(a.size() == 0);
  MT_CHECK(a.data() == nullptr);
}

MT_TEST(SecureBuffer_MoveAssign_TransfersOwnershipAndWipesTarget) {
  std::uint8_t src_a[] = {1, 1, 1};
  std::uint8_t src_b[] = {2, 2, 2, 2};
  SecureBuffer a(src_a, 3);
  SecureBuffer b(src_b, 4);
  a = std::move(b);
  MT_CHECK(a.size() == 4);
  MT_CHECK(std::memcmp(a.data(), src_b, 4) == 0);
  MT_CHECK(b.size() == 0);
  MT_CHECK(b.data() == nullptr);
}

MT_TEST(SecureBuffer_SelfMoveAssign_DoesNotCorruptOrCrash) {
  std::uint8_t src[] = {5, 6, 7};
  SecureBuffer a(src, 3);
  SecureBuffer* self = &a;
  a = std::move(*self);  // self-move-assignment
  // The `this != &other` guard in operator= must prevent this from wiping
  // then reading its own just-wiped data.
  MT_CHECK(a.size() == 3);
}

MT_TEST(SecureBuffer_Resize_Grow_PreservesPrefixAndZeroFillsTail) {
  std::uint8_t src[] = {10, 20, 30};
  SecureBuffer buf(src, 3);
  buf.Resize(6);
  MT_CHECK(buf.size() == 6);
  MT_CHECK(buf.data()[0] == 10 && buf.data()[1] == 20 && buf.data()[2] == 30);
  MT_CHECK(buf.data()[3] == 0 && buf.data()[4] == 0 && buf.data()[5] == 0);
}

MT_TEST(SecureBuffer_Resize_Shrink_PreservesPrefix) {
  std::uint8_t src[] = {1, 2, 3, 4, 5};
  SecureBuffer buf(src, 5);
  buf.Resize(2);
  MT_CHECK(buf.size() == 2);
  MT_CHECK(buf.data()[0] == 1 && buf.data()[1] == 2);
}

MT_TEST(SecureBuffer_Resize_ToZero_SafeAndEmpty) {
  std::uint8_t src[] = {1, 2, 3};
  SecureBuffer buf(src, 3);
  buf.Resize(0);
  MT_CHECK(buf.size() == 0);
  MT_CHECK(buf.empty());
}

MT_TEST(SecureBuffer_RepeatedGrowShrink_NoCorruption) {
  // Exercises many reallocation cycles -- the kind of pattern most likely
  // to surface a use-after-free, double-free, or leak in manual allocator
  // code, especially under AddressSanitizer (see this file's header
  // comment on running the whole suite under ASan).
  SecureBuffer buf(static_cast<std::size_t>(0));
  for (int cycle = 0; cycle < 50; ++cycle) {
    std::size_t grow_to = static_cast<std::size_t>(10 + cycle);
    buf.Resize(grow_to);
    MT_CHECK(buf.size() == grow_to);
    buf.data()[grow_to - 1] = static_cast<std::uint8_t>(cycle);  // touch the
                                                                   // newly
                                                                   // grown byte
    buf.Resize(5);
    MT_CHECK(buf.size() == 5);
  }
}

MT_TEST(SecureBuffer_Clone_IsIndependentCopy) {
  std::uint8_t src[] = {1, 2, 3};
  SecureBuffer a(src, 3);
  SecureBuffer b = a.Clone();
  MT_CHECK(b.size() == 3);
  MT_CHECK(std::memcmp(b.data(), src, 3) == 0);
  b.data()[0] = 0xFF;
  MT_CHECK(a.data()[0] == 1);  // mutating the clone must not affect the original
}

MT_MAIN()
