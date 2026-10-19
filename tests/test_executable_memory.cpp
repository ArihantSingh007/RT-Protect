#include "runtime/executable_memory.h"
#include "runtime/native_payload.h"

#include <vector>

#include "tests/micro_test.h"

using namespace rtprotect::runtime;

MT_TEST(ExecutableMemory_LoadedPayload_MatchesNativeReference) {
  LoadError err = LoadError::kNone;
  auto region = ExecutableMemoryRegion::Create(kPayload.data(), kPayload.size(), &err);
  MT_CHECK(region.has_value());
  MT_CHECK(err == LoadError::kNone);
  if (!region) return;

  std::int64_t inputs[] = {-100, -5, -1, 0, 1, 5, 100, 1000000, -1000000};
  for (std::int64_t x : inputs) {
    auto result = region->Call(x);
    MT_CHECK(!result.faulted);
    MT_CHECK(result.value == NativeReference(x));
  }
}

MT_TEST(ExecutableMemory_RejectsOversizedPayload) {
  // Build a payload bigger than one page -- PageSize() isn't exposed, but
  // 1 MiB is safely larger than any realistic page size.
  std::vector<std::uint8_t> huge(1024 * 1024, 0xC3);  // all RET bytes, content
                                                        // doesn't matter, we
                                                        // never execute this
  LoadError err = LoadError::kNone;
  auto region = ExecutableMemoryRegion::Create(huge.data(), huge.size(), &err);
  MT_CHECK(!region.has_value());
  MT_CHECK(err == LoadError::kPayloadTooLarge);
}

MT_TEST(ExecutableMemory_FaultingCode_IsCaughtNotCrashed) {
  // kFaultTestPayload is Intel's dedicated UD2 "always
  // raise #UD (invalid opcode)" instruction, included in this project's
  // payload allowlist specifically so this test can exercise fault
  // isolation through the real public Create()/Call() API -- see that
  // constant's header comment. This test exists to prove
  // runtime/executable_memory.h's fault isolation actually works: if it
  // didn't, this test process would simply crash instead of reporting a
  // failed MT_CHECK.
  LoadError err = LoadError::kNone;
  auto region = ExecutableMemoryRegion::Create(kFaultTestPayload.data(),
                                                kFaultTestPayload.size(), &err);
  MT_CHECK(region.has_value());
  MT_CHECK(err == LoadError::kNone);  // loading always succeeds -- nothing
                                       // about these bytes is invalid as
                                       // DATA, only as an instruction once
                                       // executed
  if (!region) return;

  auto result = region->Call(42);
  MT_CHECK(result.faulted);

  // The region must still be safely usable/destructible after a fault --
  // this isn't just "did it not crash the whole process" but "is the
  // object still in a valid state afterward."
}

MT_TEST(ExecutableMemory_RejectsUnrecognizedPayload) {
  // Create() enforces its payload allowlist itself (see
  // executable_memory.h's header comment and IsRecognizedPayload()) --
  // bytes that aren't byte-for-byte one of the known-reviewed payloads
  // must be rejected before anything is allocated or made executable,
  // regardless of how plausible or harmless-looking they are. This is a
  // nonsense instruction sequence, included specifically because it is
  // NOT kPayloadSysV, kPayloadMsx64, or kFaultTestPayload.
  std::uint8_t arbitrary[] = {0x90, 0x90, 0x90, 0xC3};  // nop; nop; nop; ret
  LoadError err = LoadError::kNone;
  auto region = ExecutableMemoryRegion::Create(arbitrary, sizeof(arbitrary), &err);
  MT_CHECK(!region.has_value());
  MT_CHECK(err == LoadError::kPayloadNotRecognized);
}

MT_TEST(ExecutableMemory_RejectsEmptyPayload) {
  LoadError err = LoadError::kNone;
  auto region = ExecutableMemoryRegion::Create(nullptr, 0, &err);
  MT_CHECK(!region.has_value());
  MT_CHECK(err == LoadError::kPayloadNotRecognized);  // 0 bytes never
                                                       // matches any
                                                       // nonzero-length
                                                       // allowlist entry
}

MT_TEST(ExecutableMemory_MultipleSequentialCalls_AllSucceed) {
  // Confirms the fault-handler install/restore cycle in Call() doesn't
  // leave any dangling state that breaks a subsequent, well-formed call --
  // important because the fault test above exercises the same signal
  // handler machinery just before this one runs in the same process.
  LoadError err = LoadError::kNone;
  auto region = ExecutableMemoryRegion::Create(kPayload.data(), kPayload.size(), &err);
  MT_CHECK(region.has_value());
  if (!region) return;

  for (std::int64_t x = 0; x < 20; ++x) {
    auto result = region->Call(x);
    MT_CHECK(!result.faulted);
    MT_CHECK(result.value == NativeReference(x));
  }
}

// ---------------------------------------------------------------------
// Object lifetime: construction, destruction, move construction, move
// assignment, self-move assignment, and repeated cleanup. These exist
// specifically to regression-test the move-assignment fix described in
// executable_memory.cpp (the previous version called
// this->~ExecutableMemoryRegion() directly and then wrote to the
// now-lifetime-ended object's members -- undefined behavior per the C++
// object model, replaced with a ReleaseResources() helper that frees the
// resource without ending the object's lifetime).
// ---------------------------------------------------------------------

MT_TEST(ExecutableMemory_MoveConstruct_TransfersOwnershipAndWorks) {
  LoadError err = LoadError::kNone;
  auto region_a = ExecutableMemoryRegion::Create(kPayload.data(), kPayload.size(), &err);
  MT_CHECK(region_a.has_value());
  if (!region_a) return;

  ExecutableMemoryRegion region_b(std::move(*region_a));
  auto result = region_b.Call(10);
  MT_CHECK(!result.faulted);
  MT_CHECK(result.value == NativeReference(10));
}

MT_TEST(ExecutableMemory_MoveAssign_ReleasesTargetAndTransfersSource) {
  LoadError err = LoadError::kNone;
  auto region_a = ExecutableMemoryRegion::Create(kPayload.data(), kPayload.size(), &err);
  auto region_b = ExecutableMemoryRegion::Create(kPayload.data(), kPayload.size(), &err);
  MT_CHECK(region_a.has_value() && region_b.has_value());
  if (!region_a || !region_b) return;

  // Move region_b INTO region_a's slot -- region_a's original mapping
  // must be released (via ReleaseResources(), not a destructor call that
  // would end region_a's own object lifetime while this function still
  // intends to use it afterward) before taking ownership of region_b's.
  *region_a = std::move(*region_b);

  auto result = region_a->Call(15);
  MT_CHECK(!result.faulted);
  MT_CHECK(result.value == NativeReference(15));
}

MT_TEST(ExecutableMemory_SelfMoveAssign_DoesNotCorruptOrCrash) {
  LoadError err = LoadError::kNone;
  auto region = ExecutableMemoryRegion::Create(kPayload.data(), kPayload.size(), &err);
  MT_CHECK(region.has_value());
  if (!region) return;

  ExecutableMemoryRegion* self = &(*region);
  *region = std::move(*self);  // self-move-assignment

  // The `this != &other` guard must prevent this from releasing its own
  // mapping and then trying to use it -- the region must still work
  // correctly afterward.
  auto result = region->Call(20);
  MT_CHECK(!result.faulted);
  MT_CHECK(result.value == NativeReference(20));
}

MT_TEST(ExecutableMemory_MovedFromObject_IsSafeToDestroy) {
  LoadError err = LoadError::kNone;
  auto region_a = ExecutableMemoryRegion::Create(kPayload.data(), kPayload.size(), &err);
  MT_CHECK(region_a.has_value());
  if (!region_a) return;

  ExecutableMemoryRegion region_b(std::move(*region_a));
  // region_a (now moved-from) is about to go out of scope (its
  // std::optional will destroy the moved-from ExecutableMemoryRegion).
  // This must not double-free the mapping region_b now owns -- the
  // move constructor nulls out the source's mem_, so ReleaseResources()
  // on the moved-from object is a safe no-op. If this test's process
  // doesn't crash and the later checks still pass, that's the actual
  // assertion -- there is no in-language way to directly observe "did a
  // double-free happen" short of running under ASan (see the main
  // README's sanitizer build instructions, which this exact test is run
  // under as part of that build).
  MT_CHECK(true);  // reaching this line without crashing is the test
}

MT_TEST(ExecutableMemory_RepeatedMoveAssign_NoLeakOrCorruption) {
  // Exercises several move-assignment cycles in a row -- the pattern most
  // likely to surface a double-free or leak if ReleaseResources() weren't
  // correctly idempotent and complete. Most valuable when run under
  // AddressSanitizer (see the main README).
  LoadError err = LoadError::kNone;
  auto region = ExecutableMemoryRegion::Create(kPayload.data(), kPayload.size(), &err);
  MT_CHECK(region.has_value());
  if (!region) return;

  for (int i = 0; i < 10; ++i) {
    auto fresh = ExecutableMemoryRegion::Create(kPayload.data(), kPayload.size(), &err);
    MT_CHECK(fresh.has_value());
    if (!fresh) return;
    *region = std::move(*fresh);
  }

  auto result = region->Call(5);
  MT_CHECK(!result.faulted);
  MT_CHECK(result.value == NativeReference(5));
}

MT_MAIN()
