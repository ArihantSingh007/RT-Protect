// fuzz/fuzz_vm_deserialize_and_verify.cpp
//
// libFuzzer harness covering bytecode_vm::Deserialize() AND
// bytecode_vm::VerifyProgram() together -- the full path untrusted
// decrypted bytecode takes before anything is ever executed (see
// runtime/reconstructed_function.h and examples/protected_checksum.h,
// both of which call Deserialize() then VerifyProgram() in that order on
// AEAD-decrypted bytes). Covering both in one harness, rather than two
// separate ones, specifically because the interesting bugs are as likely
// to be in how a value that survives Deserialize() flows into
// VerifyProgram() as in either function alone -- see this directory's
// README.md for why fuzzing the combination, not just each function in
// isolation, matters here, and for why these harnesses have not been
// executed in this project's current environment.
//
// A finding here would mean a crash, hang, or sanitizer violation
// reachable from untrusted bytes BEFORE any VM instruction is ever
// executed -- i.e. a way to break the safety boundary this project's
// whole verify-then-execute design (see bytecode_vm/verifier.h) depends
// on, at the step that's supposed to make everything after it trustworthy.

#include <cstdint>
#include <cstddef>

#include "bytecode_vm/serialize.h"
#include "bytecode_vm/verifier.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  auto program = rtprotect::vm::Deserialize(data, size);
  if (!program.has_value()) return 0;

  rtprotect::vm::VerifyError err = rtprotect::vm::VerifyError::kNone;
  auto verified = rtprotect::vm::VerifyProgram(*program, &err);
  (void)verified;
  // Deliberately NOT calling vm::Run() here even if verification
  // succeeds: this harness's scope is the untrusted-bytes-to-verified-
  // program boundary specifically. A program that Deserialize()+
  // VerifyProgram() both accept is, by this project's own design,
  // trusted to run safely (bounded stack, no unbounded loops beyond the
  // runtime instruction budget) -- exercising Run() as well would be
  // testing the interpreter's OWN correctness against programs the
  // verifier has already vouched for, a different (and much larger,
  // slower-to-fuzz) search space than "can malformed input reach the
  // interpreter at all," which is this harness's actual question.
  return 0;
}
