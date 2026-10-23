# Fuzz harnesses

Five libFuzzer harnesses, covering the critical untrusted input entry points across RTProtect:

| Harness | Covers |
|---|---|
| `fuzz_manifest_deserialize` | `integrity::DeserializeManifest()` |
| `fuzz_vm_deserialize_and_verify` | `bytecode_vm::Deserialize()` + `bytecode_vm::VerifyProgram()` together |
| `fuzz_encrypted_message_deserialize` | `crypto::EncryptedMessage::Deserialize()` |
| `fuzz_source_scanner` | `tooling::TransformSourceFile()` AST/lexical parser and virtualizer |
| `fuzz_pe_protector` | `tooling::PeProtector::IsValidPe64()` and `tooling::PeProtector::ProtectMemory()` |

## Status: written, not executed

**These harnesses have not been built or run in this project's
development environment.** `clang` is not installed here (`clang
--version` reports "not found"), and libFuzzer (`-fsanitize=fuzzer`) is a
Clang/LLVM-specific feature with no GCC equivalent -- this project's
available toolchain (GCC 13.3.0) cannot build them at all. This is
distinguished deliberately from "we fuzzed it and found nothing": no
fuzzing has actually happened yet. The harnesses are believed correct
against libFuzzer's documented contract (reviewed by hand against that
contract, each with exactly one `LLVMFuzzerTestOneInput` entry point and
no competing `main()`), but "believed correct" is not the same claim as
"has found bugs" or "has run clean for N hours" -- neither of which this
project can currently back up with real output.

## Building and running for real (on a Clang toolchain)

```bash
mkdir build-fuzz && cd build-fuzz
CC=clang CXX=clang++ cmake .. -DRTPROTECT_BUILD_FUZZERS=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build . --target fuzz_manifest_deserialize fuzz_vm_deserialize_and_verify \
                          fuzz_encrypted_message_deserialize fuzz_source_scanner fuzz_pe_protector

# Run each for a bounded time (adjust -max_total_time, in seconds):
./fuzz_manifest_deserialize -max_total_time=300 corpus/manifest/
./fuzz_vm_deserialize_and_verify -max_total_time=300 corpus/vm/
./fuzz_encrypted_message_deserialize -max_total_time=300 corpus/aead/
./fuzz_source_scanner -max_total_time=300 corpus/source/
./fuzz_pe_protector -max_total_time=300 corpus/pe/
```

Create the `corpus/*` directories first (even empty) -- libFuzzer uses
them to save interesting inputs across runs. Seeding each corpus with a
few valid, hand-crafted inputs (e.g. the serialized bytes from this
project's own unit tests) will get useful coverage faster than starting
from nothing.

A finding (crash, hang, sanitizer report) will be saved by libFuzzer as a
file named `crash-<hash>` or similar in the working directory -- reduce it
with `-minimize_crash=1` and turn it into a permanent regression test
under `tests/`, the same way every other bug found during this project's
hardening pass was handled (see docs/SECURITY_HARDENING.md for several
real examples of exactly that process, just not yet one from these fuzz
targets specifically).

## Why these three, together, and not others

- `DeserializeManifest()` and `EncryptedMessage::Deserialize()` are both
  "untrusted bytes become a structured value" entry points -- the
  canonical kind of function fuzzing is good at.
- `bytecode_vm::Deserialize()` is fuzzed TOGETHER with
  `VerifyProgram()` (one harness, not two) specifically because the
  interesting bugs are as likely to be in how a value that survives
  deserialization flows into verification as in either function alone --
  see `fuzz_vm_deserialize_and_verify.cpp`'s header comment.
- `crypto::Encrypt`/`Decrypt` are deliberately NOT given their own fuzz
  harness: they take a fixed-size key as a required parameter, which a
  single untrusted byte stream has no natural way to supply without
  either fixing a key (testing nothing fuzzing-relevant) or fabricating
  one from the input (testing the harness's own key-selection logic, not
  `Decrypt()`). `tests/test_aead.cpp`'s extensive hand-written boundary
  cases (empty inputs, oversized lengths, tampered ciphertext/tag, wrong
  key, malformed serialized blobs via `EncryptedMessage::Deserialize`,
  which IS fuzzed) already give that smaller, better-understood input
  space solid coverage.
