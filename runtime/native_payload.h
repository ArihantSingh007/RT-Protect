// runtime/native_payload.h
//
// THE ONLY MACHINE CODE THIS EXPERIMENT EVER EXECUTES.
//
// This is the single, fixed, fully-documented native-code payload for
// Phase 6's "runtime reconstruction of a protected code region" experiment
// (brief §3, architecture option 4). It computes exactly one thing:
//
//     int64_t Reconstructed(int64_t x) { return (x * 2) + 7; }
//
// Nothing else. No syscalls, no memory access beyond its own registers, no
// loops, no branches, no stack use. Every byte below is explained in the
// comment next to it, and both variants were produced by assembling real
// Intel-syntax source with GNU `as` and disassembling the result with
// `objdump` -- not hand-derived from memory and not merely asserted
// correct. The SysV variant was additionally loaded into real RW->RX
// memory and called for inputs -5..5, matching `2*x+7` exactly, before
// being used anywhere in this project. See docs/RUNTIME_RECONSTRUCTION.md
// for the full empirical record (exact commands and output).
//
// WHY A FIXED PAYLOAD, NOT A GENERIC "RUN THESE BYTES" FACILITY:
// Phase 3's bytecode VM has a verifier that constrains what a program can
// possibly do -- no opcode exists to make a syscall, dereference arbitrary
// memory, or call native code (see bytecode_vm/opcode.h). Native machine
// code has no such constraint: once bytes are mapped executable, they can
// do anything the CPU and OS permit, full stop. There is no verifier that
// can make arbitrary native bytes safe to execute. That is the central,
// irreducible risk difference between Phase 3 (constrained, recommended as
// the primary approach) and this phase (unconstrained, explicitly
// experimental/opt-in per the brief). This project accordingly never
// exposes an API that executes bytes from any source other than this one
// constant, reviewed, tested payload -- see runtime/reconstructed_function.h's
// header comment for how that boundary is enforced in the public API, and
// docs/RUNTIME_RECONSTRUCTION.md for why generalizing this loader to
// accept arbitrary or externally-sourced bytes is explicitly out of scope.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace rtprotect::runtime {

// SysV AMD64 calling convention (Linux, macOS, and this project's test
// environment): first integer argument in RDI, return value in RAX.
//
//   lea rax, [rdi + rdi + 7]   ; rax = rdi + rdi + 7 = 2*rdi + 7
//   ret
//
// Verified via: `as payload.s -o payload.o && objdump -d payload.o`
//   0: 48 8d 44 3f 07       lea    0x7(%rdi,%rdi,1),%rax
//   5: c3                   ret
// Then loaded into mmap'd RW->RX memory and called for x in [-5, 5],
// matching 2*x+7 exactly for every value. See
// docs/RUNTIME_RECONSTRUCTION.md for the full transcript.
inline constexpr std::array<std::uint8_t, 6> kPayloadSysV = {
    0x48, 0x8d, 0x44, 0x3f, 0x07,  // lea rax, [rdi + rdi + 7]
    0xc3,                          // ret
};

// Microsoft x64 calling convention (Windows): first integer argument in
// RCX, return value in RAX. Same operation, different source register.
//
//   lea rax, [rcx + rcx + 7]
//   ret
//
// Verified via the same assemble-and-disassemble process as kPayloadSysV:
//   0: 48 8d 44 09 07       lea    0x7(%rcx,%rcx,1),%rax
//   5: c3                   ret
// NOT independently execution-tested on Windows in this environment (no
// Windows runtime available here) -- see
// docs/RUNTIME_RECONSTRUCTION.md's "Not verified on Windows" note, which
// follows this project's established pattern of flagging exactly this gap
// rather than asserting Windows behavior without having observed it.
inline constexpr std::array<std::uint8_t, 6> kPayloadMsx64 = {
    0x48, 0x8d, 0x44, 0x09, 0x07,  // lea rax, [rcx + rcx + 7]
    0xc3,                          // ret
};

#if defined(_WIN32)
inline constexpr const std::array<std::uint8_t, 6>& kPayload = kPayloadMsx64;
#else
inline constexpr const std::array<std::uint8_t, 6>& kPayload = kPayloadSysV;
#endif

// Intel's UD2 instruction (0x0F 0x0B), architecturally guaranteed to raise
// an invalid-opcode fault whenever executed, on any x86/x86-64 CPU,
// regardless of calling convention. This is NOT a "protected function"
// payload -- it computes nothing and is never meaningful to call for a
// result. It exists solely so executable_memory.cpp's fault-isolation
// path (SEH on Windows, sigaction+sigsetjmp on the POSIX test harness) can
// be tested THROUGH THE REAL PUBLIC API
// (ExecutableMemoryRegion::Create()/Call()) rather than through some
// separate test-only backdoor that wouldn't actually prove the public
// path works. executable_memory.cpp's payload allowlist
// (IsRecognizedPayload()) includes this constant for exactly that reason
// -- see that function's comment. Deliberately kept in this same file
// (rather than a test-only header) so the allowlist has exactly one
// source of truth for "what Create() will ever load," matching how
// kPayloadSysV/kPayloadMsx64 are declared here too.
inline constexpr std::array<std::uint8_t, 2> kFaultTestPayload = {
    0x0f, 0x0b,  // ud2
};

// The native reference implementation this payload must match -- the same
// parity-testing pattern used throughout this project (examples/
// checksum_reference.h for Phase 3, obfuscation/checksum_flattened.h's
// comparison for Phase 5).
inline std::int64_t NativeReference(std::int64_t x) { return (x * 2) + 7; }

}  // namespace rtprotect::runtime
