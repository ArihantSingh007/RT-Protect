// crypto/secure_buffer.h
//
// A byte buffer whose contents are explicitly wiped (via OPENSSL_cleanse,
// which the compiler is not permitted to optimize away) before every
// deallocation of memory that held them -- on destruction, on shrink, AND
// on growth. This does NOT provide memory-locking (mlock/VirtualLock) --
// see docs/THREAT_MODEL.md, section "Plaintext lifetime", for what this
// does and does not protect against: it reduces the window in which a key
// or plaintext secret sits in freed heap memory, it does not prevent it
// from being paged to disk, read via a live memory dump of the running
// process, or copied into CPU registers or compiler-generated spill slots
// that this class has no visibility into (see "Limitations" below).
//
// SECURITY-RELEVANT HISTORY, kept here because it illustrates a real,
// non-obvious failure mode worth remembering: an earlier version of this
// class used std::vector<uint8_t> as its backing store and called
// data_.resize(new_size) directly for both growth and shrinkage. Wiping
// the dropped tail on SHRINK was correct, but on GROWTH past the vector's
// current capacity, std::vector's own reallocation (allocate new buffer,
// move/copy elements in, deallocate the OLD buffer) is completely outside
// this class's control -- the OLD buffer, still holding a full copy of
// whatever secret bytes it contained, was freed WITHOUT ever being passed
// to OPENSSL_cleanse. The secret didn't leak through any API this class
// exposes; it leaked through the allocator, into freed-but-unwiped heap
// memory, the exact outcome this entire class exists to prevent. This
// class now manages its own fixed-capacity-per-allocation raw buffer
// instead of delegating to std::vector, so every reallocation this class
// performs is one this class also controls the wipe-before-free of.

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>

#include <openssl/crypto.h>

namespace rtprotect::crypto {

class SecureBuffer {
 public:
  SecureBuffer() = default;

  explicit SecureBuffer(std::size_t size)
      : data_(Allocate(size)), size_(size), capacity_(size) {
    if (data_) std::memset(data_, 0, size_);  // match std::vector<T>(size)'s
                                               // value-initialization semantics
  }

  SecureBuffer(const std::uint8_t* src, std::size_t size)
      : data_(Allocate(size)), size_(size), capacity_(size) {
    if (size_ > 0) std::memcpy(data_, src, size_);
  }

  // Non-copyable: a secret should have one owner. Callers that genuinely
  // need a copy must do so explicitly via Clone().
  SecureBuffer(const SecureBuffer&) = delete;
  SecureBuffer& operator=(const SecureBuffer&) = delete;

  SecureBuffer(SecureBuffer&& other) noexcept
      : data_(other.data_), size_(other.size_), capacity_(other.capacity_) {
    other.data_ = nullptr;
    other.size_ = 0;
    other.capacity_ = 0;
  }

  SecureBuffer& operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
      ReleaseAndWipe();
      data_ = other.data_;
      size_ = other.size_;
      capacity_ = other.capacity_;
      other.data_ = nullptr;
      other.size_ = 0;
      other.capacity_ = 0;
    }
    return *this;
  }

  ~SecureBuffer() { ReleaseAndWipe(); }

  SecureBuffer Clone() const { return SecureBuffer(data_, size_); }

  std::uint8_t* data() { return data_; }
  const std::uint8_t* data() const { return data_; }
  std::size_t size() const { return size_; }
  bool empty() const { return size_ == 0; }

  // Resizes to `new_size`, preserving the first min(size(), new_size)
  // bytes. On shrink, the dropped tail is wiped in place (no reallocation
  // needed). On growth past the current allocation's capacity, a new
  // buffer is allocated, the live bytes are copied in, and the OLD buffer
  // is wiped via OPENSSL_cleanse BEFORE being freed -- see the class-level
  // comment above for why this is the whole point of this class existing
  // as its own type rather than a thin wrapper around std::vector.
  void Resize(std::size_t new_size) {
    if (new_size <= capacity_) {
      // No reallocation needed. On shrink, wipe the dropped tail in place;
      // on growth within existing capacity, zero-fill the newly-exposed
      // region (matching std::vector<T>::resize()'s value-initialization
      // of new elements).
      if (new_size < size_) {
        OPENSSL_cleanse(data_ + new_size, size_ - new_size);
      } else if (new_size > size_) {
        std::memset(data_ + size_, 0, new_size - size_);
      }
      size_ = new_size;
      return;
    }

    // Growth past current capacity: allocate new, copy live bytes in,
    // zero-fill the rest, THEN wipe-and-free the old buffer. The old
    // buffer is still valid and accessible right up until ReleaseAndWipe()
    // -- there is no window where a reallocation failure could leave this
    // object's existing secret unwiped-but-already-freed.
    std::uint8_t* new_data = Allocate(new_size);
    if (size_ > 0) std::memcpy(new_data, data_, size_);
    if (new_size > size_) std::memset(new_data + size_, 0, new_size - size_);

    ReleaseAndWipe();
    data_ = new_data;
    size_ = new_size;
    capacity_ = new_size;
  }

  // ---------------------------------------------------------------------
  // Limitations (stated per the project's standing documentation
  // requirement, not because they're unique to this class):
  //
  // - This class wipes memory IT owns and controls deallocation of. It
  //   cannot and does not wipe: copies the compiler makes into CPU
  //   registers during normal use of the data (a key byte loaded into a
  //   register for an AES round is, by definition, outside this class's
  //   reach for the instant it's in that register); compiler-generated
  //   spill slots or temporaries if the optimizer decides to keep a copy
  //   of some bytes on the stack for its own reasons; or any copy made by
  //   calling code that passes data()/size() to a function this class
  //   doesn't control (e.g. OpenSSL's own internal buffers during an AEAD
  //   operation).
  // - An attacker who can read arbitrary process memory WHILE this buffer
  //   is alive and in active use sees the plaintext secret, by
  //   definition -- wiping only helps for memory read AFTER the buffer's
  //   lifetime ends (or after a shrink/grow drops specific bytes), not
  //   during active use. See docs/THREAT_MODEL.md §6 for the general
  //   version of this limitation.
  // - No mlock/VirtualLock: these bytes CAN be paged to disk under memory
  //   pressure, and a swap file or hibernation image could retain them
  //   after the process exits. Locking pages against swap is reasonable
  //   future work, not implemented here (it also has real costs -- locked
  //   pages reduce the memory available to the rest of the system -- that
  //   would need to be weighed, not just turned on unconditionally).
  // ---------------------------------------------------------------------

 private:
  static std::uint8_t* Allocate(std::size_t size) {
    if (size == 0) return nullptr;
    // Plain new[]/delete[] rather than an aligned/locked allocator -- see
    // "Limitations" above re: mlock/VirtualLock being future work, not
    // implemented here.
    return new std::uint8_t[size];
  }

  void ReleaseAndWipe() {
    if (data_) {
      OPENSSL_cleanse(data_, capacity_ > size_ ? capacity_ : size_);
      delete[] data_;
    }
    data_ = nullptr;
    size_ = 0;
    capacity_ = 0;
  }

  std::uint8_t* data_ = nullptr;
  std::size_t size_ = 0;
  std::size_t capacity_ = 0;  // bytes actually allocated at data_; == size_
                              // for every constructor, may exceed size_
                              // only transiently never (Resize always sets
                              // capacity_ == new allocation's size -- this
                              // class does no exponential-growth
                              // over-allocation the way std::vector does,
                              // trading a little performance on repeated
                              // small growths for not having to wipe a
                              // larger-than-necessary region)
};

}  // namespace rtprotect::crypto
