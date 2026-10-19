# Two targets, deliberately separate -- this is a build-system-enforced
# version of the trust boundary documented in keys.h / signer.h's file
# headers, not just a comment:
#
#   rtprotect_integrity            -- ships in the client. Hashing,
#                                      manifest (de)serialization, and
#                                      SIGNATURE VERIFICATION ONLY. Contains
#                                      no code path that can produce a
#                                      signature.
#   rtprotect_integrity_buildtools -- NEVER linked into anything that ships.
#                                      Key generation and signing. Only
#                                      Phase 7's offline release-signing CLI
#                                      and this project's own tests (which
#                                      need to produce validly-signed
#                                      fixtures) should ever link this.
#
# If a future target accidentally links rtprotect_integrity_buildtools
# alongside application code meant to ship, that's a visible, reviewable
# line in that target's CMakeLists -- exactly the kind of mistake this
# split is meant to make easy to catch in review.

add_library(rtprotect_integrity STATIC
    sha256.cpp
    manifest.cpp
    verifier.cpp
    bound_key.cpp
)
target_include_directories(rtprotect_integrity PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(rtprotect_integrity PUBLIC OpenSSL::Crypto rtprotect_crypto)

add_library(rtprotect_integrity_buildtools STATIC
    keys.cpp
    signer.cpp
)
target_include_directories(rtprotect_integrity_buildtools PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(rtprotect_integrity_buildtools PUBLIC OpenSSL::Crypto)
