// tests/test_file_io.cpp
//
// POSIX-only for now: these tests check actual resulting file permission
// bits via stat(), symlink rejection, and no-clobber behavior, all of
// which are platform-specific concepts. The Windows ACL path in
// tooling/file_io.h's WriteSecretFile() is written to the documented
// Win32 contract but has no equivalent automated test here, since there's
// no Windows runtime in this environment to run one against -- see that
// function's header comment and the main README's Windows-verification
// notes for this standing gap.

#include "tooling/file_io.h"

#include "tests/micro_test.h"

#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#include <cstdlib>
#include <cstring>

using namespace rtprotect::tooling;

namespace {

std::string MakeTempPath(const char* name_suffix) {
  std::string dir = "/tmp/rtprotect_file_io_test";
  mkdir(dir.c_str(), 0700);
  return dir + "/" + std::to_string(getpid()) + "_" + name_suffix;
}

}  // namespace

MT_TEST(WriteSecretFile_CreatesWithOwnerOnlyPermissions) {
  std::string path = MakeTempPath("owner_only");
  unlink(path.c_str());

  std::uint8_t data[] = {1, 2, 3, 4};
  bool ok = WriteSecretFile(path, data, sizeof(data));
  MT_CHECK(ok);

  struct stat st{};
  MT_CHECK(stat(path.c_str(), &st) == 0);
  // Mask to the permission bits only (ignore file-type bits).
  mode_t perms = st.st_mode & 0777;
  MT_CHECK(perms == 0600);

  unlink(path.c_str());
}

MT_TEST(WriteSecretFile_PermissionsNotAffectedByPermissiveUmask) {
  // The whole point of passing mode directly to open() rather than
  // relying on a default mode + umask is that the result must be 0600
  // regardless of the process's umask -- confirmed here by setting an
  // intentionally permissive umask (0) immediately before the call and
  // restoring it immediately after, so this test doesn't leak a changed
  // umask to any other test running in the same process.
  std::string path = MakeTempPath("umask_test");
  unlink(path.c_str());

  mode_t old_umask = umask(0);  // most permissive possible umask
  std::uint8_t data[] = {9};
  bool ok = WriteSecretFile(path, data, sizeof(data));
  umask(old_umask);

  MT_CHECK(ok);
  struct stat st{};
  MT_CHECK(stat(path.c_str(), &st) == 0);
  MT_CHECK((st.st_mode & 0777) == 0600);

  unlink(path.c_str());
}

MT_TEST(WriteSecretFile_RefusesToFollowSymlink) {
  std::string target = MakeTempPath("symlink_target");
  std::string link = MakeTempPath("symlink_link");
  unlink(target.c_str());
  unlink(link.c_str());

  // Create an innocuous target file the symlink points at, to confirm
  // WriteSecretFile does NOT write through the link into it.
  FILE* f = fopen(target.c_str(), "w");
  MT_CHECK(f != nullptr);
  if (f) {
    fputs("original content\n", f);
    fclose(f);
  }

  MT_CHECK(symlink(target.c_str(), link.c_str()) == 0);

  std::uint8_t data[] = {0xDE, 0xAD};
  bool ok = WriteSecretFile(link, data, sizeof(data));
  MT_CHECK(!ok);  // O_NOFOLLOW must cause this to fail, not write through
                   // the symlink

  // The target file's original content must be untouched.
  FILE* check = fopen(target.c_str(), "r");
  MT_CHECK(check != nullptr);
  if (check) {
    char buf[64] = {0};
    // fgets()'s return value is checked explicitly -- glibc's
    // _FORTIFY_SOURCE (enabled implicitly at -O1 and above, which is why
    // this only surfaced in a Release build, not Debug's -O0) marks
    // fgets() warn_unused_result; a genuine, legitimate warning fixed
    // here rather than suppressed, consistent with this project's
    // zero-warnings standard holding for test code too, not only the
    // library itself.
    char* read_ok = fgets(buf, sizeof(buf), check);
    fclose(check);
    MT_CHECK(read_ok != nullptr);
    MT_CHECK(std::strcmp(buf, "original content\n") == 0);
  }

  unlink(link.c_str());
  unlink(target.c_str());
}

MT_TEST(WriteSecretFile_RefusesToOverwriteExistingFile) {
  std::string path = MakeTempPath("no_clobber");
  unlink(path.c_str());

  std::uint8_t first[] = {1, 1, 1};
  MT_CHECK(WriteSecretFile(path, first, sizeof(first)));

  std::uint8_t second[] = {2, 2, 2, 2, 2};
  bool ok = WriteSecretFile(path, second, sizeof(second));
  MT_CHECK(!ok);  // O_EXCL must reject the second write -- the first
                   // file's content must be the one still on disk

  auto readback = ReadFile(path);
  MT_CHECK(readback.has_value());
  if (readback) {
    MT_CHECK(readback->size() == 3);
    MT_CHECK((*readback)[0] == 1);
  }

  unlink(path.c_str());
}

MT_TEST(WriteSecretFile_EmptyData_StillCreatesRestrictedFile) {
  std::string path = MakeTempPath("empty");
  unlink(path.c_str());

  bool ok = WriteSecretFile(path, nullptr, 0);
  MT_CHECK(ok);
  struct stat st{};
  MT_CHECK(stat(path.c_str(), &st) == 0);
  MT_CHECK(st.st_size == 0);
  MT_CHECK((st.st_mode & 0777) == 0600);

  unlink(path.c_str());
}

MT_MAIN()

#else  // _WIN32

// No automated test here -- see this file's header comment.
int main() { return 0; }

#endif
