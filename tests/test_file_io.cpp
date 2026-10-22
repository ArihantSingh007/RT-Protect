// tests/test_file_io.cpp
//
// Native Windows unit tests for atomic file writes and secure secret file creation.

#include "tooling/file_io.h"

#include <chrono>
#include <filesystem>
#include <string>
#include <vector>
#include <windows.h>

#include "tests/micro_test.h"

using namespace rtprotect::tooling;

namespace {

std::string MakeTempPath(const char* name_suffix) {
  auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
  auto tmp_dir = std::filesystem::temp_directory_path() / "rtprotect_file_io_test";
  std::filesystem::create_directories(tmp_dir);
  return (tmp_dir / (std::to_string(now) + "_" + name_suffix)).string();
}

}  // namespace

MT_TEST(WriteSecretFile_CreatesFileAndReadsBack) {
  std::string path = MakeTempPath("secret_readback");
  std::error_code ec;
  std::filesystem::remove(path, ec);

  std::vector<std::uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF, 0x42};
  bool ok = WriteSecretFile(path, data.data(), data.size());
  MT_CHECK(ok);

  auto readback = ReadFile(path);
  MT_CHECK(readback.has_value());
  if (readback) {
    MT_CHECK(readback->size() == data.size());
    MT_CHECK(*readback == data);
  }

  std::filesystem::remove(path, ec);
}

MT_TEST(WriteSecretFile_RefusesToOverwriteExistingFile) {
  std::string path = MakeTempPath("no_clobber");
  std::error_code ec;
  std::filesystem::remove(path, ec);

  std::uint8_t first[] = {1, 1, 1};
  MT_CHECK(WriteSecretFile(path, first, sizeof(first)));

  std::uint8_t second[] = {2, 2, 2, 2, 2};
  bool ok = WriteSecretFile(path, second, sizeof(second));
  MT_CHECK(!ok);  // CREATE_NEW must reject overwrite

  auto readback = ReadFile(path);
  MT_CHECK(readback.has_value());
  if (readback) {
    MT_CHECK(readback->size() == sizeof(first));
    MT_CHECK((*readback)[0] == 1);
  }

  std::filesystem::remove(path, ec);
}

MT_TEST(WriteSecretFile_EmptyData) {
  std::string path = MakeTempPath("empty");
  std::error_code ec;
  std::filesystem::remove(path, ec);

  bool ok = WriteSecretFile(path, nullptr, 0);
  MT_CHECK(ok);

  auto readback = ReadFile(path);
  MT_CHECK(readback.has_value());
  if (readback) {
    MT_CHECK(readback->empty());
  }

  std::filesystem::remove(path, ec);
}

MT_TEST(WriteFile_AtomicWriteAndReplace) {
  std::string path = MakeTempPath("atomic_replace");
  std::error_code ec;
  std::filesystem::remove(path, ec);

  std::string text1 = "Initial payload content";
  MT_CHECK(WriteTextFile(path, text1));

  auto read1 = ReadTextFile(path);
  MT_CHECK(read1.has_value());
  if (read1) {
    MT_CHECK(*read1 == text1);
  }

  std::string text2 = "Overwritten replacement payload";
  MT_CHECK(WriteTextFile(path, text2));

  auto read2 = ReadTextFile(path);
  MT_CHECK(read2.has_value());
  if (read2) {
    MT_CHECK(*read2 == text2);
  }

  std::filesystem::remove(path, ec);
}

MT_MAIN()
