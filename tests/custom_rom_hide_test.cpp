/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include <fcntl.h>
#include <linux/magic.h>
#include <sys/statfs.h>
#include <unistd.h>

#include <sstream>
#include <string>

#include "../libc/bionic/custom_rom_hide.h"

// Exercise the app gate without changing the host process's credentials.
extern "C" uid_t getuid() noexcept { return 10000; }

namespace {
class ScopedFd {
 public:
  explicit ScopedFd(int fd) : fd_(fd) {}
  ~ScopedFd() {
    custom_rom_hide_unregister_fd(fd_);
    if (fd_ >= 0) close(fd_);
  }
  int get() const { return fd_; }
 private:
  int fd_;
};

std::string ReadAll(int fd) {
  std::string out;
  char buf[4096];
  ssize_t n;
  while ((n = read(fd, buf, sizeof(buf))) > 0) out.append(buf, n);
  EXPECT_EQ(0, n);
  return out;
}

std::string MountOptions(const std::string& mounts, const std::string& target) {
  std::istringstream lines(mounts);
  std::string line;
  while (std::getline(lines, line)) {
    std::istringstream fields(line);
    std::string source, mount, type, options;
    if (fields >> source >> mount >> type >> options && mount == target) return options;
  }
  return {};
}
}

TEST(custom_rom_hide, equivalent_openat_paths) {
  ScopedFd dir(open("/proc/self", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  ASSERT_GE(dir.get(), 0);
  ScopedFd absolute(custom_rom_hide_openat(AT_FDCWD, "/proc/self/mounts", O_RDONLY, 0));
  ScopedFd relative(custom_rom_hide_openat(dir.get(), "mounts", O_RDONLY, 0));
  ScopedFd ignored_dirfd(custom_rom_hide_openat(-1, "/proc/self/mounts", O_RDONLY, 0));
  ASSERT_GE(absolute.get(), 0);
  ASSERT_GE(relative.get(), 0);
  ASSERT_GE(ignored_dirfd.get(), 0);
  std::string expected = ReadAll(absolute.get());
  ASSERT_FALSE(expected.empty());
  EXPECT_EQ(expected, ReadAll(relative.get()));
  EXPECT_EQ(expected, ReadAll(ignored_dirfd.get()));
}

TEST(custom_rom_hide, substituted_descriptor_is_read_only) {
  ScopedFd fd(custom_rom_hide_openat(AT_FDCWD, "/proc/self/mounts", O_RDONLY, 0));
  ASSERT_GE(fd.get(), 0);
  struct statfs fs;
  ASSERT_EQ(0, fstatfs(fd.get(), &fs));
  ASSERT_EQ(TMPFS_MAGIC, fs.f_type);
  EXPECT_EQ(O_RDONLY, fcntl(fd.get(), F_GETFL) & O_ACCMODE);
  errno = 0;
  EXPECT_EQ(-1, write(fd.get(), "x", 1));
  EXPECT_EQ(EBADF, errno);
  EXPECT_FALSE(ReadAll(fd.get()).empty());
}

TEST(custom_rom_hide, cloexec_is_preserved) {
  for (int flags : {O_RDONLY, O_RDONLY | O_CLOEXEC}) {
    ScopedFd fd(custom_rom_hide_openat(AT_FDCWD, "/proc/self/mounts", flags, 0));
    ASSERT_GE(fd.get(), 0);
    EXPECT_EQ((flags & O_CLOEXEC) ? FD_CLOEXEC : 0, fcntl(fd.get(), F_GETFD) & FD_CLOEXEC);
  }
}

TEST(custom_rom_hide, nofollow_rejects_a_symlink) {
  errno = 0;
  ScopedFd fd(custom_rom_hide_openat(AT_FDCWD, "/proc/mounts", O_RDONLY | O_NOFOLLOW, 0));
  EXPECT_EQ(-1, fd.get());
  EXPECT_EQ(ELOOP, errno);
}

TEST(custom_rom_hide, directory_flag_rejects_a_regular_file) {
  errno = 0;
  ScopedFd fd(custom_rom_hide_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY | O_DIRECTORY, 0));
  EXPECT_EQ(-1, fd.get());
  EXPECT_EQ(ENOTDIR, errno);
}

TEST(custom_rom_hide, path_flag_preserves_the_original_object) {
  ScopedFd fd(custom_rom_hide_openat(AT_FDCWD, "/proc/self/maps", O_PATH | O_CLOEXEC, 0));
  ASSERT_GE(fd.get(), 0);
  EXPECT_NE(0, fcntl(fd.get(), F_GETFL) & O_PATH);
  struct statfs fs;
  ASSERT_EQ(0, fstatfs(fd.get(), &fs));
  EXPECT_EQ(PROC_SUPER_MAGIC, fs.f_type);
}

TEST(custom_rom_hide, writable_open_preserves_kernel_behavior) {
  errno = 0;
  ScopedFd native(open("/proc/self/mounts", O_RDWR));
  int expected_errno = errno;
  errno = 0;
  ScopedFd actual(custom_rom_hide_openat(AT_FDCWD, "/proc/self/mounts", O_RDWR, 0));
  if (native.get() < 0) {
    EXPECT_EQ(-1, actual.get());
    EXPECT_EQ(expected_errno, errno);
  } else {
    ASSERT_GE(actual.get(), 0);
    struct statfs fs;
    ASSERT_EQ(0, fstatfs(actual.get(), &fs));
    EXPECT_EQ(PROC_SUPER_MAGIC, fs.f_type);
    EXPECT_EQ(O_RDWR, fcntl(actual.get(), F_GETFL) & O_ACCMODE);
  }
}

TEST(custom_rom_hide, non_partition_mount_options_are_unchanged) {
  ScopedFd native(open("/proc/self/mounts", O_RDONLY));
  ScopedFd filtered(custom_rom_hide_openat(AT_FDCWD, "/proc/self/mounts", O_RDONLY, 0));
  ASSERT_GE(native.get(), 0);
  ASSERT_GE(filtered.get(), 0);
  std::string expected = MountOptions(ReadAll(native.get()), "/proc");
  ASSERT_FALSE(expected.empty());
  EXPECT_EQ(expected, MountOptions(ReadAll(filtered.get()), "/proc"));
}
