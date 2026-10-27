// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (c) 2026 Andyl, Inc.
#include "source-launch-peer-controls.h"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <string>

using namespace dmtcp_crucible::original_unix_peer;

static void waitOriginalDeath(int descriptor)
{
  pollfd event{descriptor, POLLIN, 0};
  const timespec deadline{20, 0};
  assert(kernelCall(SYS_ppoll, reinterpret_cast<long>(&event), 1,
                    reinterpret_cast<long>(&deadline), 0, 0) == 1);
  assert(event.revents & POLLIN);
}

static Descriptor holdOriginalChild(long child)
{
  Descriptor death;
  death.number = int(kernelCall(SYS_pidfd_open, child, 0));
  assert(death.number >= 0);
  return death;
}

static Descriptor createConsole(const std::string &path)
{
  Descriptor console;
  console.number = int(kernelCall(SYS_openat, AT_FDCWD,
      reinterpret_cast<long>(path.c_str()),
      O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
  assert(console.number >= 0);
  return console;
}

int main(int argc, char **argv)
{
  assert(argc == 4);
  assert(std::getenv("CRUCIBLE_CAPTURE_PROCESS_POLICY") == nullptr);
  assert(std::getenv("CRUCIBLE_NATIVE_THREAD_PROFILE") == nullptr);
  assert(std::getenv("CRUCIBLE_NATIVE_SHARED_PROFILE") == nullptr);

  const std::string toolkit = argv[1];
  const std::string temporary = argv[3];
  const std::string coordinator = toolkit + "/bin/dmtcp_coordinator";
  const std::string launcher = toolkit + "/bin/dmtcp_launch";
  const std::string portPath = temporary + "/port";
  auto coordinatorConsole = createConsole(temporary + "/coordinator-console");
  auto applicationConsole = createConsole(temporary + "/application-console");
  assert(setenv("TMPDIR", temporary.c_str(), 1) == 0);
  assert(setenv("DMTCP_QUIET", "2", 1) == 0);

  const long coordinatorPid = kernelCall(SYS_fork);
  assert(coordinatorPid >= 0);
  if (coordinatorPid == 0) {
    assert(kernelCall(SYS_dup2, coordinatorConsole.number, STDERR_FILENO) == STDERR_FILENO);
    char *arguments[] = {const_cast<char *>(coordinator.c_str()),
      const_cast<char *>("--quiet"), const_cast<char *>("--quiet"),
      const_cast<char *>("--coord-port"), const_cast<char *>("0"),
      const_cast<char *>("--port-file"), const_cast<char *>(portPath.c_str()),
      const_cast<char *>("--tmpdir"), const_cast<char *>(temporary.c_str()),
      const_cast<char *>("--exit-on-last"), const_cast<char *>("--timeout"),
      const_cast<char *>("35"), nullptr};
    extern char **environ;
    kernelCall(SYS_execve, reinterpret_cast<long>(coordinator.c_str()),
               reinterpret_cast<long>(arguments), reinterpret_cast<long>(environ));
    kernelCall(SYS_exit_group, 125);
    __builtin_unreachable();
  }
  auto coordinatorDeath = holdOriginalChild(coordinatorPid);

  char port[16]{};
  for (unsigned attempt = 0; attempt != 200; ++attempt) {
    const long descriptor = kernelCall(SYS_openat, AT_FDCWD,
        reinterpret_cast<long>(portPath.c_str()), O_RDONLY | O_NOFOLLOW | O_CLOEXEC, 0);
    if (descriptor >= 0) {
      const long size = kernelCall(SYS_read, descriptor, reinterpret_cast<long>(port), 15);
      assert(kernelCall(SYS_close, descriptor) == 0);
      if (size > 0) break;
    }
    const timespec interval{0, 50000000};
    kernelCall(SYS_nanosleep, reinterpret_cast<long>(&interval), 0);
  }
  assert(port[0] != 0);

  const long applicationPid = kernelCall(SYS_fork);
  assert(applicationPid >= 0);
  if (applicationPid == 0) {
    assert(kernelCall(SYS_dup2, applicationConsole.number, STDERR_FILENO) == STDERR_FILENO);
    char *arguments[] = {const_cast<char *>(launcher.c_str()),
      const_cast<char *>("--quiet"), const_cast<char *>("--quiet"),
      const_cast<char *>("--join-coordinator"), const_cast<char *>("--coord-port"),
      port, const_cast<char *>("--tmpdir"), const_cast<char *>(temporary.c_str()),
      argv[2], nullptr};
    extern char **environ;
    kernelCall(SYS_execve, reinterpret_cast<long>(launcher.c_str()),
               reinterpret_cast<long>(arguments), reinterpret_cast<long>(environ));
    kernelCall(SYS_exit_group, 125);
    __builtin_unreachable();
  }
  auto applicationDeath = holdOriginalChild(applicationPid);

  waitOriginalDeath(applicationDeath.number);
  int applicationStatus = -1;
  assert(kernelCall(SYS_wait4, applicationPid,
      reinterpret_cast<long>(&applicationStatus), 0, 0) == applicationPid);
  std::printf("Nonselected original application status=%d\n", applicationStatus);
  std::fflush(stdout);
  assert(WIFEXITED(applicationStatus) && WEXITSTATUS(applicationStatus) == 0);

  waitOriginalDeath(coordinatorDeath.number);
  int coordinatorStatus = -1;
  assert(kernelCall(SYS_wait4, coordinatorPid,
      reinterpret_cast<long>(&coordinatorStatus), 0, 0) == coordinatorPid);
  std::printf("Nonselected original coordinator status=%d\n", coordinatorStatus);
  std::fflush(stdout);
  assert(WIFEXITED(coordinatorStatus) && WEXITSTATUS(coordinatorStatus) == 0);

  assert(applicationDeath.closeOnce());
  assert(coordinatorDeath.closeOnce());
  assert(applicationConsole.closeOnce());
  assert(coordinatorConsole.closeOnce());
  std::puts("Unchanged nonselected normal worker/exit-on-last lifecycle exits0; no native cut authority.");
}
