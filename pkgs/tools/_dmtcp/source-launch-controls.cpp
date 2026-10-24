// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (c) 2026 Andyl, Inc.
#include "source-launch-peer-controls.h"

#include <pwd.h>
#include <sys/resource.h>
#include <sys/utsname.h>

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <unistd.h>

using namespace dmtcp_crucible::original_unix_peer;

static bool waitReadable(int fd)
{
  pollfd event{fd, POLLIN, 0};
  const timespec remaining{20, 0};
  return kernelCall(SYS_ppoll, reinterpret_cast<long>(&event), 1,
                    reinterpret_cast<long>(&remaining), 0, 0) == 1 &&
         (event.revents & POLLIN);
}

int main(int argc, char **argv)
{
  assert(argc == 4);
  const char *toolkit = argv[1];
  const char *application = argv[2];
  const char *temporary = argv[3];
  const std::string portFile = std::string(temporary) + "/port";
  const char *portPath = portFile.c_str();
  const std::string coordinator = std::string(toolkit) + "/bin/dmtcp_coordinator";
  const std::string launcher = std::string(toolkit) + "/bin/dmtcp_launch";

  rlimit descriptorLimit{1024, 1024};
  assert(setrlimit(RLIMIT_NOFILE, &descriptorLimit) == 0);
  passwd *user = getpwuid(geteuid());
  assert(user && user->pw_name);
  utsname machine{};
  assert(uname(&machine) == 0);
  const std::string logRoot = std::string(temporary) + "/dmtcp-" + user->pw_name + "@" + machine.nodename;
  assert(mkdir(logRoot.c_str(), 0700) == 0);
  assert(setenv("TMPDIR", temporary, 1) == 0);
  assert(setenv("CRUCIBLE_CAPTURE_LOG_ROOT", logRoot.c_str(), 1) == 0);
  const char *selectors[][2] = {
    {"CRUCIBLE_CAPTURE_PROCESS_POLICY", "cfi-single-worker-control.v3"},
    {"CRUCIBLE_CAPTURE_WRITER_COHORT_POLICY", "cohort.v1"},
    {"CRUCIBLE_CAPTURE_CONTROL_PARK_POLICY", "terminal.v1"},
    {"CRUCIBLE_CAPTURE_COORDINATOR_WRITER_POLICY", "restart-script.v1"},
    {"CRUCIBLE_CAPTURE_LOG_WRITER_POLICY", "assert-log.v1"},
    {"CRUCIBLE_CAPTURE_MAP_ENVELOPE_POLICY", "map-envelope.v1"},
    {"CRUCIBLE_CAPTURE_EXEC_CUSTODY_POLICY", "exec-custody.v1"},
    {"CRUCIBLE_NATIVE_SHARED_PROFILE", "shared-birth.v1"},
    {"CRUCIBLE_NATIVE_THREAD_PROFILE", "atomic-loop.v1"},
    {"CRUCIBLE_CAPTURE_CONTROL_COOKIE", "1111111111111111111111111111111111111111111111111111111111111111"},
    {"DMTCP_QUIET", "2"},
  };
  for (const auto &selector : selectors)
    assert(setenv(selector[0], selector[1], 1) == 0);

  // Each native producer adopts a private empty0600 console. Sharing the
  // outer controller's log would mix unrelated file offsets and debit banks.
  Descriptor originalControllerConsole;
  originalControllerConsole.number = int(kernelCall(SYS_fcntl, STDERR_FILENO,
                                                     F_DUPFD_CLOEXEC, 0));
  assert(originalControllerConsole.number >= 0);
  const std::string coordinatorConsolePath = std::string(temporary) + "/coordinator-console";
  const std::string applicationConsolePath = std::string(temporary) + "/application-console";
  Descriptor coordinatorConsole;
  Descriptor applicationConsole;
  coordinatorConsole.number = int(kernelCall(SYS_openat, AT_FDCWD,
      reinterpret_cast<long>(coordinatorConsolePath.c_str()),
      O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
  assert(coordinatorConsole.number >= 0);
  applicationConsole.number = int(kernelCall(SYS_openat, AT_FDCWD,
      reinterpret_cast<long>(applicationConsolePath.c_str()),
      O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
  assert(applicationConsole.number >= 0);

  // This original literal child is held before any further probe or effect.
  const long coordinatorPid = kernelCall(SYS_fork);
  assert(coordinatorPid >= 0);
  if (coordinatorPid == 0) {
    if (kernelCall(SYS_dup2, coordinatorConsole.number, STDERR_FILENO) != STDERR_FILENO) {
      kernelCall(SYS_exit_group, 125);
      __builtin_unreachable();
    }
    char *arguments[] = {const_cast<char *>(coordinator.c_str()),
      const_cast<char *>("--quiet"), const_cast<char *>("--quiet"),
      const_cast<char *>("--coord-port"), const_cast<char *>("0"),
      const_cast<char *>("--port-file"), const_cast<char *>(portPath),
      const_cast<char *>("--tmpdir"), const_cast<char *>(temporary),
      const_cast<char *>("--exit-on-last"), const_cast<char *>("--timeout"),
      const_cast<char *>("35"), nullptr};
    extern char **environ;
    kernelCall(SYS_execve, reinterpret_cast<long>(coordinator.c_str()),
               reinterpret_cast<long>(arguments), reinterpret_cast<long>(environ));
    kernelCall(SYS_exit_group, 125);
    __builtin_unreachable();
  }
  Descriptor coordinatorDeath;
  coordinatorDeath.number = int(kernelCall(SYS_pidfd_open, coordinatorPid, 0));
  assert(coordinatorDeath.number >= 0);

  char port[16]{};
  for (unsigned attempt = 0; attempt != 200; ++attempt) {
    const int file = int(kernelCall(SYS_openat, AT_FDCWD,
                                  reinterpret_cast<long>(portPath), O_RDONLY | O_CLOEXEC));
    if (file >= 0) {
      const long count = kernelCall(SYS_read, file, reinterpret_cast<long>(port), sizeof(port) - 1);
      assert(kernelCall(SYS_close, file) == 0);
      if (count > 0) {
        if (port[count - 1] == '\n') port[count - 1] = 0;
        break;
      }
    }
    const timespec interval{0, 50 * 1000 * 1000};
    kernelCall(SYS_nanosleep, reinterpret_cast<long>(&interval), 0);
  }
  assert(port[0] != 0);
  auto *original = OriginalUnixPeer::reserveProcessLifetime();
  assert(original && original->prepareSourceExec(launcher.c_str(), application));
  char *arguments[] = {const_cast<char *>(launcher.c_str()),
    const_cast<char *>("--join-coordinator"), const_cast<char *>("--coord-host"),
    const_cast<char *>("127.0.0.1"), const_cast<char *>("--coord-port"), port,
    const_cast<char *>("--interval"), const_cast<char *>("0"),
    const_cast<char *>("--no-gzip"), const_cast<char *>("--tmpdir"),
    const_cast<char *>(temporary), const_cast<char *>(application), nullptr};
  extern char **environ;
  // The launcher and final application retain the SAME native console
  // across their authenticated exec. Restore the controller's unrelated
  // diagnostics before evaluating or reporting the launch result.
  assert(kernelCall(SYS_dup2, applicationConsole.number, STDERR_FILENO) == STDERR_FILENO);
  const bool launched = original->launch(arguments, environ);
  assert(kernelCall(SYS_dup2, originalControllerConsole.number, STDERR_FILENO) == STDERR_FILENO);
  assert(launched);
  assert(original->originalArgumentCount() == 12);
  assert(waitReadable(original->originalChannel()));
  assert(original->receiveOffer());
  std::array<unsigned char, 344> expected{};
  const char marker[] = "ORIGINAL-SHARED-EXEC-OBSERVATION-V1";
  std::memcpy(expected.data(), marker, sizeof(marker));
  assert(original->originalOffer() == expected);
  std::printf("Actual same kernel child %ld authenticated after selected launcher/library exec; native observation marker only.\n",
              original->originalChildPid());

  assert(original->cancel());
  assert(waitReadable(original->originalDeathDescriptor()));
  assert(original->retire());
  std::printf("Selected original application status=%d after original cancellation\n",
              original->originalTerminalStatus());
  std::fflush(stdout);
  assert(WIFSIGNALED(original->originalTerminalStatus()));
  assert(WTERMSIG(original->originalTerminalStatus()) == SIGKILL);

  assert(waitReadable(coordinatorDeath.number));
  int status;
  assert(kernelCall(SYS_wait4, coordinatorPid, reinterpret_cast<long>(&status), 0, 0)
         == coordinatorPid);
  // Intentional cancellation closes the selected worker's original stream.
  // Its finite selected reader refuses EOF before generic exit-on-last logic.
  std::printf("Observed original app terminal=%d; coordinator terminal=%d\n",
              original->originalTerminalStatus(), status);
  std::fflush(stdout);
  assert(WIFEXITED(status) && WEXITSTATUS(status) == 86);
  assert(coordinatorDeath.closeOnce());
  assert(coordinatorConsole.closeOnce());
  assert(applicationConsole.closeOnce());
  assert(originalControllerConsole.closeOnce());
  std::puts("Original normal launch peers reaped; no checkpoint/native graph/cut/adoption/Ready claimed.");
}
