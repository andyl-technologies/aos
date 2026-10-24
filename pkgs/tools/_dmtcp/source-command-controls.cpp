// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (c) 2026 Andyl, Inc.
#include "dmtcp_source_command.h"

#include <cassert>
#include <cstdio>
#include <string>
#include <fcntl.h>
#include <poll.h>
#include <sys/syscall.h>
#include <cstdlib>

static void interruptHandler(int) {}

struct Invocation
{
  const char *shell;
  const char *command;
  int status = -1;
};

static void *invoke(void *argument)
{
  auto &invocation = *static_cast<Invocation *>(argument);
  invocation.status = dmtcp_source_command::run(invocation.shell, invocation.command);
  return nullptr;
}

int main(int argc, char **argv)
{
  assert(argc == 5);
  const char *shell = argv[1];
  struct sigaction original{};
  struct sigaction handler{};
  handler.sa_handler = interruptHandler;
  sigemptyset(&handler.sa_mask);
  assert(sigaction(SIGINT, &handler, &original) == 0);
  sigset_t before;
  assert(pthread_sigmask(SIG_BLOCK, nullptr, &before) == 0);

  assert(dmtcp_source_command::run(shell, nullptr) == 1);
  assert(dmtcp_source_command::run(shell, "exit 7") == W_EXITCODE(7, 0));
  const int signalStatus = dmtcp_source_command::run(shell, "kill -TERM $$");
  assert(WIFSIGNALED(signalStatus) && WTERMSIG(signalStatus) == SIGTERM);
  assert(dmtcp_source_command::run("/nonexistent-source-shell", "exit 0") ==
         W_EXITCODE(127, 0));

  // Observe the actual shell ELF through procfs using the pinned AOS tool.
  const std::string command = std::string("test \"$(") + argv[2] +
      " /proc/$$/exe)\" = '" + shell + "'";
  assert(dmtcp_source_command::run(shell, command.c_str()) == 0);

  // Exercise literal operands through the actual pinned copy program. Shell
  // punctuation and newlines belong to the filenames, not the command grammar.
  const std::string sourcePath = std::string(argv[3]) +
      "/source ' \" $(false); (copy)\ninput";
  const std::string destinationPath = std::string(argv[3]) +
      "/destination ' \" $(false); (copy)\noutput";
  const int source = open(sourcePath.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
  assert(source >= 0);
  assert(write(source, "literal copy\n", 13) == 13);
  assert(close(source) == 0);

  const std::string copyCommand = dmtcp_source_command::copyCommand(
      argv[4], sourcePath.c_str(), destinationPath.c_str());
  assert(dmtcp_source_command::run(shell, copyCommand.c_str()) == 0);
  const int destination = open(destinationPath.c_str(), O_RDONLY | O_NOFOLLOW);
  assert(destination >= 0);
  char copied[14]{};
  assert(read(destination, copied, sizeof(copied)) == 13);
  assert(std::string(copied) == "literal copy\n");
  assert(close(destination) == 0);

  Invocation first{shell, "exit 3"};
  Invocation second{shell, "exit 4"};
  pthread_t threads[2];
  assert(pthread_create(&threads[0], nullptr, invoke, &first) == 0);
  assert(pthread_create(&threads[1], nullptr, invoke, &second) == 0);
  assert(pthread_join(threads[0], nullptr) == 0);
  assert(pthread_join(threads[1], nullptr) == 0);
  assert(first.status == W_EXITCODE(3, 0));
  assert(second.status == W_EXITCODE(4, 0));

  const std::string childFile = std::string(argv[3]) + "/cancel-child";
  const std::string waitingCommand = "umask 077; printf '%s\\n' \"$$\" > '" +
      childFile + "'; while :; do :; done";
  Invocation canceled{shell, waitingCommand.c_str()};
  pthread_t waitingThread;
  assert(pthread_create(&waitingThread, nullptr, invoke, &canceled) == 0);

  char childText[32]{};
  for (unsigned attempt = 0; attempt != 1000; ++attempt) {
    const int descriptor = open(childFile.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor >= 0) {
      const ssize_t size = read(descriptor, childText, sizeof(childText) - 1);
      assert(close(descriptor) == 0);
      if (size > 0) break;
    }
    const timespec interval{0, 5000000};
    nanosleep(&interval, nullptr);
  }
  char *end = nullptr;
  const long child = std::strtol(childText, &end, 10);
  assert(child > 0 && end && *end == '\n');
  const int death = int(syscall(SYS_pidfd_open, child, 0));
  assert(death >= 0);
  pollfd observed{death, POLLIN, 0};
  assert(poll(&observed, 1, 0) == 0);

  assert(pthread_cancel(waitingThread) == 0);
  void *threadResult = nullptr;
  assert(pthread_join(waitingThread, &threadResult) == 0);
  assert(threadResult == PTHREAD_CANCELED);
  assert(poll(&observed, 1, 5000) == 1 && (observed.revents & POLLIN));
  int childStatus;
  assert(waitpid(pid_t(child), &childStatus, WNOHANG) == -1 && errno == ECHILD);
  assert(close(death) == 0);

  struct sigaction after{};
  sigset_t afterMask;
  assert(sigaction(SIGINT, nullptr, &after) == 0);
  assert(after.sa_handler == interruptHandler);
  assert(pthread_sigmask(SIG_BLOCK, nullptr, &afterMask) == 0);
  assert(sigismember(&before, SIGCHLD) == sigismember(&afterMask, SIGCHLD));
  assert(sigaction(SIGINT, &original, nullptr) == 0);
  std::puts("Actual source shell ELF, encoded exit/signal/failure status, concurrent commands, canceled helper retirement and signal restoration passed; no native cut authority.");
}
