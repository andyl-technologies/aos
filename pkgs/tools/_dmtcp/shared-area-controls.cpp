// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (c) 2026 Andyl, Inc.
#include "crucible_original_shared_area.h"
// Existing upstream allocator declarations have unused placement-new extents.
// Keep strict diagnostics on the new bank and controls.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include "crucible_exec_state.h"
#pragma GCC diagnostic pop

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <pthread.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace dmtcp_crucible;
using original_shared_area::OriginalSharedArea;
using original_shared_area::OriginalRecord;

// Actual kernel file/map/exec effects are exercised here. The small test
// handoff is not the production complete exec-custody journal and cannot
// authorize a native process cut, checkpoint, branch or SourceReady.
constexpr int SharedDescriptor = 996;
constexpr int HandoffDescriptor = 995;
constexpr size_t PageBytes = 4096;
constexpr size_t RecordBytes = 29 * 8;

static OriginalSharedArea owner;
static OriginalSharedArea *threadTarget = &owner;

static OriginalRecord createOriginal(const char *path)
{
  assert(owner.begin(PageBytes, SharedDescriptor));
  assert(owner.openOriginal(path) >= 0);
  assert(owner.extendOriginal());
  assert(owner.transferOriginal());
  assert(owner.beginMapping());

  void *mapping = mmap(nullptr, PageBytes, PROT_READ | PROT_WRITE,
                       MAP_SHARED, SharedDescriptor, 0);
  assert(owner.mappedOriginal(mapping));
  std::memcpy(mapping, "original", 9);
  assert(pwrite(SharedDescriptor, "x", 1, PageBytes) == 1);
  assert(owner.headerWritten());
  const auto &actual = owner.originalRecord();
  assert(actual.mappingAttempt == 1 && actual.mappingSlotsReserved == 2);
  assert(actual.openAttempt == 1 && actual.closeAttempt == 1);
  assert(actual.sourceDescriptor == -1 && actual.closeCompleted);
  return actual;
}

static int receiveAfterExec()
{
  unsigned char bytes[RecordBytes]{};
  assert(read(HandoffDescriptor, bytes, sizeof(bytes)) == sizeof(bytes));
  assert(close(HandoffDescriptor) == 0);
  OriginalRecord received{};
  exec_state::Reader reader(bytes, sizeof(bytes));
  original_shared_area::preservationFields(reader, received);
  assert(reader.complete());

  assert(owner.importExecPreservation(received));
  assert(owner.beginMapping());
  void *mapping = mmap(nullptr, PageBytes, PROT_READ | PROT_WRITE,
                       MAP_SHARED, SharedDescriptor, 0);
  assert(owner.mappedOriginal(mapping));
  assert(std::memcmp(mapping, "original", 9) == 0);
  const auto &actual = owner.originalRecord();
  assert(actual.process == received.process);
  assert(actual.device == received.device && actual.inode == received.inode);
  assert(actual.mappingAddress == received.mappingAddress);
  assert(actual.libraryMappingAddress == reinterpret_cast<uintptr_t>(mapping));
  assert(actual.openAttempt == 1 && actual.resizeAttempt == 1);
  assert(actual.duplicateAttempt == 1 && actual.closeAttempt == 1);
  assert(actual.mappingAttempt == 2 && actual.mappingStorageReserved == 2 * PageBytes);
  assert(actual.execImported && actual.libraryMappingCompleted);
  assert(owner.observeExec());

  // A third mapping attempt consumes no renewed slot or kernel mmap effect.
  assert(!owner.beginMapping());
  assert(owner.originalRecord().mappingAttempt == 2);
  assert(owner.originalRecord().refused);
  assert(munmap(mapping, PageBytes) == 0);
  assert(close(SharedDescriptor) == 0);
  return 0;
}

static void execOriginal(OriginalRecord record)
{
  unsigned char bytes[RecordBytes]{};
  exec_state::Writer writer(bytes, sizeof(bytes));
  original_shared_area::preservationFields(writer, record);
  assert(writer.valid() && writer.size() == sizeof(bytes));
  int descriptors[2];
  assert(pipe(descriptors) == 0);
  assert(write(descriptors[1], bytes, sizeof(bytes)) == sizeof(bytes));
  assert(close(descriptors[1]) == 0);
  assert(dup2(descriptors[0], HandoffDescriptor) == HandoffDescriptor);
  assert(close(descriptors[0]) == 0);
  char executable[4096]{};
  const ssize_t extent = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
  assert(extent > 0 && extent < ssize_t(sizeof(executable) - 1));
  char argument[] = "receive";
  char *arguments[] = {executable, argument, nullptr};
  execv(executable, arguments);
  assert(false);
}

static void *foreignThread(void *)
{
  threadTarget->beginMapping();
  _exit(1);
}

int main(int count, char **arguments)
{
  if (count == 2 && std::strcmp(arguments[1], "receive") == 0)
    return receiveAfterExec();
  assert(count == 3);
  const int selected = std::atoi(arguments[1]);
  const char *path = arguments[2];

  if (selected == 1) {
    int existing = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
    assert(existing >= 0 && write(existing, "held", 4) == 4);
    assert(owner.begin(PageBytes, SharedDescriptor));
    assert(owner.openOriginal(path) == -1);
    assert(owner.originalRecord().openAttempt == 1 && owner.originalRecord().refused);
    assert(!owner.begin(PageBytes, SharedDescriptor));
    char bytes[4]{};
    assert(pread(existing, bytes, sizeof(bytes), 0) == sizeof(bytes));
    assert(std::memcmp(bytes, "held", 4) == 0);
    assert(close(existing) == 0);
    assert(unlink(path) == 0);
    return 0;
  }

  OriginalRecord record = createOriginal(path);
  if (selected == 0) {
    // The actual created file can be removed only after the successor exits;
    // a source-owned parent harness retains cleanup custody for that path.
    execOriginal(record);
  } else if (selected == 2 || selected == 3 || selected == 7) {
    OriginalSharedArea separate;
    if (selected == 2) record.mappingAttempt = 0;
    if (selected == 7) record.protectedDescriptor += std::int64_t(1) << 32;
    if (selected == 3) {
      int replacement = open("/dev/null", O_RDWR);
      assert(replacement >= 0);
      assert(dup2(replacement, SharedDescriptor) == SharedDescriptor);
      assert(close(replacement) == 0);
    }
    assert(!separate.importExecPreservation(record));
    assert(separate.originalRecord().refused);
    assert(!separate.importExecPreservation(record));
  } else if (selected == 4 || selected == 5) {
    const pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
      if (selected == 4) {
        owner.beginMapping();
        _exit(1);
      }
      // This child owns a fresh account on its main thread. The worker then
      // differs only by actual TID, so a PID-only gate would reach exit1.
      OriginalSharedArea childOwner;
      threadTarget = &childOwner;
      pthread_t thread;
      assert(pthread_create(&thread, nullptr, foreignThread, nullptr) == 0);
      pthread_join(thread, nullptr);
      _exit(1);
    }
    int status = 0;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 125);
    assert(!owner.originalRecord().refused);
  } else if (selected == 6) {
    const pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
      OriginalSharedArea newProcess;
      assert(!newProcess.importExecPreservation(record));
      assert(newProcess.originalRecord().refused);
      _exit(0);
    }
    int status = 0;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  } else {
    assert(false);
  }

  assert(munmap(reinterpret_cast<void *>(record.mappingAddress), PageBytes) == 0);
  assert(close(SharedDescriptor) == 0);
  assert(unlink(path) == 0);
  std::puts("actual shared-area control passed");
}
