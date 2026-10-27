// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (c) 2026 Andyl, Inc.
#include "crucible_original_thread_owner.h"

#include <cassert>
#include <cerrno>
#include <cstdio>
#include <semaphore.h>
#include <unistd.h>

using namespace dmtcp_crucible::original_thread_owner;

// Thread bodies/list states are authored fixtures. Actual pthread creation,
// stack/TLS address placement, raw TIDs, foreign fork and exit/reap are real.
// These controls do not run a native gem5 cut or establish full process closure.
static OriginalThreadOwner owner;
static Thread mother{};
static Thread *checkpoint = nullptr;
static sem_t born;
static sem_t inspect;
static int mode = 0;
static bool bindAccepted = false;
static bool cutAccepted = false;

static void *unexpected(void *) { return nullptr; }

static void *selectedCheckpoint(void *)
{
  pid_t originalTid = kernelCall(SYS_gettid);
  checkpoint->ptid = &originalTid;
  checkpoint->ctid = &originalTid;
  checkpoint->pthreadSelf = reinterpret_cast<void *>(pthread_self());
  checkpoint->state = ST_CKPNTHREAD;
  bindAccepted = owner.bindThread(checkpoint, originalTid, checkpoint->pthreadSelf);
  assert(sem_post(&born) == 0);
  assert(sem_wait(&inspect) == 0);

  if (mode == 1 || mode == 2) {
    if (mode == 2) checkpoint->fn = unexpected;
    cutAccepted = owner.inspectCut(&mother, checkpoint, &mother);
    assert(!owner.inspectCut(&mother, checkpoint, &mother));
  }
  return nullptr;
}

static void selectOriginal()
{
  assert(owner.select(&mother, selectedCheckpoint));
  mother.state = ST_SUSPENDED;
  static pid_t motherTid;
  motherTid = kernelCall(SYS_gettid);
  mother.ptid = &motherTid;
  mother.ctid = &motherTid;
  mother.pthreadSelf = reinterpret_cast<void *>(pthread_self());
  assert(owner.bindThread(&mother, motherTid, mother.pthreadSelf));
}

static void runPthread(int selectedMode, bool originalStack)
{
  mode = selectedMode;
  selectOriginal();
  void *stack = owner.stackAddress();
  owner.authenticateCreate(selectedCheckpoint, nullptr);
  checkpoint = owner.reserveCheckpoint(selectedCheckpoint, nullptr);
  assert(checkpoint);
  checkpoint->fn = selectedCheckpoint;
  mother.next = checkpoint;
  checkpoint->prev = &mother;
  assert(sem_init(&born, 0, 0) == 0);
  assert(sem_init(&inspect, 0, 0) == 0);

  pthread_attr_t attributes;
  assert(pthread_attr_init(&attributes) == 0);
  assert(pthread_attr_setguardsize(&attributes, 0) == 0);
  if (originalStack)
    assert(pthread_attr_setstack(&attributes, stack, owner.StackBytes) == 0);
  pthread_t actual;
  const int result = pthread_create(&actual, &attributes, selectedCheckpoint, nullptr);
  assert(owner.finishBirth(result));
  assert(pthread_attr_destroy(&attributes) == 0);
  assert(sem_wait(&born) == 0);
  assert(bindAccepted == originalStack);
  assert(sem_post(&inspect) == 0);
  assert(pthread_join(actual, nullptr) == 0);
  assert(cutAccepted == (mode == 1 && originalStack));
  assert(owner.observedCut() == cutAccepted);
  assert(sem_destroy(&inspect) == 0);
  assert(sem_destroy(&born) == 0);
}

static void control(int selectedCase)
{
  switch (selectedCase) {
    case 0:
      runPthread(1, true);
      break;
    case 1:
      runPthread(2, true);
      break;
    case 2:
      runPthread(0, false);
      assert(owner.state() == OriginalThreadOwner::Phase::Refused);
      break;
    case 3:
      selectOriginal();
      owner.authenticateCreate(unexpected, nullptr);
      assert(false);
      break;
    case 4:
      selectOriginal();
      owner.authenticateCreate(selectedCheckpoint, &mother);
      assert(false);
      break;
    case 5: {
      selectOriginal();
      const pid_t foreign = fork();
      assert(foreign >= 0);
      if (foreign == 0) {
        owner.authenticateProcess();
        _exit(1);
      }
      int status;
      assert(waitpid(foreign, &status, 0) == foreign);
      assert(WIFEXITED(status) && WEXITSTATUS(status) == 125);
      assert(owner.state() == OriginalThreadOwner::Phase::Reserved);
      break;
    }
    case 6:
      selectOriginal();
      assert(owner.reserveCheckpoint(selectedCheckpoint, nullptr));
      assert(!owner.finishBirth(EAGAIN));
      assert(!owner.reserveCheckpoint(selectedCheckpoint, nullptr));
      assert(!owner.select(&mother, selectedCheckpoint));
      break;
    case 7:
      selectOriginal();
      assert(owner.reserveCheckpoint(selectedCheckpoint, nullptr));
      assert(!owner.reserveCheckpoint(selectedCheckpoint, nullptr));
      assert(!owner.finishBirth(0));
      break;
    case 8:
      selectOriginal();
      owner.refuseRetirement();
      break;
    default:
      assert(false);
  }
}

int main()
{
  for (int selectedCase = 0; selectedCase != 9; ++selectedCase) {
    const pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
      control(selectedCase);
      _exit(0);
    }
    int status;
    assert(waitpid(child, &status, 0) == child);
    const int expected = selectedCase == 3 || selectedCase == 4 || selectedCase == 8 ? 86 : 0;
    assert(WIFEXITED(status) && WEXITSTATUS(status) == expected);
  }
  std::puts("Nine thread-owner controls passed; authored Thread bodies are not native cut permission.");
}
