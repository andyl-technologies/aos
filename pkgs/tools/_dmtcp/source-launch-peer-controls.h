// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (c) 2026 Andyl, Inc.
#ifndef DMTCP_CRUCIBLE_ORIGINAL_UNIX_PEER_H
#define DMTCP_CRUCIBLE_ORIGINAL_UNIX_PEER_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <linux/magic.h>
#include <new>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <sys/wait.h>

namespace dmtcp_crucible::original_unix_peer
{

// Bypasses process-image interposition before its restart owners are repaired.
inline long kernelCall(long number, long a = 0, long b = 0, long c = 0,
                       long d = 0, long e = 0, long f = 0)
{
#if defined(__x86_64__)
  register long r10 __asm__("r10") = d;
  register long r8 __asm__("r8") = e;
  register long r9 __asm__("r9") = f;
  long result;
  __asm__ volatile("syscall" : "=a"(result)
      : "a"(number), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
      : "rcx", "r11", "memory");
  return result;
#elif defined(__aarch64__)
  register long x8 __asm__("x8") = number;
  register long x0 __asm__("x0") = a;
  register long x1 __asm__("x1") = b;
  register long x2 __asm__("x2") = c;
  register long x3 __asm__("x3") = d;
  register long x4 __asm__("x4") = e;
  register long x5 __asm__("x5") = f;
  __asm__ volatile("svc 0" : "+r"(x0)
      : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
      : "memory", "cc");
  return x0;
#else
#error Unsupported native Linux host architecture
#endif
}

struct KernelObject
{
  std::uint64_t device = 0;
  std::uint64_t inode = 0;

  bool matches(const struct stat &actual) const
  {
    return device == std::uint64_t(actual.st_dev) &&
           inode == std::uint64_t(actual.st_ino);
  }
};

/** Holds one original descriptor through ambiguous close outcomes.
 *
 * Clearing the usable number precedes close. An uncertain close is permanent:
 * a subsequently reused number cannot be polled, signalled or closed again.
 */
struct Descriptor
{
  int number = -1;
  bool unknown = false;

  bool closeOnce()
  {
    if (unknown) return false;
    if (number < 0) return true;
    const int original = number;
    number = -1;
    if (kernelCall(SYS_close, original) != 0) {
      unknown = true;
      return false;
    }
    return true;
  }
};

/** Owns one selected native child and its cut-message transport.
 *
 * This is transport custody, not a native cut issuer. Only a genuine private
 * graph/cut owner may emit an offer; authenticated bytes alone cannot mint a
 * NativeCutPermit, finalize image banks, sign branches or arm a node.
 *
 * The constructor reserves the complete process-lifetime account before fork.
 * Its child executes the held selected ELF directly; no launcher PID, TCP
 * identity field or caller-supplied PID substitutes for that actual birth.
 * A socketpair's SO_PEERCRED describes its creator, so each message instead
 * requires kernel SCM_CREDENTIALS for this exact held child.
 */
class OriginalUnixPeer
{
public:
  static constexpr std::size_t OfferBytes = 344;
  static constexpr int ChildChannelDescriptor = 994;
  static constexpr unsigned CurrentnessLimit = 64;
  static constexpr std::size_t LaunchVectorEntries = 128;
  static constexpr std::size_t LaunchVectorBytes = 32 * 1024;

  enum class Phase : unsigned char
  {
    Reserved, Prepared, Born, Offered, Refused, Retired
  };

  static OriginalUnixPeer *reserveProcessLifetime();

  OriginalUnixPeer(const OriginalUnixPeer &) = delete;
  OriginalUnixPeer &operator=(const OriginalUnixPeer &) = delete;

  static constexpr std::size_t storageBytes();

  /** Opens the selected ELF and retains the source namespace incarnations. */
  bool prepare(const char *executablePath)
  {
    return prepareSourceExec(executablePath, nullptr);
  }

  /** Owns the SAME child across one selected launcher-to-application exec.
   *
   * The launcher is executed from its original held ELF. An optional held
   * application ELF selects the only final message sender image. This is
   * transport lineage, not proof of a completed source exec-custody bank;
   * native source issuance must additionally authenticate that original bank.
   */
  bool prepareSourceExec(const char *launcherPath, const char *applicationPath)
  {
    authenticateOwner();
    if (preparationAttempted) return false;
    preparationAttempted = true;
    if (!launcherPath || sourcePid <= 0 || sourceUid < 0 || sourceGid < 0 ||
        kernelCall(SYS_gettid) != sourcePid ||
        kernelCall(SYS_getuid) != sourceUid || kernelCall(SYS_getgid) != sourceGid)
      return refuse();
    // dup3 must not replace another original inherited descriptor.
    if (kernelCall(SYS_fcntl, ChildChannelDescriptor, F_GETFD) != -9)
      return refuse();

    executable.number = int(kernelCall(SYS_openat, AT_FDCWD,
        reinterpret_cast<long>(launcherPath), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    if (executable.number < 0 || !regularIdentity(executable.number, selectedElf))
      return refuse();

    if (applicationPath != nullptr) {
      application.number = int(kernelCall(SYS_openat, AT_FDCWD,
          reinterpret_cast<long>(applicationPath), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
      if (application.number < 0 || !regularIdentity(application.number, finalElf))
        return refuse();
      applicationSelected = true;
    }

    for (std::size_t i = 0; i != NamespaceNames.size(); ++i) {
      sourceNamespaces[i].number = openNamespace(AT_FDCWD, SelfNamespacePaths[i]);
      if (sourceNamespaces[i].number < 0 ||
          !namespaceIdentity(sourceNamespaces[i].number, namespaceObjects[i]))
        return refuse();
    }

    int pair[2] = {-1, -1};
    if (kernelCall(SYS_socketpair, AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC,
                   0, reinterpret_cast<long>(pair)) != 0)
      return refuse();
    channel.number = pair[0];
    childEndpoint.number = pair[1];
    const int enabled = 1;
    if (kernelCall(SYS_setsockopt, channel.number, SOL_SOCKET, SO_PASSCRED,
                   reinterpret_cast<long>(&enabled), sizeof(enabled)) != 0)
      return refuse();

    phase = Phase::Prepared;
    return true;
  }

  /** Consumes the sole child birth before fork or exec effects. */
  bool launch(char *const arguments[], char *const environment[])
  {
    authenticateOwner();
    if (launchAttempted) return false;
    launchAttempted = true;
    if (phase != Phase::Prepared || !current() || !arguments || !environment)
      return refuse();

    // Own every exact launch byte before fork. Caller vectors can be freed or
    // changed afterward without changing the original launch, and the child
    // never allocates, reopens arguments or acquires an inherited allocator.
    if (!freezeVector(arguments, argumentStorage, originalArguments,
                      argumentCount, argumentBytes) || argumentCount == 0 ||
        !freezeVector(environment, environmentStorage, originalEnvironment,
                      environmentCount, environmentBytes))
      return refuse();

#if defined(__x86_64__)
    const long child = kernelCall(SYS_fork);
#else
    const long child = kernelCall(SYS_clone, SIGCHLD);
#endif
    if (child < 0) return refuse();
    if (child == 0) {
      // No diagnostics, allocation or inherited provider callbacks in the
      // child. The channel survives exec; every other held owner is CLOEXEC.
      if (childEndpoint.number == ChildChannelDescriptor ||
          kernelCall(SYS_dup3, childEndpoint.number, ChildChannelDescriptor, 0) < 0)
        terminateChild(125);
      kernelCall(SYS_execveat, executable.number, reinterpret_cast<long>(""),
          reinterpret_cast<long>(originalArguments.data()),
          reinterpret_cast<long>(originalEnvironment.data()),
          AT_EMPTY_PATH);
      terminateChild(125);
    }

    childPid = child;
    phase = Phase::Born;
    pidfd.number = int(kernelCall(SYS_pidfd_open, childPid, 0));
    if (!childEndpoint.closeOnce() || pidfd.number < 0) return refuse();
    if (!childPath(childPid, childProcPath)) return refuse();
    childProc.number = int(kernelCall(SYS_openat, AT_FDCWD,
        reinterpret_cast<long>(childProcPath.data()), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    struct statfs filesystem{};
    if (childProc.number < 0 || kernelCall(SYS_fstatfs, childProc.number,
          reinterpret_cast<long>(&filesystem)) != 0 ||
        filesystem.f_type != PROC_SUPER_MAGIC)
      return refuse();
    return true;
  }

  /** Receives exactly one ready socket message with actual sender credentials.
   *
   * The original event loop must wait for readability before this nonblocking
   * attempt. A short/truncated/foreign/early/error message permanently refuses
   * the same account. No syscall retry or additional offer is authorized.
   */
  bool receiveOffer()
  {
    authenticateOwner();
    if (receiveAttempted) return false;
    receiveAttempted = true;
    if (phase != Phase::Born || !current() || !childLive()) return refuse();

    iovec vector{offer.data(), offer.size()};
    msghdr message{};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.data();
    message.msg_controllen = ancillary.size();
    const long received = kernelCall(SYS_recvmsg, channel.number,
        reinterpret_cast<long>(&message), MSG_DONTWAIT | MSG_CMSG_CLOEXEC);

    bool credentialsSeen = false;
    bool credentialsValid = false;
    bool foreignControl = false;
    for (auto *control = CMSG_FIRSTHDR(&message); control;
         control = CMSG_NXTHDR(&message, control)) {
      if (control->cmsg_level == SOL_SOCKET && control->cmsg_type == SCM_CREDENTIALS &&
          control->cmsg_len == CMSG_LEN(sizeof(Credentials)) && !credentialsSeen) {
        Credentials actual{};
        std::memcpy(&actual, CMSG_DATA(control), sizeof(actual));
        credentialsSeen = true;
        credentialsValid = actual.pid == childPid && actual.uid == sourceUid &&
                           actual.gid == sourceGid;
      } else {
        foreignControl = true;
        if (control->cmsg_level == SOL_SOCKET && control->cmsg_type == SCM_RIGHTS &&
            control->cmsg_len >= CMSG_LEN(0)) {
          const std::size_t bytes = control->cmsg_len - CMSG_LEN(0);
          const auto *descriptors = reinterpret_cast<const int *>(CMSG_DATA(control));
          for (std::size_t i = 0; i != bytes / sizeof(int); ++i) {
            if (receivedRights == rejectedRights.size()) return refuse();
            auto &original = rejectedRights[receivedRights++];
            original.number = descriptors[i];
            if (!original.closeOnce()) closeUnknown = true;
          }
        }
      }
    }

    if (received != long(offer.size()) || !credentialsValid || foreignControl ||
        (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) || closeUnknown ||
        !childIdentityCurrent())
      return refuse();

    phase = Phase::Offered;
    return true;
  }

  int originalChannel() const { authenticateOwner(); return channel.number; }
  int originalDeathDescriptor() const { authenticateOwner(); return pidfd.number; }
  long originalChildPid() const { authenticateOwner(); return childPid; }
  std::size_t originalArgumentCount() const { authenticateOwner(); return argumentCount; }
  std::size_t originalEnvironmentCount() const { authenticateOwner(); return environmentCount; }
  std::size_t originalArgumentBytes() const { authenticateOwner(); return argumentBytes; }
  std::size_t originalEnvironmentBytes() const { authenticateOwner(); return environmentBytes; }
  const char *argumentAt(std::size_t ordinal) const
  {
    authenticateOwner();
    return ordinal < argumentCount ? originalArguments[ordinal] : nullptr;
  }
  Phase state() const { authenticateOwner(); return phase; }
  const std::array<unsigned char, OfferBytes> &originalOffer() const { authenticateOwner(); return offer; }

  /** Cancels only the original held child, retaining ambiguity and outcome. */
  bool cancel()
  {
    authenticateOwner();
    if (cancelAttempted) return false;
    cancelAttempted = true;
    if (!current() || childPid <= 0 || pidfd.number < 0 || pidfd.unknown)
      return false;
    if (!childLive()) return true;
    return kernelCall(SYS_pidfd_send_signal, pidfd.number, SIGKILL, 0, 0) == 0;
  }

  /** Records actual original-child death before closing any custody handles. */
  bool retire()
  {
    authenticateOwner();
    if (phase == Phase::Retired || closeUnknown || !current()) return false;
    if (childPid > 0 && !reaped) {
      if (pidfd.number < 0 || childLive()) return false;
      int status = 0;
      if (kernelCall(SYS_wait4, childPid, reinterpret_cast<long>(&status), WNOHANG, 0)
          != childPid)
        return false;
      terminalStatus = status;
      reaped = true;
    }

    bool closed = channel.closeOnce();
    closed = childEndpoint.closeOnce() && closed;
    closed = application.closeOnce() && closed;
    closed = executable.closeOnce() && closed;
    closed = childProc.closeOnce() && closed;
    closed = pidfd.closeOnce() && closed;
    for (auto &fd : sourceNamespaces) closed = fd.closeOnce() && closed;
    for (auto &fd : childNamespaces) closed = fd.closeOnce() && closed;
    if (!closed) {
      closeUnknown = true;
      return false;
    }
    phase = Phase::Retired;
    return true;
  }

  int originalTerminalStatus() const { authenticateOwner(); return terminalStatus; }

private:
  static bool freezeVector(char *const input[],
      std::array<char, LaunchVectorBytes> &storage,
      std::array<char *, LaunchVectorEntries> &vector,
      std::size_t &count, std::size_t &charged)
  {
    // Whole vector/slot backing was reserved in the original constructor.
    // Byte debits advance before copying; a partial invalid vector remains
    // in the same refused owner without retry, trimming or replacement.
    for (; count != vector.size(); ++count) {
      if (input[count] == nullptr) {
        vector[count] = nullptr;
        return true;
      }
      if (count + 1 == vector.size() || charged == storage.size()) return false;
      const std::size_t begin = charged;
      bool terminated = false;
      while (charged != storage.size()) {
        const char byte = input[count][charged - begin];
        storage[charged++] = byte;
        if (byte == 0) {
          terminated = true;
          break;
        }
      }
      if (!terminated) return false;
      vector[count] = storage.data() + begin;
    }
    return false;
  }

  struct Credentials { int pid; unsigned uid; unsigned gid; };
  struct ElfIdentity
  {
    KernelObject object;
    off_t size = 0;
    timespec modified{};
    timespec changed{};
  };

  OriginalUnixPeer()
      : sourcePid(kernelCall(SYS_getpid)), sourceUid(kernelCall(SYS_geteuid)),
        sourceGid(kernelCall(SYS_getegid))
  {}

  void authenticateOwner() const
  {
    if (sourcePid <= 0 || sourceUid < 0 || sourceGid < 0 ||
        kernelCall(SYS_getpid) != sourcePid || kernelCall(SYS_gettid) != sourcePid ||
        kernelCall(SYS_geteuid) != sourceUid || kernelCall(SYS_getegid) != sourceGid) {
      kernelCall(SYS_exit_group, 125);
      __builtin_unreachable();
    }
  }
  ~OriginalUnixPeer() = default;

  struct Lifetime;
  static Lifetime &lifetime();

  bool refuse()
  {
    phase = Phase::Refused;
    return false;
  }

  [[noreturn]] static void terminateChild(int status)
  {
    kernelCall(SYS_exit_group, status);
    __builtin_trap();
  }

  static bool childPath(long pid, std::array<char, 64> &output)
  {
    if (pid <= 0) return false;
    std::array<char, 24> digits{};
    unsigned count = 0;
    auto remaining = static_cast<unsigned long>(pid);
    do {
      digits[count++] = char('0' + remaining % 10);
      remaining /= 10;
    } while (remaining);
    std::memcpy(output.data(), "/proc/", 6);
    for (unsigned i = 0; i != count; ++i) output[6 + i] = digits[count - 1 - i];
    output[6 + count] = 0;
    return true;
  }

  static int openNamespace(int directory, const char *path)
  {
    return int(kernelCall(SYS_openat, directory, reinterpret_cast<long>(path),
                          O_RDONLY | O_CLOEXEC));
  }

  static bool namespaceIdentity(int fd, KernelObject &output)
  {
    struct statfs filesystem{};
    struct stat actual{};
    if (kernelCall(SYS_fstatfs, fd, reinterpret_cast<long>(&filesystem)) != 0 ||
        filesystem.f_type != NSFS_MAGIC ||
        kernelCall(SYS_fstat, fd, reinterpret_cast<long>(&actual)) != 0 || !actual.st_ino)
      return false;
    output = {std::uint64_t(actual.st_dev), std::uint64_t(actual.st_ino)};
    return true;
  }

  static bool regularIdentity(int fd, ElfIdentity &output)
  {
    struct stat actual{};
    if (kernelCall(SYS_fstat, fd, reinterpret_cast<long>(&actual)) != 0 ||
        !S_ISREG(actual.st_mode) || !(actual.st_mode & 0111) ||
        (actual.st_mode & (S_ISUID | S_ISGID)) || actual.st_size <= 0)
      return false;
    output = {{std::uint64_t(actual.st_dev), std::uint64_t(actual.st_ino)},
              actual.st_size, actual.st_mtim, actual.st_ctim};
    return true;
  }

  bool current()
  {
    authenticateOwner();
    if (currentnessAttempts == CurrentnessLimit) return false;
    ++currentnessAttempts;
    for (std::size_t i = 0; i != NamespaceNames.size(); ++i) {
      // Failed preparation has not necessarily acquired all namespaces.
      // Closing already-held resources grants neither birth nor cut credit.
      if (sourceNamespaces[i].number < 0) continue;
      Descriptor observed;
      observed.number = openNamespace(AT_FDCWD, SelfNamespacePaths[i]);
      KernelObject actual;
      const bool matches = observed.number >= 0 &&
          namespaceIdentity(observed.number, actual) &&
          actual.device == namespaceObjects[i].device && actual.inode == namespaceObjects[i].inode;
      if (!observed.closeOnce()) closeUnknown = true;
      if (!matches || closeUnknown) return false;
    }
    return true;
  }

  bool childLive() const
  {
    if (pidfd.number < 0 || pidfd.unknown) return false;
    pollfd actual{pidfd.number, POLLIN, 0};
    const timespec noWait{};
    return kernelCall(SYS_ppoll, reinterpret_cast<long>(&actual), 1,
                      reinterpret_cast<long>(&noWait), 0, 0) == 0;
  }

  bool childIdentityCurrent()
  {
    if (!childLive()) return false;
    Descriptor observed;
    observed.number = int(kernelCall(SYS_openat, childProc.number,
        reinterpret_cast<long>("exe"), O_RDONLY | O_CLOEXEC));
    ElfIdentity actual;
    const auto &expected = applicationSelected ? finalElf : selectedElf;
    const bool sameElf = observed.number >= 0 && regularIdentity(observed.number, actual) &&
        actual.object.device == expected.object.device && actual.object.inode == expected.object.inode &&
        actual.size == expected.size && actual.modified.tv_sec == expected.modified.tv_sec &&
        actual.modified.tv_nsec == expected.modified.tv_nsec &&
        actual.changed.tv_sec == expected.changed.tv_sec && actual.changed.tv_nsec == expected.changed.tv_nsec;
    if (!observed.closeOnce()) closeUnknown = true;
    if (!sameElf || closeUnknown) return false;

    for (std::size_t i = 0; i != NamespaceNames.size(); ++i) {
      childNamespaces[i].number = openNamespace(childProc.number, NamespaceNames[i]);
      KernelObject actualNamespace;
      if (childNamespaces[i].number < 0 ||
          !namespaceIdentity(childNamespaces[i].number, actualNamespace) ||
          actualNamespace.device != namespaceObjects[i].device ||
          actualNamespace.inode != namespaceObjects[i].inode)
        return false;
    }
    return childLive();
  }

  static constexpr std::array<const char *, 3> NamespaceNames{
      "ns/pid", "ns/user", "ns/mnt"};
  static constexpr std::array<const char *, 3> SelfNamespacePaths{
      "/proc/self/ns/pid", "/proc/self/ns/user", "/proc/self/ns/mnt"};

  Phase phase = Phase::Reserved;
  bool preparationAttempted = false;
  bool launchAttempted = false;
  bool receiveAttempted = false;
  bool cancelAttempted = false;
  bool reaped = false;
  bool closeUnknown = false;
  unsigned currentnessAttempts = 0;
  unsigned receivedRights = 0;
  int terminalStatus = 0;
  const long sourcePid;
  const long sourceUid;
  const long sourceGid;
  long childPid = 0;
  Descriptor channel, childEndpoint, executable, application, childProc, pidfd;
  std::array<Descriptor, 3> sourceNamespaces{};
  std::array<Descriptor, 3> childNamespaces{};
  std::array<Descriptor, 16> rejectedRights{};
  std::array<KernelObject, 3> namespaceObjects{};
  ElfIdentity selectedElf;
  ElfIdentity finalElf;
  bool applicationSelected = false;
  std::array<char, LaunchVectorBytes> argumentStorage{};
  std::array<char, LaunchVectorBytes> environmentStorage{};
  std::array<char *, LaunchVectorEntries> originalArguments{};
  std::array<char *, LaunchVectorEntries> originalEnvironment{};
  std::size_t argumentCount = 0;
  std::size_t argumentBytes = 0;
  std::size_t environmentCount = 0;
  std::size_t environmentBytes = 0;
  std::array<char, 64> childProcPath{};
  std::array<unsigned char, OfferBytes> offer{};
  alignas(cmsghdr) std::array<unsigned char,
      CMSG_SPACE(sizeof(Credentials)) + CMSG_SPACE(16 * sizeof(int))> ancillary{};
};

struct OriginalUnixPeer::Lifetime
{
  alignas(OriginalUnixPeer) unsigned char bytes[sizeof(OriginalUnixPeer)]{};
  bool reserved = false;
};

inline OriginalUnixPeer::Lifetime &OriginalUnixPeer::lifetime()
{
  static Lifetime storage;
  return storage;
}

inline OriginalUnixPeer *OriginalUnixPeer::reserveProcessLifetime()
{
  if (kernelCall(SYS_getpid) != kernelCall(SYS_gettid)) return nullptr;
  auto &storage = lifetime();
  if (storage.reserved) return nullptr;
  storage.reserved = true;
  return ::new (storage.bytes) OriginalUnixPeer;
}

constexpr std::size_t OriginalUnixPeer::storageBytes()
{
  return sizeof(Lifetime);
}

} // namespace dmtcp_crucible::original_unix_peer
#endif
