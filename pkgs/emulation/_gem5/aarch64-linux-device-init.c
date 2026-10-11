/* SPDX-License-Identifier: MIT */
/* Freestanding PID1: the syscall ABI and structures come from ARM kernel UAPI. */
#include <asm/errno.h>
#include <asm/fcntl.h>
#include <asm/unistd.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>

_Static_assert(sizeof(struct ifreq) == 40, "AArch64 Linux interface ioctl extent");
_Static_assert(__builtin_offsetof(struct ifreq, ifr_flags) == 16,
               "AArch64 Linux interface flags offset");

#define AF_PACKET 17
#define SOCK_RAW 3
#define SOL_PACKET 263
#define AT_FDCWD (-100)

typedef unsigned long usize;
typedef long isize;

void *
memcpy(void *destination, const void *source, usize extent)
{
    unsigned char *out = destination;
    const unsigned char *in = source;
    for (usize index = 0; index < extent; ++index)
        out[index] = in[index];
    return destination;
}

void *
memset(void *destination, int value, usize extent)
{
    unsigned char *out = destination;
    for (usize index = 0; index < extent; ++index)
        out[index] = value;
    return destination;
}

static int
same_bytes(const void *left, const void *right, usize extent)
{
    const unsigned char *first = left;
    const unsigned char *second = right;
    for (usize index = 0; index < extent; ++index) {
        if (first[index] != second[index])
            return 0;
    }
    return 1;
}

static long
syscall6(long number, long first, long second, long third,
         long fourth, long fifth, long sixth)
{
    register long x0 __asm__("x0") = first;
    register long x1 __asm__("x1") = second;
    register long x2 __asm__("x2") = third;
    register long x3 __asm__("x3") = fourth;
    register long x4 __asm__("x4") = fifth;
    register long x5 __asm__("x5") = sixth;
    register long x8 __asm__("x8") = number;
    __asm__ volatile("svc #0" : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
                     : "memory", "cc");
    return x0;
}

static long
open_file(const char *path, long flags, long mode)
{
    return syscall6(__NR_openat, AT_FDCWD, (long)path, flags, mode, 0, 0);
}

static void
close_file(long descriptor)
{
    syscall6(__NR_close, descriptor, 0, 0, 0, 0, 0);
}

static void
write_text(const char *text)
{
    usize size = 0;
    while (text[size])
        ++size;
    usize written = 0;
    while (written < size) {
        long result = syscall6(__NR_write, 1, (long)(text + written), size - written, 0, 0, 0);
        if (result == -EINTR)
            continue;
        if (result <= 0)
            return;
        written += result;
    }
}

static int
failure(const char *operation, long result)
{
    write_text("GEM5_DEVICE_FAILURE ");
    write_text(operation);
    write_text(" errno=");
    unsigned long number = result < 0 ? -result : result;
    char digits[21];
    usize position = sizeof(digits) - 1;
    digits[position] = 0;
    do {
        digits[--position] = '0' + number % 10;
        number /= 10;
    } while (number);
    write_text(digits + position);
    write_text("\n");
    return -1;
}

static int
contains(const char *text, const char *wanted)
{
    for (usize index = 0; text[index]; ++index) {
        usize offset = 0;
        while (wanted[offset] && text[index + offset] == wanted[offset])
            ++offset;
        if (!wanted[offset])
            return 1;
    }
    return 0;
}

static int
probe_network(void)
{
    const unsigned short protocol = 0xb588; /* Network-order EtherType 0x88b5. */
    long socket = syscall6(__NR_socket, AF_PACKET, SOCK_RAW, protocol, 0, 0, 0);
    if (socket < 0)
        return failure("network-socket", socket);
    int ignore_outgoing = 1;
    long result = syscall6(__NR_setsockopt, socket, SOL_PACKET, PACKET_IGNORE_OUTGOING,
                          (long)&ignore_outgoing, sizeof(ignore_outgoing), 0);
    if (result < 0)
        return failure("network-incoming-filter", result);

    struct ifreq interface = {0};
    memcpy(interface.ifr_name, "eth0", 5);
    result = syscall6(__NR_ioctl, socket, SIOCGIFINDEX, (long)&interface, 0, 0, 0);
    if (result < 0)
        return failure("network-interface", result);
    int index = interface.ifr_ifindex;
    result = syscall6(__NR_ioctl, socket, SIOCGIFFLAGS, (long)&interface, 0, 0, 0);
    if (result < 0)
        return failure("network-flags", result);
    interface.ifr_flags |= IFF_UP;
    result = syscall6(__NR_ioctl, socket, SIOCSIFFLAGS, (long)&interface, 0, 0, 0);
    if (result < 0)
        return failure("network-up", result);

    struct sockaddr_ll address = {0};
    address.sll_family = AF_PACKET;
    address.sll_protocol = protocol;
    address.sll_ifindex = index;
    result = syscall6(__NR_bind, socket, (long)&address, sizeof(address), 0, 0, 0);
    if (result < 0)
        return failure("network-bind", result);

    unsigned char frame[64] = {0};
    memset(frame, 0xff, 6);
    frame[6] = 2;
    frame[11] = 1;
    frame[12] = 0x88;
    frame[13] = 0xb5;
    memcpy(frame + 14, "CRUCIBLE_GEM5_NATIVE_FRAME", 25);
    result = syscall6(__NR_sendto, socket, (long)frame, sizeof(frame), 0,
                      (long)&address, sizeof(address));
    if (result != (long)sizeof(frame))
        return failure("network-send", result);
    write_text("GEM5_NETWORK_TX_READY bytes=64\n");

    unsigned char observed[128];
    result = syscall6(__NR_recvfrom, socket, (long)observed, sizeof(observed), 0, 0, 0);
    if (result != (long)sizeof(frame) || !same_bytes(observed, frame, sizeof(frame)))
        return failure("network-receive-mismatch", result);
    close_file(socket);
    write_text("GEM5_NETWORK_RX_VERIFIED bytes=64\n");
    return 0;
}

static int
probe_block(void)
{
    long disk = open_file("/dev/vda", O_RDWR | O_CLOEXEC, 0);
    if (disk < 0)
        return failure("block-open", disk);
    unsigned char expected[512];
    for (usize index = 0; index < sizeof(expected); ++index)
        expected[index] = index;
    long result = syscall6(__NR_pwrite64, disk, (long)expected, sizeof(expected), 512, 0, 0);
    if (result != (long)sizeof(expected))
        return failure("block-write", result);
    result = syscall6(__NR_fsync, disk, 0, 0, 0, 0, 0);
    if (result < 0)
        return failure("block-flush", result);
    close_file(disk);

    disk = open_file("/dev/vda", O_RDONLY | O_DIRECT | O_CLOEXEC, 0);
    if (disk < 0)
        return failure("block-direct-open", disk);
    static unsigned char observed[512] __attribute__((aligned(4096)));
    result = syscall6(__NR_pread64, disk, (long)observed, sizeof(observed), 512, 0, 0);
    if (result != (long)sizeof(observed) || !same_bytes(observed, expected, sizeof(expected)))
        return failure("block-read-mismatch", result);
    close_file(disk);
    write_text("GEM5_BLOCK_READ_WRITE_FLUSH_VERIFIED sector=1 bytes=512\n");
    return 0;
}

static int
probe_filesystem(void)
{
    syscall6(__NR_mkdirat, AT_FDCWD, (long)"/mnt", 0755, 0, 0, 0);
    long result = syscall6(__NR_mount, (long)"crucible", (long)"/mnt", (long)"9p", 0,
                          (long)"trans=virtio,version=9p2000.L,cache=none", 0);
    if (result < 0)
        return failure("9p-mount", result);
    long file = open_file("/mnt/probe", O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
    if (file < 0)
        return failure("9p-open", file);
    const char expected[] = "crucible native 9p ownership\n";
    char observed[sizeof(expected)];
    result = syscall6(__NR_write, file, (long)expected, sizeof(expected), 0, 0, 0);
    if (result != (long)sizeof(expected))
        return failure("9p-write", result);
    result = syscall6(__NR_fsync, file, 0, 0, 0, 0, 0);
    if (result < 0)
        return failure("9p-flush", result);
    result = syscall6(__NR_pread64, file, (long)observed, sizeof(observed), 0, 0, 0);
    if (result != (long)sizeof(observed) || !same_bytes(observed, expected, sizeof(expected)))
        return failure("9p-read-mismatch", result);
    close_file(file);
    write_text("GEM5_9P_READ_WRITE_FLUSH_VERIFIED\n");
    return 0;
}

void
init_main(void)
{
    syscall6(__NR_mount, (long)"devtmpfs", (long)"/dev", (long)"devtmpfs", 0, 0, 0);
    long console = open_file("/dev/console", O_RDWR, 0);
    if (console >= 0) {
        for (long descriptor = 0; descriptor < 3; ++descriptor) {
            if (descriptor != console)
                syscall6(__NR_dup3, console, descriptor, 0, 0, 0, 0);
        }
        if (console > 2)
            close_file(console);
    }
    syscall6(__NR_mount, (long)"proc", (long)"/proc", (long)"proc", 0, 0, 0);
    syscall6(__NR_mount, (long)"sysfs", (long)"/sys", (long)"sysfs", 0, 0, 0);
    write_text("GEM5_LINUX_INIT_READY\n");

    char command[2048] = {0};
    int successful = 1;
    long file = open_file("/proc/cmdline", O_RDONLY, 0);
    if (file < 0) {
        failure("command-line-open", file);
        successful = 0;
    } else {
        long result = syscall6(__NR_read, file, (long)command, sizeof(command) - 1, 0, 0, 0);
        if (result < 0) {
            failure("command-line-read", result);
            successful = 0;
        }
        close_file(file);
    }
    if (contains(command, "gem5_probe=network"))
        successful &= probe_network() == 0;
    if (contains(command, "gem5_probe=block"))
        successful &= probe_block() == 0;
    if (contains(command, "gem5_probe=9p"))
        successful &= probe_filesystem() == 0;
    write_text(successful ? "GEM5_LINUX_PROBE_COMPLETE\n" : "GEM5_LINUX_PROBE_FAILED\n");
    for (;;)
        syscall6(__NR_ppoll, 0, 0, 0, 0, 0, 0);
}

__attribute__((naked, noreturn)) void
_start(void)
{
    __asm__ volatile("bl init_main\n1: wfe\nb 1b");
}
