#define _GNU_SOURCE

#include <stddef.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Flush a linker's mapped output before releasing it. Some filesystems lose
 * dirty mapped pages at munmap even though the call reports success. */
int munmap(void *address, size_t length) {
    msync(address, length, MS_SYNC);
    return syscall(SYS_munmap, address, length);
}
