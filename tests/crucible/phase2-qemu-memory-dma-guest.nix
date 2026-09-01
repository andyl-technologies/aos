{pkgs}:
# A diskless Linux initramfs that publishes the physical page backing an
# aligned direct-I/O buffer before performing real virtio-blk I/O. The test
# plugin can therefore target payload DMA without touching queue descriptors.
pkgs.mkDerivation {
  pname = "crucible-memory-dma-initramfs";
  version = "0";
  src = null;

  buildDeps = [
    pkgs.coreutils
    pkgs.cpio
    pkgs.pigz
    pkgs.binutils
  ];

  phases = [
    {
      name = "build-memory-dma-initramfs";
      script = ''
        set -eu
        cat > init.c <<'INIT_C'
        #define _GNU_SOURCE
        #include <fcntl.h>
        #include <stdlib.h>
        #include <stdint.h>
        #include <stdio.h>
        #include <string.h>
        #include <sys/mman.h>
        #include <sys/mount.h>
        #include <sys/stat.h>
        #include <time.h>
        #include <unistd.h>

        enum {
          sector_bytes = 512,
          page_bytes = 4096,
        };

        static volatile uint64_t dma_target_mailbox;

        __attribute__((noinline, used))
        static void dma_target_published(void)
        {
          __asm__ volatile("" ::: "memory");
        }

        __attribute__((noinline, used))
        static void dma_test_ready(void)
        {
          __asm__ volatile("" ::: "memory");
        }

        __attribute__((noinline, used))
        static void dma_test_complete(void)
        {
          __asm__ volatile("" ::: "memory");
        }

        int main(void)
        {
          const struct timespec retry = {0, 10000000};
          uint64_t pagemap_entry;
          uint8_t *sector;
          int pagemap_fd;
          int block_fd = -1;

          mkdir("/dev", 0755);
          if (mount("devtmpfs", "/dev", "devtmpfs", 0, "") != 0) {
            return 1;
          }
          mkdir("/proc", 0555);
          if (mount("proc", "/proc", "proc", 0, "") != 0 ||
              posix_memalign((void **)&sector, page_bytes, page_bytes) != 0 ||
              mlock(sector, page_bytes) != 0) {
            return 2;
          }
          memset(sector, 0, page_bytes);
          pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
          if (pagemap_fd < 0 ||
              pread(pagemap_fd, &pagemap_entry, sizeof(pagemap_entry),
                    ((uintptr_t)sector / page_bytes) *
                    sizeof(pagemap_entry)) != sizeof(pagemap_entry) ||
              (pagemap_entry & (UINT64_C(1) << 63)) == 0 ||
              (pagemap_entry & ((UINT64_C(1) << 55) - 1)) == 0) {
            return 3;
          }
          dma_target_mailbox =
              (pagemap_entry & ((UINT64_C(1) << 55) - 1)) * page_bytes;
          if (close(pagemap_fd) != 0) {
            return 4;
          }
          dma_target_published();
          for (volatile unsigned wait = 0; wait < 100000; wait++) {
            __asm__ volatile("" ::: "memory");
          }
          dma_test_ready();
          for (unsigned attempt = 0; attempt < 10000; attempt++) {
            block_fd = open("/dev/vda", O_RDWR | O_DIRECT);
            if (block_fd >= 0) {
              break;
            }
            nanosleep(&retry, NULL);
          }
          if (block_fd < 0) {
            return 5;
          }
          for (size_t index = 0; index < sector_bytes; index++) {
            sector[index] = (uint8_t)(index ^ 0x36u);
          }
          if (pwrite(block_fd, sector, sector_bytes, 0) != sector_bytes ||
              fsync(block_fd) != 0) {
            return 6;
          }
          memset(sector, 0, sector_bytes);
          if (pread(block_fd, sector, sector_bytes, 0) != sector_bytes) {
            return 7;
          }
          for (size_t index = 0; index < sector_bytes; index++) {
            uint8_t expected = ((uint8_t)(index ^ 0x36u)) | 1u;

            if (sector[index] != expected) {
              return 8;
            }
          }
          if (close(block_fd) != 0 ||
              munlock(sector, page_bytes) != 0) {
            return 9;
          }
          free(sector);
          dma_test_complete();
          for (;;) {
            nanosleep(&retry, NULL);
          }
        }
        INIT_C

        cc -static -O2 -Wall -Wextra -Werror -o init init.c
        symbol() {
          nm -n init | awk -v name="$1" '$3 == name { print "0x" $1 }'
        }
        mailbox=$(symbol dma_target_mailbox)
        publish=$(symbol dma_target_published)
        ready=$(symbol dma_test_ready)
        complete=$(symbol dma_test_complete)
        test -n "$mailbox"
        test -n "$publish"
        test -n "$ready"
        test -n "$complete"
        strip --strip-all init
        mkdir -p root "$out"
        cp init root/init
        chmod 0755 root/init
        printf 'mailbox=%s\npublish=%s\nready=%s\ncomplete=%s\n' \
          "$mailbox" "$publish" "$ready" "$complete" > "$out/symbols"
        (
          cd root
          find . -print0 \
            | LC_ALL=C sort -z \
            | cpio --quiet -o -H newc -R +0:+0 --reproducible --null \
            | pigz -9 -n > "$out/initrd.img"
        )
        test -s "$out/initrd.img"
      '';
    }
  ];
}
