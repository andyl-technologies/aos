{pkgs}:
# A diskless Linux initramfs that waits for the crucible-shmem virtio-blk
# device, completes one sector write, then remains in a deterministic
# nanosleep loop. The completed write is the live consumer of patch 0017's
# nonzero pending sentinel: a successful write poll returns zero bytes.
pkgs.mkDerivation {
  pname = "crucible-live-block-io-write-initramfs";
  version = "0";
  src = null;

  buildDeps = [
    pkgs.coreutils
    pkgs.cpio
    pkgs.pigz
  ];

  phases = [
    {
      name = "build-block-write-initramfs";
      script = ''
        set -eu
        cat > init.c <<'INIT_C'
        #include <fcntl.h>
        #include <stdint.h>
        #include <stdio.h>
        #include <sys/mount.h>
        #include <sys/stat.h>
        #include <time.h>
        #include <unistd.h>

        int main(void)
        {
          const struct timespec retry = {0, 10000000};
          const struct timespec idle = {0, 20000000};
          uint8_t sector[512];
          int fd = -1;

          mkdir("/dev", 0755);
          if (mount("devtmpfs", "/dev", "devtmpfs", 0, "") != 0) {
            return 1;
          }
          for (size_t index = 0; index < sizeof(sector); index++) {
            sector[index] = (uint8_t)(index ^ 0x37u);
          }
          for (unsigned attempt = 0; attempt < 10000; attempt++) {
            fd = open("/dev/vda", O_RDWR);
            if (fd >= 0) {
              break;
            }
            nanosleep(&retry, NULL);
          }
          if (fd < 0 || pwrite(fd, sector, sizeof(sector), 0) != sizeof(sector) ||
              fsync(fd) != 0 || close(fd) != 0) {
            return 1;
          }
          puts("CRUCIBLE_BLOCK_WRITE_COMPLETE");
          fflush(stdout);
          for (;;) {
            nanosleep(&idle, NULL);
          }
        }
        INIT_C

        cc -static -O2 -Wall -Wextra -Werror -o init init.c
        strip --strip-all init
        mkdir -p root
        cp init root/init
        chmod 0755 root/init
        mkdir -p "$out"
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
