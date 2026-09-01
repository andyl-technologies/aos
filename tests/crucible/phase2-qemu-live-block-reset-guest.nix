{pkgs}:
# A diskless Linux initramfs that certifies the guest-visible half of the live
# block reset contract: a declared-topology reset must raise the virtio config
# interrupt, and a request in the modeled recovery interval must receive EIO.
pkgs.mkDerivation {
  pname = "crucible-live-block-reset-initramfs";
  version = "0";
  src = null;

  buildDeps = [
    pkgs.coreutils
    pkgs.cpio
    pkgs.pigz
  ];

  phases = [
    {
      name = "build-block-reset-initramfs";
      script = ''
        set -eu
        cat > init.c <<'INIT_C'
        #include <ctype.h>
        #include <errno.h>
        #include <fcntl.h>
        #include <stdint.h>
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>
        #include <sys/mount.h>
        #include <sys/stat.h>
        #include <time.h>
        #include <unistd.h>

        static int virtio_device_name(char *output, size_t capacity)
        {
          char target[256];
          const char *name;
          const char *end;
          ssize_t length = readlink("/sys/class/block/vda/device", target,
                                    sizeof(target) - 1);

          if (length <= 0 || (size_t)length >= sizeof(target)) {
            return -1;
          }
          target[length] = '\0';
          name = target;
          for (const char *cursor = target; (cursor = strstr(cursor, "virtio")); cursor++) {
            name = cursor;
          }
          if (strncmp(name, "virtio", 6) != 0) {
            return -1;
          }
          end = strchr(name, '/');
          size_t name_length = end ? (size_t)(end - name) : strlen(name);
          if (name_length == 0 || name_length >= capacity) {
            return -1;
          }
          memcpy(output, name, name_length);
          output[name_length] = '\0';
          return 0;
        }

        static long long config_interrupts(const char *virtio_name)
        {
          char line[1024];
          char label[64];
          FILE *interrupts;

          if (snprintf(label, sizeof(label), "%s-config", virtio_name) >=
              (int)sizeof(label)) {
            return -1;
          }
          interrupts = fopen("/proc/interrupts", "r");
          if (!interrupts) {
            return -1;
          }
          while (fgets(line, sizeof(line), interrupts)) {
            char *cursor;
            char *end;
            long long total = 0;

            if (!strstr(line, label) || !(cursor = strchr(line, ':'))) {
              continue;
            }
            cursor++;
            while (*cursor) {
              while (isspace((unsigned char)*cursor)) {
                cursor++;
              }
              if (!isdigit((unsigned char)*cursor)) {
                break;
              }
              errno = 0;
              unsigned long long value = strtoull(cursor, &end, 10);
              if (errno || end == cursor || value > (unsigned long long)INT64_MAX - total) {
                fclose(interrupts);
                return -1;
              }
              total += (long long)value;
              cursor = end;
            }
            fclose(interrupts);
            return total;
          }
          fclose(interrupts);
          return -1;
        }

        int main(void)
        {
          const struct timespec retry = {0, 1000000};
          uint8_t sector[512];
          char virtio_name[32];
          long long before;
          long long after = -1;
          int fd = -1;

          mkdir("/dev", 0755);
          mkdir("/proc", 0755);
          mkdir("/sys", 0755);
          if (mount("devtmpfs", "/dev", "devtmpfs", 0, "") != 0 ||
              mount("proc", "/proc", "proc", 0, "") != 0 ||
              mount("sysfs", "/sys", "sysfs", 0, "") != 0) {
            return 1;
          }
          memset(sector, 0x5a, sizeof(sector));
          for (unsigned attempt = 0; attempt < 10000; attempt++) {
            fd = open("/dev/vda", O_RDWR | O_SYNC);
            if (fd >= 0) {
              break;
            }
            nanosleep(&retry, NULL);
          }
          if (fd < 0 || virtio_device_name(virtio_name, sizeof(virtio_name)) != 0) {
            return 1;
          }
          before = config_interrupts(virtio_name);
          if (before < 0 || pwrite(fd, sector, sizeof(sector), 0) != sizeof(sector)) {
            return 1;
          }
          for (unsigned attempt = 0; attempt < 100000; attempt++) {
            after = config_interrupts(virtio_name);
            if (after > before) {
              break;
            }
            nanosleep(&retry, NULL);
          }
          if (after <= before) {
            return 1;
          }
          errno = 0;
          if (pwrite(fd, sector, sizeof(sector), sizeof(sector)) != -1 ||
              errno != EIO) {
            return 1;
          }
          printf("CRUCIBLE_BLOCK_RESET_ERRNO=%d\n", errno);
          printf("CRUCIBLE_BLOCK_CONFIG_IRQ_DELTA=%lld\n", after - before);
          fflush(stdout);
          for (;;) {
            nanosleep(&retry, NULL);
          }
        }
        INIT_C

        cc -static -O2 -Wall -Wextra -Werror -o init init.c
        strip --strip-all init
        mkdir -p root "$out"
        cp init root/init
        chmod 0755 root/init
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
