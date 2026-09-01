{pkgs}:
# A Linux initramfs that creates two independently observable pieces of live
# production state before the shared-cause event: an unflushed write to the
# optional Crucible-managed data disk and one raw Ethernet frame large enough
# to remain reserved in the deliberately slow World network queue.
pkgs.mkDerivation {
  pname = "crucible-signal-shared-cause-initramfs";
  version = "0";
  src = null;

  buildDeps = [
    pkgs.coreutils
    pkgs.cpio
    pkgs.pigz
  ];

  phases = [
    {
      name = "build-signal-shared-cause-initramfs";
      script = ''
        set -eu
        cat > init.c <<'INIT_C'
        #define _GNU_SOURCE
        #include <arpa/inet.h>
        #include <fcntl.h>
        #include <linux/if_packet.h>
        #include <net/ethernet.h>
        #include <net/if.h>
        #include <stdint.h>
        #include <string.h>
        #include <sys/ioctl.h>
        #include <sys/mount.h>
        #include <sys/socket.h>
        #include <sys/stat.h>
        #include <time.h>
        #include <unistd.h>

        #define FRAME_LEN 1514
        #define CRUCIBLE_ETHERTYPE 0x88b5

        static const struct timespec retry = {0, 1000000};

        static int bring_up(int fd, const char *name) {
          struct ifreq request;
          memset(&request, 0, sizeof(request));
          strncpy(request.ifr_name, name, IFNAMSIZ - 1);
          if (ioctl(fd, SIOCGIFFLAGS, &request) != 0) {
            return -1;
          }
          request.ifr_flags |= IFF_UP;
          return ioctl(fd, SIOCSIFFLAGS, &request);
        }

        static int write_volatile_sector(void) {
          uint8_t sector[4096] __attribute__((aligned(4096)));
          int fd = -1;
          for (size_t index = 0; index < sizeof(sector); index++) {
            sector[index] = (uint8_t)(index ^ 0xa7u);
          }
          for (unsigned attempt = 0; attempt < 1000; attempt++) {
            fd = open("/dev/vdb", O_RDWR | O_DIRECT);
            if (fd >= 0) {
              break;
            }
            nanosleep(&retry, 0);
          }
          if (fd < 0) {
            return 0;
          }
          ssize_t written = pwrite(fd, sector, sizeof(sector), 0);
          return written == (ssize_t)sizeof(sector);
        }

        int main(void) {
          mkdir("/dev", 0755);
          (void)mount("devtmpfs", "/dev", "devtmpfs", 0, "");
          if (!write_volatile_sector()) {
            for (;;) nanosleep(&retry, 0);
          }

          int fd = socket(AF_PACKET, SOCK_RAW, htons(CRUCIBLE_ETHERTYPE));
          if (fd < 0 || bring_up(fd, "eth0") != 0) {
            for (;;) nanosleep(&retry, 0);
          }
          struct ifreq index_request;
          memset(&index_request, 0, sizeof(index_request));
          strncpy(index_request.ifr_name, "eth0", IFNAMSIZ - 1);
          if (ioctl(fd, SIOCGIFINDEX, &index_request) != 0) {
            for (;;) nanosleep(&retry, 0);
          }

          uint8_t frame[FRAME_LEN];
          memset(frame, 0x5a, sizeof(frame));
          memset(frame, 0xff, 6);
          frame[6] = 0x52; frame[7] = 0x54; frame[8] = 0x00;
          frame[9] = 0x12; frame[10] = 0x34; frame[11] = 0x56;
          frame[12] = 0x88; frame[13] = 0xb5;

          struct sockaddr_ll destination;
          memset(&destination, 0, sizeof(destination));
          destination.sll_family = AF_PACKET;
          destination.sll_protocol = htons(CRUCIBLE_ETHERTYPE);
          destination.sll_ifindex = index_request.ifr_ifindex;
          destination.sll_halen = 6;
          memset(destination.sll_addr, 0xff, 6);
          uint64_t sequence = 0;
          memcpy(frame + 14, &sequence, sizeof(sequence));
          if (sendto(fd, frame, sizeof(frame), 0,
                     (struct sockaddr *)&destination, sizeof(destination)) !=
              (ssize_t)sizeof(frame)) {
            for (;;) nanosleep(&retry, 0);
          }
          for (;;) pause();
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
