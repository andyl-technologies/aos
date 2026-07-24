{pkgs}:
# A diskless Linux initramfs whose PID 1 emits one raw Ethernet probe, blocks
# until the Crucible router reply arrives, then emits an acknowledgement. The
# guest creates all application traffic; the host gate only routes the
# guest-originated frame and schedules its deterministic response.
pkgs.mkDerivation {
  pname = "crucible-live-network-io-initramfs";
  version = "0";
  src = null;

  buildDeps = [
    pkgs.coreutils
    pkgs.cpio
    pkgs.pigz
  ];

  phases = [
    {
      name = "build-live-network-io-initramfs";
      script = ''
        set -eu
        cat > init.c <<'INIT_C'
        #include <arpa/inet.h>
        #include <linux/if_packet.h>
        #include <net/ethernet.h>
        #include <net/if.h>
        #include <stdint.h>
        #include <string.h>
        #include <sys/ioctl.h>
        #include <sys/socket.h>
        #include <time.h>
        #include <unistd.h>

        #define FRAME_LEN 60
        #define PAYLOAD_OFFSET 14
        #define CRUCIBLE_ETHERTYPE 0x88b5

        static const uint8_t guest_mac[6] =
          {0x52, 0x54, 0x00, 0x12, 0x34, 0x56};
        static const uint8_t probe_payload[] = "crucible-network-probe-v1";
        static const uint8_t reply_payload[] = "crucible-network-reply-v1";
        static const uint8_t ack_payload[] = "crucible-network-ack-v1";

        static void park_forever(void) {
          const struct timespec interval = {0, 20000000};
          for (;;) {
            nanosleep(&interval, 0);
          }
        }

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

        static void build_frame(uint8_t frame[FRAME_LEN],
                                const uint8_t destination[6],
                                const uint8_t source[6],
                                const uint8_t *payload,
                                size_t payload_len) {
          memset(frame, 0, FRAME_LEN);
          memcpy(frame, destination, 6);
          memcpy(frame + 6, source, 6);
          frame[12] = 0x88;
          frame[13] = 0xb5;
          memcpy(frame + PAYLOAD_OFFSET, payload, payload_len);
        }

        static ssize_t send_frame(int fd, int ifindex,
                                  const uint8_t frame[FRAME_LEN]) {
          struct sockaddr_ll destination;
          memset(&destination, 0, sizeof(destination));
          destination.sll_family = AF_PACKET;
          destination.sll_protocol = htons(CRUCIBLE_ETHERTYPE);
          destination.sll_ifindex = ifindex;
          destination.sll_halen = 6;
          memcpy(destination.sll_addr, frame, 6);
          return sendto(fd, frame, FRAME_LEN, 0,
                        (struct sockaddr *)&destination, sizeof(destination));
        }

        int main(void) {
          int fd = socket(AF_PACKET, SOCK_RAW, htons(CRUCIBLE_ETHERTYPE));
          if (fd < 0 || bring_up(fd, "eth0") != 0) {
            park_forever();
          }

          struct ifreq index_request;
          memset(&index_request, 0, sizeof(index_request));
          strncpy(index_request.ifr_name, "eth0", IFNAMSIZ - 1);
          if (ioctl(fd, SIOCGIFINDEX, &index_request) != 0) {
            park_forever();
          }

          struct sockaddr_ll address;
          memset(&address, 0, sizeof(address));
          address.sll_family = AF_PACKET;
          address.sll_protocol = htons(CRUCIBLE_ETHERTYPE);
          address.sll_ifindex = index_request.ifr_ifindex;
          if (bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
            park_forever();
          }

          uint8_t frame[FRAME_LEN];
          const uint8_t broadcast[6] =
            {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
          build_frame(frame, broadcast, guest_mac, probe_payload,
                      sizeof(probe_payload) - 1);
          if (send_frame(fd, index_request.ifr_ifindex, frame) !=
              (ssize_t)sizeof(frame)) {
            park_forever();
          }

          for (;;) {
            ssize_t received = recv(fd, frame, sizeof(frame), 0);
            if (received < PAYLOAD_OFFSET + (ssize_t)(sizeof(reply_payload) - 1)) {
              continue;
            }
            if (frame[12] != 0x88 || frame[13] != 0xb5 ||
                memcmp(frame + PAYLOAD_OFFSET, reply_payload,
                       sizeof(reply_payload) - 1) != 0) {
              continue;
            }

            const uint8_t router_mac[6] =
              {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
            build_frame(frame, router_mac, guest_mac, ack_payload,
                        sizeof(ack_payload) - 1);
            if (send_frame(fd, index_request.ifr_ifindex, frame) !=
                (ssize_t)sizeof(frame)) {
              park_forever();
            }
            park_forever();
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

        cat > "$out/evidence.env" <<'EVIDENCE'
        guest_format=diskless-linux-initramfs
        guest_init=pid1-raw-ethernet-probe-reply-ack
        guest_traffic_origin=guest-only
        guest_protocol=ethertype-88b5
        guest_interface=virtio-net-eth0
        EVIDENCE
      '';
    }
  ];
}
