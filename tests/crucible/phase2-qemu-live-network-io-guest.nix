{
  pkgs,
  selectable ? false,
}:
# A diskless Linux initramfs whose PID 1 exchanges a raw Ethernet probe,
# acknowledgement, and checkpoint-continuation stream. The guest creates all
# application traffic; the host gate only routes guest-originated frames and
# schedules deterministic responses.
pkgs.mkDerivation {
  pname = "crucible-live-network-io-initramfs";
  version = "0";
  src = null;

  buildDeps =
    [
      pkgs.coreutils
      pkgs.cpio
      pkgs.pigz
    ]
    ++ pkgs.lib.optional selectable pkgs.crucible-guest;

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
        #include <stdio.h>
        #include <stdint.h>
        #include <stdlib.h>
        #include <string.h>
        #include <sys/ioctl.h>
        #include <sys/socket.h>
        #include <time.h>
        #include <unistd.h>
        #include <sys/wait.h>

        #define FRAME_LEN 60
        #define PAYLOAD_OFFSET 14
        #define CRUCIBLE_ETHERTYPE 0x88b5

        static const uint8_t probe_payload[] = "crucible-network-probe-v1";
        static const uint8_t reply_payload[] = "crucible-network-reply-v1";
        static const uint8_t ack_payload[] = "crucible-network-ack-v1";
        static const uint8_t backpressure_payload[] =
          "crucible-network-backpressure-v1";
        static const uint8_t backpressure_ack_payload[] =
          "crucible-network-backpressure-ack-v1";
        static const uint8_t checkpoint_payload[] =
          "crucible-network-checkpoint-v1";
        static const uint8_t continuation_payload[] =
          "crucible-network-continuation-v1";

        #if CRUCIBLE_SELECTABLE_PRODUCT
        static const char recovery_fast_id[] =
          "0101010101010101010101010101010101010101010101010101010101010101";
        static const char recovery_safe_id[] =
          "0202020202020202020202020202020202020202020202020202020202020202";

        static int run_crucible_guest(char *const argv[], char *output,
                                      size_t output_capacity) {
          int output_pipe[2];
          if (pipe(output_pipe) != 0) {
            return -1;
          }
          pid_t child = fork();
          if (child < 0) {
            close(output_pipe[0]);
            close(output_pipe[1]);
            return -1;
          }
          if (child == 0) {
            close(output_pipe[0]);
            if (dup2(output_pipe[1], STDOUT_FILENO) < 0) {
              _exit(126);
            }
            close(output_pipe[1]);
            execv(argv[0], argv);
            _exit(127);
          }

          close(output_pipe[1]);
          size_t used = 0;
          int overflow = 0;
          for (;;) {
            uint8_t scratch[128];
            ssize_t count = read(output_pipe[0], scratch, sizeof(scratch));
            if (count == 0) {
              break;
            }
            if (count < 0) {
              close(output_pipe[0]);
              (void)waitpid(child, 0, 0);
              return -1;
            }
            size_t available = output_capacity > used
              ? output_capacity - used - 1
              : 0;
            size_t copy = (size_t)count < available
              ? (size_t)count
              : available;
            if (copy > 0) {
              memcpy(output + used, scratch, copy);
              used += copy;
            }
            if (copy != (size_t)count) {
              overflow = 1;
            }
          }
          close(output_pipe[0]);
          int status = 0;
          if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
              WEXITSTATUS(status) != 0 || overflow || output_capacity == 0) {
            return -1;
          }
          while (used > 0 && (output[used - 1] == '\n' || output[used - 1] == '\r')) {
            --used;
          }
          output[used] = '\0';
          return 0;
        }

        static int configure_product_selectables(int *fast_recovery,
                                                 uint64_t *retry_quanta) {
          char empty[1];
          char *register_recovery[] = {
            "/crucible-guest", "selectable", "register-discrete", "1",
            "network.recovery-policy",
            (char *)recovery_safe_id,
            "0101010101010101010101010101010101010101010101010101010101010101=fast",
            "0202020202020202020202020202020202020202020202020202020202020202=safe",
            0
          };
          if (run_crucible_guest(register_recovery, empty, sizeof(empty)) != 0) {
            return -1;
          }
          char *register_retry[] = {
            "/crucible-guest", "selectable", "register-u64", "2",
            "network.retry-quanta", "1", "9", "2", "3", "quanta", 0
          };
          if (run_crucible_guest(register_retry, empty, sizeof(empty)) != 0) {
            return -2;
          }
          char *setup_complete[] = {
            "/crucible-guest", "setup-complete", 0
          };
          if (run_crucible_guest(setup_complete, empty, sizeof(empty)) != 0) {
            return -3;
          }

          char recovery[80];
          char *choose_recovery[] = {
            "/crucible-guest", "selectable", "choose-discrete", "1",
            "network.recovery-policy", "routing/boot",
            (char *)recovery_fast_id, (char *)recovery_safe_id, 0
          };
          if (run_crucible_guest(choose_recovery, recovery, sizeof(recovery)) != 0) {
            return -4;
          }
          const char discrete_prefix[] = "discrete=";
          if (strncmp(recovery, discrete_prefix, sizeof(discrete_prefix) - 1) != 0) {
            return -5;
          }
          const char *recovery_id = recovery + sizeof(discrete_prefix) - 1;
          if (strcmp(recovery_id, recovery_fast_id) == 0) {
            *fast_recovery = 1;
          } else if (strcmp(recovery_id, recovery_safe_id) == 0) {
            *fast_recovery = 0;
          } else {
            return -6;
          }

          char retry[32];
          char *choose_retry[] = {
            "/crucible-guest", "selectable", "choose-u64", "2",
            "network.retry-quanta", "routing/boot", "1", "9", "2", 0
          };
          if (run_crucible_guest(choose_retry, retry, sizeof(retry)) != 0 ||
              strncmp(retry, "u64=", 4) != 0) {
            return -7;
          }
          char *end = 0;
          unsigned long long parsed = strtoull(retry + 4, &end, 10);
          if (end == retry + 4 || *end != '\0' || parsed < 1 || parsed > 9 ||
              ((parsed - 1) % 2) != 0) {
            return -8;
          }
          *retry_quanta = (uint64_t)parsed;
          return 0;
        }
        #endif

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

        static int read_guest_mac_and_stagger_tx(int fd, const char *name,
                                                 uint8_t guest_mac[6]) {
          struct ifreq request;
          memset(&request, 0, sizeof(request));
          strncpy(request.ifr_name, name, IFNAMSIZ - 1);
          if (ioctl(fd, SIOCGIFHWADDR, &request) != 0) {
            return -1;
          }
          memcpy(guest_mac, request.ifr_hwaddr.sa_data, 6);

          /*
           * Multi-guest certification assigns stable node-derived MACs. A
           * bounded instruction-count stagger keeps independent boot probes
           * in one canonical order across fresh QEMU process launches. The
           * ordinary single-guest fixture MAC has its high bit clear.
           */
          if (((uint8_t)request.ifr_hwaddr.sa_data[0] & 0x80) != 0) {
            for (volatile uint64_t remaining = 25000000;
                 remaining > 0; --remaining) {
            }
          }
          return 0;
        }

        static int payload_matches(const uint8_t *frame, ssize_t received,
                                   const uint8_t *payload, size_t payload_len) {
          return received >= PAYLOAD_OFFSET + (ssize_t)payload_len &&
                 memcmp(frame + PAYLOAD_OFFSET, payload, payload_len) == 0;
        }

        static int addresses_match(const uint8_t *frame, ssize_t received,
                                   const uint8_t destination[6],
                                   const uint8_t source[6]) {
          return received >= PAYLOAD_OFFSET &&
                 memcmp(frame, destination, 6) == 0 &&
                 memcmp(frame + 6, source, 6) == 0;
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
          if (fd < 0) {
            park_forever();
          }

          struct sockaddr_ll address;
          memset(&address, 0, sizeof(address));
          address.sll_family = AF_PACKET;
          address.sll_protocol = htons(CRUCIBLE_ETHERTYPE);
          address.sll_ifindex = 0;
          if (bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
            park_forever();
          }

          /*
           * Bind the certifying packet socket to the EtherType on all
           * interfaces before IFF_UP enables the virtio receive queue. Linux
           * permits ifindex zero for packet-socket binding even while eth0 is
           * down. Once QEMU can accept the host's exact retained retry,
           * userspace already owns the protocol, so the kernel cannot discard
           * the canary in the interval between IFF_UP and a device bind.
           */
          if (bring_up(fd, "eth0") != 0) {
            park_forever();
          }

          struct ifreq index_request;
          memset(&index_request, 0, sizeof(index_request));
          strncpy(index_request.ifr_name, "eth0", IFNAMSIZ - 1);
          if (ioctl(fd, SIOCGIFINDEX, &index_request) != 0) {
            park_forever();
          }
          uint8_t guest_mac[6];
          if (read_guest_mac_and_stagger_tx(fd, "eth0", guest_mac) != 0) {
            park_forever();
          }

          uint8_t frame[FRAME_LEN];
          const uint8_t broadcast[6] =
            {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

          #if CRUCIBLE_SELECTABLE_PRODUCT
          int fast_recovery = 0;
          uint64_t retry_quanta = 0;
          int selectable_status =
            configure_product_selectables(&fast_recovery, &retry_quanta);
          if (selectable_status != 0) {
            uint8_t error_payload[40];
            memset(error_payload, 0, sizeof(error_payload));
            int error_len = snprintf((char *)error_payload,
                                     sizeof(error_payload),
                                     "crucible-selectable-error-%d",
                                     -selectable_status);
            if (error_len > 0 && error_len < (int)sizeof(error_payload) &&
                error_len <= FRAME_LEN - PAYLOAD_OFFSET) {
              build_frame(frame, broadcast, guest_mac, error_payload,
                          (size_t)error_len);
              (void)send_frame(fd, index_request.ifr_ifindex, frame);
            }
            park_forever();
          }
          #endif

          #if CRUCIBLE_SELECTABLE_PRODUCT
          uint8_t selected_payload[40];
          memset(selected_payload, 0, sizeof(selected_payload));
          const char *policy = fast_recovery ? "fast" : "safe";
          int selected_len = snprintf((char *)selected_payload,
                                      sizeof(selected_payload),
                                      "crucible-selected-%s-q%llu",
                                      policy,
                                      (unsigned long long)retry_quanta);
          if (selected_len <= 0 || selected_len >= (int)sizeof(selected_payload) ||
              selected_len > FRAME_LEN - PAYLOAD_OFFSET) {
            park_forever();
          }
          build_frame(frame, broadcast, guest_mac, selected_payload,
                      (size_t)selected_len);
          if (send_frame(fd, index_request.ifr_ifindex, frame) !=
              (ssize_t)sizeof(frame)) {
            park_forever();
          }
          #endif
          build_frame(frame, broadcast, guest_mac, probe_payload,
                      sizeof(probe_payload) - 1);
          if (send_frame(fd, index_request.ifr_ifindex, frame) !=
              (ssize_t)sizeof(frame)) {
            park_forever();
          }

          for (;;) {
            struct sockaddr_ll incoming;
            socklen_t incoming_len = sizeof(incoming);
            memset(&incoming, 0, sizeof(incoming));
            ssize_t received = recvfrom(fd, frame, sizeof(frame), 0,
                                        (struct sockaddr *)&incoming,
                                        &incoming_len);
            if (received < PAYLOAD_OFFSET || frame[12] != 0x88 ||
                frame[13] != 0xb5 ||
                incoming.sll_ifindex != index_request.ifr_ifindex ||
                incoming.sll_pkttype == PACKET_OUTGOING) {
              continue;
            }

            const uint8_t *response_payload = 0;
            size_t response_payload_len = 0;
            unsigned int response_count = 1;
            uint8_t response_destination[6];
            memcpy(response_destination, broadcast, 6);
            const uint8_t router_mac[6] =
              {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
            if (payload_matches(frame, received, reply_payload,
                                sizeof(reply_payload) - 1) &&
                addresses_match(frame, received, guest_mac, router_mac)) {
              /*
               * This is the certifying ACK branch. It is reachable only for
               * a router-originated frame addressed to this exact NIC, so a
               * reflected guest probe or a misrouted frame cannot satisfy the
               * host's reply-receipt evidence.
               */
              response_payload = ack_payload;
              response_payload_len = sizeof(ack_payload) - 1;
              memcpy(response_destination, router_mac, 6);
            } else if (payload_matches(frame, received, backpressure_payload,
                                       sizeof(backpressure_payload) - 1) &&
                       addresses_match(frame, received, broadcast,
                                       router_mac)) {
              response_payload = backpressure_ack_payload;
              response_payload_len = sizeof(backpressure_ack_payload) - 1;
              memcpy(response_destination, router_mac, 6);
            } else if (payload_matches(frame, received, probe_payload,
                                       sizeof(probe_payload) - 1) &&
                       memcmp(frame, broadcast, 6) == 0 &&
                       memcmp(frame + 6, guest_mac, 6) != 0) {
              /* The two-VM world gate acknowledges only a peer's probe. */
              response_payload = ack_payload;
              response_payload_len = sizeof(ack_payload) - 1;
              memcpy(response_destination, frame + 6, 6);
            } else if (payload_matches(frame, received, ack_payload,
                                       sizeof(ack_payload) - 1)) {
              response_payload = checkpoint_payload;
              response_payload_len = sizeof(checkpoint_payload) - 1;
              response_count = 4;
              memcpy(response_destination, frame + 6, 6);
            } else if (payload_matches(frame, received, checkpoint_payload,
                                       sizeof(checkpoint_payload) - 1)) {
              response_payload = continuation_payload;
              response_payload_len = sizeof(continuation_payload) - 1;
              memcpy(response_destination, frame + 6, 6);
            } else if (payload_matches(frame, received, continuation_payload,
                                       sizeof(continuation_payload) - 1)) {
              response_payload = checkpoint_payload;
              response_payload_len = sizeof(checkpoint_payload) - 1;
              memcpy(response_destination, frame + 6, 6);
            } else {
              continue;
            }

            build_frame(frame, response_destination, guest_mac,
                        response_payload, response_payload_len);
            for (unsigned int response = 0; response < response_count;
                 ++response) {
              if (send_frame(fd, index_request.ifr_ifindex, frame) !=
                  (ssize_t)sizeof(frame)) {
                park_forever();
              }
            }
          }
        }
        INIT_C

        cc -static -O2 -Wall -Wextra -Werror \
          -DCRUCIBLE_SELECTABLE_PRODUCT=${
          if selectable
          then "1"
          else "0"
        } \
          -o init init.c
        strip --strip-all init

        mkdir -p root
        cp init root/init
        chmod 0755 root/init
        ${pkgs.lib.optionalString selectable ''
          cp ${pkgs.crucible-guest}/bin/crucible-guest root/crucible-guest
          chmod 0755 root/crucible-guest
        ''}

        mkdir -p "$out"
        # The product fixture carries a static Rust client. Keep its newc
        # archive uncompressed so deterministic TCG time measures the product
        # behavior rather than billions of guest inflate instructions.
        (
          cd root
          find . -print0 \
            | LC_ALL=C sort -z \
            | cpio --quiet -o -H newc -R +0:+0 --reproducible --null \
            | ${
          if selectable
          then "cat"
          else "pigz -9 -n"
        } > "$out/initrd.img"
        )
        test -s "$out/initrd.img"

        cat > "$out/evidence.env" <<'EVIDENCE'
        guest_format=diskless-linux-initramfs
        guest_init=pid1-raw-ethernet-probe-reply-ack
        guest_traffic_origin=guest-only
        guest_protocol=ethertype-88b5
        guest_interface=virtio-net-eth0
        guest_receive_filter=eth0-non-outgoing
        guest_reply_ack_binding=exact-router-source-and-guest-destination
        guest_self_probe_acknowledgement=forbidden
        multi_guest_tx_order=deterministic-node-mac-stagger
        selectable_product=${
          if selectable
          then "true"
          else "false"
        }
        selectable_guest_surface=${
          if selectable
          then "crucible-guest-typed-cli"
          else "disabled"
        }
        initramfs_encoding=${
          if selectable
          then "uncompressed-newc"
          else "gzip-newc"
        }
        EVIDENCE
      '';
    }
  ];
}
