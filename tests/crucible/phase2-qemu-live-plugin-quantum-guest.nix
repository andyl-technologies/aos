{pkgs}:
# A minimal diskless Linux initramfs whose PID 1 authenticates readiness through
# the selectable protocol and then blocks, so the kernel idle task runs `sti;
# hlt` while waiting on an exact virtual timer deadline.
pkgs.mkDerivation {
  pname = "crucible-live-plugin-quantum-idle-initramfs";
  version = "0";
  src = null;

  buildDeps = [
    pkgs.coreutils
    pkgs.cpio
    pkgs.pigz
  ];

  phases = [
    {
      name = "build-idle-initramfs";
      script = ''
        set -eu
        cat > init.c <<'INIT_C'
        #define _GNU_SOURCE

        #include <sched.h>
        #include <stdint.h>
        #include <string.h>
        #include <sys/io.h>
        #include <time.h>

        enum {
          REGISTER_BYTES = 81,
          REQUEST_BYTES = 128,
        };

        static const unsigned char setup_complete[] = {
          0x43, 0x52, 0x42, 0x4c, 0x03, 0x00, 0x02,
          0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00,
        };

        static unsigned char registration[REGISTER_BYTES];
        static unsigned char request[REQUEST_BYTES];

        static void put_u16(unsigned char *bytes, unsigned offset, uint16_t value) {
          bytes[offset] = value;
          bytes[offset + 1] = value >> 8;
        }

        static void put_u32(unsigned char *bytes, unsigned offset, uint32_t value) {
          for (unsigned index = 0; index < 4; ++index) {
            bytes[offset + index] = value >> (index * 8);
          }
        }

        static void put_u64(unsigned char *bytes, unsigned offset, uint64_t value) {
          for (unsigned index = 0; index < 8; ++index) {
            bytes[offset + index] = value >> (index * 8);
          }
        }

        static void put_range(
            unsigned char *bytes,
            unsigned offset,
            uint32_t start,
            uint32_t length) {
          put_u32(bytes, offset, start);
          put_u32(bytes, offset + 4, length);
        }

        static void emit_doorbell(void *payload, unsigned length) {
          uintptr_t address = (uintptr_t)payload;
          __asm__ volatile("outb %%al, $0xe7" : : "a"(address), "c"(length) : "memory");
        }

        static int pin_to_boot_vcpu(void) {
          cpu_set_t affinity;

          CPU_ZERO(&affinity);
          CPU_SET(0, &affinity);
          if (sched_setaffinity(0, sizeof(affinity), &affinity) != 0) {
            return -1;
          }
          return sched_getcpu() == 0 ? 0 : -1;
        }

        static void prepare_registration(void) {
          static const unsigned char selectable_id[] = "flight.ready";
          static const unsigned char semantic_tag[] = "readiness";

          put_u16(registration, 0, 1);
          put_u16(registration, 2, 1);
          put_u16(registration, 4, 56);
          put_u32(registration, 8, REGISTER_BYTES);
          put_u64(registration, 12, 1);
          put_range(registration, 20, 56, sizeof(selectable_id) - 1);
          put_range(registration, 28, 68, 1);
          put_range(registration, 36, 69, 1);
          put_range(registration, 44, 70, 11);
          put_u16(registration, 52, 1);
          memcpy(registration + 56, selectable_id, sizeof(selectable_id) - 1);
          registration[68] = 1;
          registration[69] = 1;
          put_u16(registration, 70, sizeof(semantic_tag) - 1);
          memcpy(registration + 72, semantic_tag, sizeof(semantic_tag) - 1);
        }

        static void prepare_request(void) {
          static const unsigned char selectable_id[] = "flight.ready";
          static const unsigned char instance_key[] = "boot";

          put_u16(request, 0, 1);
          put_u16(request, 2, 2);
          put_u16(request, 4, 48);
          put_u32(request, 8, REQUEST_BYTES);
          put_u64(request, 12, 2);
          put_range(request, 20, 48, sizeof(selectable_id) - 1);
          put_range(request, 28, 60, sizeof(instance_key) - 1);
          put_u32(request, 44, 64);
          memcpy(request + 48, selectable_id, sizeof(selectable_id) - 1);
          memcpy(request + 60, instance_key, sizeof(instance_key) - 1);
        }

        int main(void) {
          /* The host authenticates the readiness request as a vCPU-0 event. */
          if (pin_to_boot_vcpu() != 0) {
            return 110;
          }
          if (iopl(3) != 0) {
            return 111;
          }

          prepare_registration();
          prepare_request();
          emit_doorbell(registration, sizeof(registration));
          emit_doorbell((void *)setup_complete, sizeof(setup_complete));
          emit_doorbell(request, sizeof(request));

          /*
           * The first long interval gives the host a stable, readiness-relative
           * window in which to prove all-vCPU idle. Later short intervals retain
           * the exact timer-wake exercise used by the flight.
           */
          const struct timespec readiness_interval = {1, 0};
          const struct timespec interval = {0, 20000000};
          nanosleep(&readiness_interval, NULL);
          for (;;) {
            nanosleep(&interval, NULL);
          }
          return 0;
        }
        INIT_C

        cc -static -O2 -o init init.c
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
        guest_init=pid1-selectable-readiness-then-fixed-interval-nanosleep-loop
        guest_readiness=required-flight.ready-selectable-request
        guest_readiness_vcpu=cpu0-affinity-required-before-doorbell
        guest_idle=kernel-idle-task-sti-hlt-on-near-virtual-timer-deadline
        EVIDENCE
      '';
    }
  ];
}
