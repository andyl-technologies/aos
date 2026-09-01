{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
}: let
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  patchName = "0031-crucible-det-rng-delivery.patch";
  patchDir = ../../pkgs/emulation/qemu-patches;
  patchSource = builtins.readFile (patchDir + "/${patchName}");
  patchSeries = import ../../pkgs/emulation/qemu-patches/_series.nix;
  prerequisitePatchNames =
    builtins.filter
    (name: builtins.lessThan name patchName)
    patchSeries.patchFiles;
  applyPrerequisitePatches =
    lib.concatMapStringsSep "\n"
    (name: "patch --batch --fuzz=0 -p1 < ${patchDir + "/${name}"}")
    prerequisitePatchNames;

  rngProbe = pkgs.mkDerivation {
    pname = "crucible-phase1-det-rng-delivery-guest-probe";
    version = "0";
    src = null;

    phases = [
      {
        name = "build-det-rng-delivery-guest-probe";
        script = ''
          set -eu

          mkdir -p "$out/bin"
          cat > virtio-rng-request.c <<'PROBE_C'
          #include <errno.h>
          #include <fcntl.h>
          #include <stdio.h>
          #include <sys/mount.h>
          #include <sys/reboot.h>
          #include <sys/stat.h>
          #include <unistd.h>

          #ifndef RB_POWER_OFF
          #define RB_POWER_OFF 0x4321fedc
          #endif

          enum { SAMPLE_BYTES = 32, DEVICE_WAIT_ATTEMPTS = 400 };

          static int mount_one(const char *source, const char *target,
                               const char *type) {
            if (mkdir(target, 0755) != 0 && errno != EEXIST) {
              perror(target);
              return -1;
            }
            if (mount(source, target, type, 0, "") != 0 && errno != EBUSY) {
              perror(target);
              return -1;
            }
            return 0;
          }

          static int read_hwrng(unsigned char sample[SAMPLE_BYTES]) {
            for (int attempt = 0; attempt < DEVICE_WAIT_ATTEMPTS; attempt++) {
              int fd = open("/dev/hwrng", O_RDONLY | O_NONBLOCK);
              size_t offset = 0;

              if (fd < 0) {
                if (errno == ENOENT || errno == ENODEV) {
                  usleep(10000);
                  continue;
                }
                perror("/dev/hwrng");
                return -1;
              }
              while (offset < SAMPLE_BYTES) {
                ssize_t n = read(fd, sample + offset, SAMPLE_BYTES - offset);
                if (n > 0) {
                  offset += (size_t)n;
                  continue;
                }
                if (n < 0 && (errno == EAGAIN || errno == EINTR)) {
                  usleep(10000);
                  continue;
                }
                if (n < 0) {
                  perror("/dev/hwrng");
                } else {
                  fputs("/dev/hwrng returned EOF\n", stderr);
                }
                close(fd);
                return -1;
              }
              close(fd);
              return 0;
            }
            fputs("/dev/hwrng did not appear\n", stderr);
            return -1;
          }

          int main(void) {
            static const char digits[] = "0123456789abcdef";
            unsigned char sample[SAMPLE_BYTES];
            int result = 1;

            if (mount_one("proc", "/proc", "proc") == 0 &&
                mount_one("sysfs", "/sys", "sysfs") == 0 &&
                mount_one("devtmpfs", "/dev", "devtmpfs") == 0 &&
                read_hwrng(sample) == 0) {
              fputs("VIRTIO_RNG_BYTES=", stdout);
              for (size_t index = 0; index < SAMPLE_BYTES; index++) {
                putchar(digits[sample[index] >> 4]);
                putchar(digits[sample[index] & 0x0f]);
              }
              putchar('\n');
              puts("VIRTIO_RNG_REQUEST:PASS");
              result = 0;
            } else {
              puts("VIRTIO_RNG_REQUEST:FAIL");
            }

            sync();
            if (reboot(RB_POWER_OFF) != 0) {
              perror("poweroff");
            }
            return result;
          }
          PROBE_C

          cc -std=gnu11 -O2 -Wall -Wextra -Werror \
            virtio-rng-request.c -o "$out/bin/virtio-rng-request"
        '';
      }
    ];
  };

  rngProbeInitramfs = pkgs.mkDerivation {
    pname = "crucible-phase1-det-rng-delivery-initramfs";
    version = "0";
    src = null;

    buildDeps = [
      pkgs.coreutils
      pkgs.cpio
      pkgs.findutils
      pkgs.grep
      pkgs.pigz
    ];
    exportReferencesGraph = ["closure-0" rngProbe];

    phases = [
      {
        name = "build-det-rng-delivery-initramfs";
        script = ''
          set -eu

          mkdir -p root/dev root/nix/store root/proc root/sys root/tmp
          grep '^/nix/store/' closure-0 | sort -u > closure-paths
          while IFS= read -r path; do
            cp -a "$path" "root$path"
          done < closure-paths
          ln -s ${rngProbe}/bin/virtio-rng-request root/init

          mkdir -p "$out"
          (
            cd root
            find . -print0 \
              | LC_ALL=C sort -z \
              | cpio --quiet -o -H newc -R +0:+0 --reproducible --null \
              | pigz -9 -n -p "''${NIX_BUILD_CORES:-1}" > "$out/initrd.img"
          )
        '';
      }
    ];
  };

  qemuPackageResultLines =
    if qemuPackage == null
    then ''
      qemu_package=standalone-fixture
      qemu_package_version=standalone-fixture
    ''
    else ''
      qemu_package=${qemuPackage}
      qemu_package_version=${qemuPackage.version}
    '';
  qemuRuntimeResultLines =
    if qemuPackage == null
    then ''
      det_rng_delivery_runtime_exercised=false
    ''
    else ''
      det_rng_delivery_runtime_exercised=true
      det_rng_delivery_exact_source_fixture=passed
      det_rng_delivery_stock_vs_patched_discriminated=true
      det_rng_delivery_plain_icount_upstream_equivalent=true
      det_rng_actual_virtio_request=passed
      det_rng_repeated_payload_identical=true
      det_rng_sim_bottom_half_suppressed=true
    '';

  # Behavioral probe: boot a minimal guest under the sim accelerator and perform
  # a real nonblocking /dev/hwrng read backed by rng-builtin + virtio-rng-pci.
  # The exact-source fixture below separately compiles the stock and patched
  # rng_backend_request_entropy implementations and proves that only patched sim
  # delivery completes before the emulated bottom half. Plain TCG icount matches
  # stock byte-for-byte. This is the backend hop of the two-hop synchronous
  # entropy-completion seal; the dispatch hop is the crucible-det-virtio-ioeventfd
  # microtest. The end-to-end determinism property — two identical runs producing
  # a byte-identical fingerprint under an adversarial host — is witnessed
  # authoritatively by checks.crucible.phase0.s6KaslrAslr and
  # checks.crucible.phase1.guestEntropyLaunch, which the per-patch microtests name.
  qemuRuntimeScript =
    if qemuPackage == null
    then ''
      echo "qemuPackage=null; runtime rng-delivery smoke exercise skipped" > "$out/runtime-skipped.txt"
    ''
    else ''
      qemu="${qemuPackage}/bin/qemu-system-x86_64"

      fail() {
        echo "FAIL: $*" >&2
        exit 1
      }

      vmlinuz=$(ls ${pkgs.linux}/boot/vmlinuz-* | head -1)
      if [ -z "$vmlinuz" ]; then
        fail "no vmlinuz under ${pkgs.linux}/boot"
      fi

      run_guest() {
        run="$1"
        stdout="$out/detrng-$run.stdout"
        stderr="$out/detrng-$run.stderr"
        serial="$out/detrng-$run.serial"
        payload="$out/detrng-$run.payload"
        rm -f "$stdout" "$stderr" "$serial" "$payload"

        timeout 300 "$qemu" \
          -nodefaults \
          -no-user-config \
          -display none \
          -monitor none \
          -machine q35 \
          -accel sim,thread=single \
          -icount shift=0,sleep=off,align=off \
          -cpu qemu64,-rdrand,-rdseed \
          -m 128 \
          -smp 1 \
          -rtc base=2026-01-01T00:00:00,clock=vm \
          -seed 0x0010c031 \
          -object rng-builtin,id=det-rng0 \
          -device virtio-rng-pci,rng=det-rng0,id=det-vrng0 \
          -kernel "$vmlinuz" \
          -initrd ${rngProbeInitramfs}/initrd.img \
          -append "console=ttyS0 reboot=k panic=1 rdinit=/init quiet net.ifnames=0" \
          -chardev file,id=serial0,path="$serial" \
          -serial chardev:serial0 \
          -no-reboot \
          > "$stdout" 2> "$stderr" || {
            cat "$serial" >&2 || true
            cat "$stderr" >&2 || true
            fail "sim virtio-rng request guest run $run failed"
          }

        tr -d '\r' < "$serial" \
          | grep '^VIRTIO_RNG_BYTES=[0-9a-f]\{64\}$' > "$payload" \
          || fail "guest run $run did not receive a 32-byte virtio-rng payload"
        tr -d '\r' < "$serial" \
          | grep -q '^VIRTIO_RNG_REQUEST:PASS$' \
          || fail "guest run $run did not service a virtio-rng request"
      }

      run_guest 1
      run_guest 2
      cmp -s "$out/detrng-1.payload" "$out/detrng-2.payload" \
        || fail "identical sim runs produced different virtio-rng payloads"
    '';

  inherit (import ./_lib.nix {inherit lib;}) hasInfix;

  failuresFor = label: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${label}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  qemuNixRequirements = [
    {
      label = "det rng delivery patch wiring";
      needle = "builtins.concatStringsSep \"\" (map patchCommand series.patchFiles)";
    }
  ];

  patchRequirements = [
    {
      label = "backend drain hook";
      needle = "void (*drain_requests)(RngBackend *s);";
    }
    {
      label = "builtin drain implementation";
      needle = "static void rng_builtin_drain_requests(RngBackend *b)";
    }
    {
      label = "builtin drain registration";
      needle = "rbc->drain_requests = rng_builtin_drain_requests;";
    }
    {
      label = "per-request sim rng sequence";
      needle = "qemu_guest_getrandom_sim_rng_nofail(req->data, req->size);";
    }
    {
      label = "per-request sim rng initialization";
      needle = "g_rand_new_with_seed_array(sim_rng_seed,";
    }
    {
      label = "run-seed capture";
      needle = "memcpy(sim_rng_seed, &seed, sizeof(seed));";
    }
    {
      label = "icount-gated synchronous drain";
      needle = "if (icount_enabled() && strcmp(current_accel_name(), \"sim\") == 0 &&";
    }
    {
      label = "sim-accelerator gate include";
      needle = "qemu/accel.h";
    }
    {
      label = "icount gate include";
      needle = "system/cpu-timers.h";
    }
    {
      label = "no record/replay rationale";
      needle = "RFC-0010";
    }
    {
      label = "paired dispatch seal cross-reference";
      needle = "15-io-subnodes.md";
    }
  ];

  failures =
    failuresFor "pkgs/emulation/qemu.nix" qemuNix qemuNixRequirements
    ++ failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource patchRequirements;
in
  if failures != []
  then throw "crucible phase1 det-rng-delivery check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-det-rng-delivery";
      version = "0";
      src = null;

      inherit patchSource;
      passAsFile = ["patchSource"];

      buildDeps =
        [
          pkgs.coreutils
          pkgs.diffutils
          pkgs.gawk
          pkgs.grep
          pkgs.patch
          pkgs.tar
          pkgs.xz
        ]
        ++ lib.optionals (qemuPackage != null) [qemuPackage];

      phases = [
        {
          name = "run-det-rng-delivery-microtest";
          script = ''
            set -eu

            mkdir -p "$out"

            apply_dir="$TMPDIR/qemu-det-rng-delivery-apply"
            mkdir -p "$apply_dir"
            tar -xf ${pkgs.qemu-crucible.src} -C "$apply_dir"
            source_dir="$apply_dir/qemu-${pkgs.qemu-crucible.version}"

            extract_request_function() {
              source="$1"
              destination="$2"
              gawk '
                /^void rng_backend_request_entropy\(/ { capture = 1 }
                capture {
                  print
                  opens = gsub(/\{/, "{")
                  closes = gsub(/\}/, "}")
                  depth += opens - closes
                  if (opens > 0) {
                    saw_open = 1
                  }
                  if (saw_open && depth == 0) {
                    exit
                  }
                }
              ' "$source" > "$destination"
              test -s "$destination"
            }

            write_request_fixture() {
              implementation="$1"
              function_source="$2"
              fixture_source="$3"

              cat > "$fixture_source.prefix" <<'FIXTURE_PREFIX'
            #include <stdbool.h>
            #include <stdint.h>
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>

            typedef void EntropyReceiveFunc(void *opaque, const void *data,
                                            size_t size);

            typedef struct RngRequest RngRequest;
            typedef struct RngBackend RngBackend;
            typedef struct RngBackendClass RngBackendClass;

            struct RngRequest {
                EntropyReceiveFunc *receive_entropy;
                uint8_t *data;
                void *opaque;
                size_t offset;
                size_t size;
                RngRequest *next;
            };

            typedef struct RequestQueue {
                RngRequest *first;
                RngRequest *last;
            } RequestQueue;

            struct RngBackendClass {
                void (*request_entropy)(RngBackend *s, RngRequest *req);
                void (*drain_requests)(RngBackend *s);
            };

            struct RngBackend {
                RngBackendClass *klass;
                RequestQueue requests;
                unsigned scheduled_bottom_halves;
            };

            #define RNG_BACKEND_GET_CLASS(backend) ((backend)->klass)
            #define g_malloc(size) malloc(size)
            #define QSIMPLEQ_INSERT_TAIL(queue, element, link) do { \
                (element)->next = NULL; \
                if ((queue)->last != NULL) { \
                    (queue)->last->next = (element); \
                } else { \
                    (queue)->first = (element); \
                } \
                (queue)->last = (element); \
            } while (0)

            static bool fixture_icount_enabled;
            static const char *fixture_accel_name;

            static bool icount_enabled(void)
            {
                return fixture_icount_enabled;
            }

            static const char *current_accel_name(void)
            {
                return fixture_accel_name;
            }
            FIXTURE_PREFIX

              cat > "$fixture_source.suffix" <<'FIXTURE_SUFFIX'
            typedef struct VirtioRngFrontend {
                unsigned callbacks;
                uint8_t bytes[16];
                size_t size;
            } VirtioRngFrontend;

            static void schedule_builtin_bottom_half(RngBackend *backend,
                                                     RngRequest *request)
            {
                (void)request;
                backend->scheduled_bottom_halves++;
            }

            static void drain_builtin_requests(RngBackend *backend)
            {
                while (backend->requests.first != NULL) {
                    RngRequest *request = backend->requests.first;

                    backend->requests.first = request->next;
                    if (backend->requests.first == NULL) {
                        backend->requests.last = NULL;
                    }
                    for (size_t index = 0; index < request->size; index++) {
                        request->data[index] = (uint8_t)(0xa0U + index);
                    }
                    request->receive_entropy(request->opaque, request->data,
                                             request->size);
                    free(request->data);
                    free(request);
                }
            }

            static void virtio_rng_receive_entropy(void *opaque, const void *data,
                                                   size_t size)
            {
                VirtioRngFrontend *frontend = opaque;

                if (size > sizeof(frontend->bytes)) {
                    fputs("oversized virtio-rng response\n", stderr);
                    exit(1);
                }
                frontend->callbacks++;
                frontend->size = size;
                memcpy(frontend->bytes, data, size);
            }

            int main(int argc, char **argv)
            {
                RngBackendClass klass = {
                    .request_entropy = schedule_builtin_bottom_half,
                    .drain_requests = drain_builtin_requests,
                };
                RngBackend backend = { .klass = &klass };
                VirtioRngFrontend frontend = { 0 };
                unsigned callbacks_before_bottom_half;
                unsigned expected_bottom_halves;
                bool expect_inline;

                if (argc != 4) {
                    fputs("usage: fixture ACCEL ICOUNT EXPECT_INLINE\n", stderr);
                    return 2;
                }
                fixture_accel_name = argv[1];
                fixture_icount_enabled = strcmp(argv[2], "1") == 0;
                expect_inline = strcmp(argv[3], "1") == 0;
                expected_bottom_halves = expect_inline ? 0 : 1;

                rng_backend_request_entropy(&backend, 16,
                                            virtio_rng_receive_entropy,
                                            &frontend);
                callbacks_before_bottom_half = frontend.callbacks;

                if (backend.scheduled_bottom_halves != expected_bottom_halves ||
                    (callbacks_before_bottom_half == 1) != expect_inline) {
                    fputs("wrong pre-bottom-half delivery state\n", stderr);
                    return 1;
                }
                if (expect_inline != (backend.requests.first == NULL)) {
                    fputs("wrong request queue state\n", stderr);
                    return 1;
                }

                drain_builtin_requests(&backend);
                if (frontend.callbacks != 1 || frontend.size != 16 ||
                    backend.requests.first != NULL ||
                    frontend.bytes[0] != 0xa0 || frontend.bytes[15] != 0xaf) {
                    fputs("virtio-rng request was not serviced exactly once\n",
                          stderr);
                    return 1;
                }

                printf("accel=%s\n", fixture_accel_name);
                printf("icount=%s\n", fixture_icount_enabled ? "on" : "off");
                printf("delivery_before_bottom_half=%s\n",
                       callbacks_before_bottom_half == 1 ? "true" : "false");
                printf("bottom_half_scheduled=%s\n",
                       backend.scheduled_bottom_halves == 1 ? "true" : "false");
                puts("virtio_rng_request_serviced=true");
                puts("virtio_rng_payload=a0..af");
                return 0;
            }
            FIXTURE_SUFFIX

              cat "$fixture_source.prefix" "$function_source" \
                "$fixture_source.suffix" > "$fixture_source"
              cc -std=c11 -O2 -Wall -Wextra -Werror \
                -Wno-unused-function -D"FIXTURE_IMPLEMENTATION=$implementation" \
                "$fixture_source" -o "$fixture_source.bin"
            }

            extract_request_function "$source_dir/backends/rng.c" \
              "$TMPDIR/rng-request-stock.function.c"
            write_request_fixture stock "$TMPDIR/rng-request-stock.function.c" \
              "$TMPDIR/rng-request-stock.c"

            if grep -R -q 'drain_requests' "$source_dir"/backends/rng-builtin.c "$source_dir"/include/system/rng.h 2>/dev/null; then
              echo "stock rng backend already exposes a synchronous drain hook" >&2
              exit 1
            fi

            (
              cd "$source_dir"
              ${applyPrerequisitePatches}
              patch --batch --fuzz=0 -p1 < "$patchSourcePath"
              grep -F -q 'void (*drain_requests)(RngBackend *s);' include/system/rng.h
              grep -F -q 'static void rng_builtin_drain_requests(RngBackend *b)' backends/rng-builtin.c
              grep -F -q 'rbc->drain_requests = rng_builtin_drain_requests;' backends/rng-builtin.c
              grep -F -q 'qemu_guest_getrandom_sim_rng_nofail(req->data, req->size);' backends/rng-builtin.c
              grep -F -q 'void qemu_guest_getrandom_sim_rng_nofail(void *buf, size_t len)' util/guest-random.c
              grep -F -q 'g_rand_new_with_seed_array(sim_rng_seed,' util/guest-random.c
              grep -F -q 'memcpy(sim_rng_seed, &seed, sizeof(seed));' util/guest-random.c
              grep -F -q 'if (icount_enabled() && strcmp(current_accel_name(), "sim") == 0 &&' backends/rng.c
              grep -F -q '#include "qemu/accel.h"' backends/rng.c
              grep -F -q '#include "system/cpu-timers.h"' backends/rng.c
            )

            extract_request_function "$source_dir/backends/rng.c" \
              "$TMPDIR/rng-request-patched.function.c"
            write_request_fixture patched "$TMPDIR/rng-request-patched.function.c" \
              "$TMPDIR/rng-request-patched.c"

            "$TMPDIR/rng-request-stock.c.bin" sim 1 0 > "$out/stock-sim.txt"
            "$TMPDIR/rng-request-patched.c.bin" sim 1 1 > "$out/patched-sim.txt"
            "$TMPDIR/rng-request-stock.c.bin" tcg 1 0 > "$out/stock-plain-icount.txt"
            "$TMPDIR/rng-request-patched.c.bin" tcg 1 0 > "$out/patched-plain-icount.txt"
            "$TMPDIR/rng-request-stock.c.bin" sim 0 0 > "$out/stock-sim-no-icount.txt"
            "$TMPDIR/rng-request-patched.c.bin" sim 0 0 > "$out/patched-sim-no-icount.txt"

            if cmp -s "$out/stock-sim.txt" "$out/patched-sim.txt"; then
              echo "patched sim delivery did not differ from stock" >&2
              exit 1
            fi
            diff -u "$out/stock-plain-icount.txt" "$out/patched-plain-icount.txt"
            diff -u "$out/stock-sim-no-icount.txt" "$out/patched-sim-no-icount.txt"
            grep -q '^delivery_before_bottom_half=false$' "$out/stock-sim.txt"
            grep -q '^delivery_before_bottom_half=true$' "$out/patched-sim.txt"
            grep -q '^bottom_half_scheduled=false$' "$out/patched-sim.txt"
            grep -q '^virtio_rng_request_serviced=true$' "$out/patched-sim.txt"

            ${qemuRuntimeScript}

            cat > "$out/result" <<'RESULT'
            PASS
            check=checks.crucible.phase1.detRngDelivery
            gate=gate:layer0-determinism
            gate=gate:patch-microtests
            tasks=T-DET-1
            patch=0031-crucible-det-rng-delivery.patch
            patched_fixture_exercised=true
            stock_negative_control=true
            stock_vs_patched_sim_discriminated=true
            plain_icount_matches_upstream=true
            sim_without_icount_matches_upstream=true
            exact_rng_backend_request_function_exercised=true
            virtio_rng_request_serviced=true
            sim_bottom_half_suppressed=true
            seal_hop=backend
            paired_dispatch_seal=0032-crucible-det-virtio-ioeventfd.patch
            e2e_witness=checks.crucible.phase0.s6KaslrAslr
            e2e_witness=checks.crucible.phase1.guestEntropyLaunch
            ${qemuPackageResultLines}
            ${qemuRuntimeResultLines}
            RESULT
          '';
        }
      ];
    }
