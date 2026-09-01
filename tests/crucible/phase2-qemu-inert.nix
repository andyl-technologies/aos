{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.gates.qemuInert",
  taskIds ? ["T-DET-23" "T-HARN-21" "T-PATCH-3"],
  openTaskIds ? [],
  patchMicrotests ? import ./phase2-patch-microtests.nix {inherit pkgs lib;},
  referenceQemu ? pkgs.qemu-crucible-reference,
  patchedQemu ? pkgs.qemu-crucible,
  dependencies ? [],
}: let
  # Deterministic structural proof that the virtio-rng delivery patches
  # (0031/0032) are byte-for-byte inert with sim off, closing the E7a async
  # RNG-completion delivery-icount residual. See the derivation header for why
  # this is a proof rather than a (necessarily flaky) runtime measurement.
  rngDeliveryInert = import ./phase2-qemu-rng-delivery-inert.nix {
    inherit pkgs lib;
    qemuPackage = patchedQemu;
  };
  workload = pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-inert-workload";
    version = "0";
    src = null;

    phases = [
      {
        name = "build-workload";
        script = ''
          mkdir -p "$out/bin"

          cat > inert-workload.c <<'INERT_WORKLOAD_C'
          #include <fcntl.h>
          #include <stdint.h>
          #include <stdio.h>
          #include <string.h>
          #include <unistd.h>

          enum { RNG_SAMPLE_BYTES = 64 };

          static uint64_t fnv1a_update(uint64_t hash,
                                       const unsigned char *buf,
                                       size_t len) {
            for (size_t i = 0; i < len; i++) {
              hash ^= buf[i];
              hash *= 1099511628211ULL;
            }
            return hash;
          }

          static uint64_t fnv1a(const unsigned char *buf, size_t len) {
            return fnv1a_update(1469598103934665603ULL, buf, len);
          }

          static int read_prefix(const char *path, unsigned char *buf, size_t len) {
            int fd = open(path, O_RDONLY);
            if (fd < 0) {
              perror(path);
              return 1;
            }
            ssize_t got = read(fd, buf, len);
            if (got < 0) {
              perror("read");
              close(fd);
              return 1;
            }
            close(fd);
            if ((size_t)got != len) {
              fprintf(stderr, "%s: short read: %zd\n", path, got);
              return 1;
            }
            return 0;
          }

          static int read_hwrng(unsigned char *buf, size_t len,
                                uint32_t *read_calls) {
            int fd = open("/dev/hwrng", O_RDONLY);
            size_t offset = 0;

            if (fd < 0) {
              perror("/dev/hwrng");
              return 1;
            }
            while (offset < len) {
              ssize_t got;
              *read_calls += 1;
              got = read(fd, buf + offset, len - offset);
              if (got < 0) {
                perror("read /dev/hwrng");
                close(fd);
                return 1;
              }
              if (got == 0) {
                fprintf(stderr, "/dev/hwrng: unexpected EOF\n");
                close(fd);
                return 1;
              }
              offset += (size_t)got;
            }
            close(fd);
            return 0;
          }

          static uint64_t workload_fingerprint(const unsigned char *block,
                                               size_t block_len,
                                               const unsigned char *ninep,
                                               size_t ninep_len,
                                               const unsigned char *rng,
                                               size_t rng_len) {
            static const unsigned char domain[] =
              "crucible-qemu-inert-guest-output-v1";
            uint64_t hash = 1469598103934665603ULL;

            hash = fnv1a_update(hash, domain, sizeof(domain) - 1);
            hash = fnv1a_update(hash, block, block_len);
            hash = fnv1a_update(hash, ninep, ninep_len);
            return fnv1a_update(hash, rng, rng_len);
          }

          static int write_evidence(const char *path,
                                    const unsigned char *block,
                                    size_t block_len,
                                    const unsigned char *ninep,
                                    size_t ninep_len,
                                    const unsigned char *rng,
                                    size_t rng_len,
                                    uint32_t read_calls,
                                    uint64_t execution_fingerprint) {
            FILE *file = fopen(path, "w");
            if (file == NULL) {
              perror(path);
              return 1;
            }
            if (fprintf(file,
                        "format=crucible-qemu-inert-execution-output-v1\n"
                        "block_hash=%016llx\n"
                        "ninep_hash=%016llx\n"
                        "rng_bytes=",
                        (unsigned long long)fnv1a(block, block_len),
                        (unsigned long long)fnv1a(ninep, ninep_len)) < 0) {
              perror("write evidence");
              fclose(file);
              return 1;
            }
            for (size_t index = 0; index < rng_len; index++) {
              if (fprintf(file, "%02x", rng[index]) < 0) {
                perror("write RNG evidence");
                fclose(file);
                return 1;
              }
            }
            if (fprintf(file,
                        "\nrng_bytes_read=%zu\n"
                        "rng_read_calls=%u\n"
                        "guest_output_fingerprint=%016llx\n",
                        rng_len,
                        read_calls,
                        (unsigned long long)execution_fingerprint) < 0 ||
                fclose(file) != 0) {
              perror("finish evidence");
              return 1;
            }
            return 0;
          }

          int main(int argc, char **argv) {
            unsigned char block[128];
            unsigned char ninep[128];
            unsigned char rng[RNG_SAMPLE_BYTES];
            uint32_t rng_read_calls = 0;
            uint64_t execution_fingerprint;
            if (argc != 4) {
              fprintf(stderr,
                      "usage: inert-workload BLOCK_FILE NINEP_FILE EVIDENCE_FILE\n");
              return 1;
            }
            if (read_prefix(argv[1], block, sizeof(block)) != 0 ||
                read_prefix(argv[2], ninep, sizeof(ninep)) != 0 ||
                read_hwrng(rng, sizeof(rng), &rng_read_calls) != 0) {
              return 1;
            }
            const char *block_prefix = "CRUCIBLE_QEMU_INERT_BLOCK";
            const char *ninep_prefix = "CRUCIBLE_QEMU_INERT_9P";
            if (memcmp(block, block_prefix, strlen(block_prefix)) != 0 ||
                memcmp(ninep, ninep_prefix, strlen(ninep_prefix)) != 0) {
              fprintf(stderr, "unexpected device payload\n");
              return 1;
            }
            execution_fingerprint = workload_fingerprint(
              block, sizeof(block), ninep, sizeof(ninep), rng, sizeof(rng));
            if (write_evidence(argv[3], block, sizeof(block), ninep,
                               sizeof(ninep), rng, sizeof(rng),
                               rng_read_calls, execution_fingerprint) != 0) {
              return 1;
            }
            printf("CRUCIBLE_QEMU_INERT_BLOCK_HASH=%016llx\n",
                   (unsigned long long)fnv1a(block, sizeof(block)));
            printf("CRUCIBLE_QEMU_INERT_9P_HASH=%016llx\n",
                   (unsigned long long)fnv1a(ninep, sizeof(ninep)));
            printf("CRUCIBLE_QEMU_INERT_RNG_HASH=%016llx\n",
                   (unsigned long long)fnv1a(rng, sizeof(rng)));
            printf("CRUCIBLE_QEMU_INERT_RNG_BYTES=%zu\n", sizeof(rng));
            printf("CRUCIBLE_QEMU_INERT_RNG_READ_CALLS=%u\n", rng_read_calls);
            printf("CRUCIBLE_QEMU_INERT_GUEST_OUTPUT_FINGERPRINT=%016llx\n",
                   (unsigned long long)execution_fingerprint);
            printf("CRUCIBLE_QEMU_INERT_DEVICE_IO_DONE\n");
            return 0;
          }
          INERT_WORKLOAD_C

          cc -std=c11 -O2 -Wall -Wextra -Werror inert-workload.c \
            -o "$out/bin/inert-workload"

          cat > poweroff.c <<'POWEROFF_C'
          #include <stdio.h>
          #include <sys/reboot.h>
          #include <unistd.h>

          #ifndef RB_POWER_OFF
          #define RB_POWER_OFF 0x4321fedc
          #endif

          int main(void) {
            sync();
            if (reboot(RB_POWER_OFF) != 0) {
              perror("poweroff");
              return 1;
            }
            return 0;
          }
          POWEROFF_C

          cc -std=gnu11 -O2 -Wall -Wextra -Werror poweroff.c \
            -o "$out/bin/inert-poweroff"
        '';
      }
    ];
  };

  initramfs = let
    initramfsDeps = [
      pkgs.bash
      pkgs.coreutils
      pkgs.kmod
      pkgs.linux
      pkgs.util-linux
      workload
    ];
    depPaths = builtins.concatStringsSep ":" (
      builtins.concatMap (
        dep: let
          base = builtins.toString dep;
        in [
          "${base}/bin"
          "${base}/sbin"
        ]
      )
      initramfsDeps
    );
    graphPairs =
      lib.concatLists
      (lib.imap (i: dep: [
          "closure-${builtins.toString i}"
          dep
        ])
        initramfsDeps);
  in
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-inert-initramfs";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.cpio
        pkgs.findutils
        pkgs.grep
        pkgs.pigz
      ];

      exportReferencesGraph = graphPairs;

      phases = [
        {
          name = "build-initramfs";
          script = ''
            set -eu

            grep -h '^/nix/store/' closure-* | sort -u > closure-paths

            mkdir -p root/bin root/sbin root/lib root/nix/store root/tmp root/proc root/sys root/dev root/run root/mnt/virtfs
            while IFS= read -r p; do
              cp -a "$p" root"$p"
            done < closure-paths

            ln -sfn ${pkgs.bash}/bin/bash root/bin/sh
            ln -sfn ${pkgs.bash}/bin/bash root/bin/bash
            ln -sfn ${pkgs.linux}/lib/modules root/lib/modules
            ln -sfn ${workload}/bin/inert-poweroff root/sbin/poweroff

            cat > root/init <<'INIT'
            #!${pkgs.bash}/bin/bash
            export PATH="/bin:/sbin:${depPaths}"
            export HOME=/tmp

            mount -t proc proc /proc
            mount -t sysfs sysfs /sys
            mount -t devtmpfs devtmpfs /dev
            mount -t tmpfs tmpfs /tmp
            mount -t tmpfs tmpfs /run

            echo "CRUCIBLE_QEMU_INERT_READY"
            test_result=0

            for module in 9pnet 9pnet_virtio 9p virtio_rng; do
              modprobe "$module" || test_result=1
            done

            i=0
            while [ "$i" -lt 100 ] && { [ ! -b /dev/vda ] || [ ! -c /dev/hwrng ]; }; do
              sleep 0.05
              i=$((i + 1))
            done
            [ -b /dev/vda ] || test_result=1
            [ -c /dev/hwrng ] || test_result=1

            if [ "$test_result" -eq 0 ]; then
              mount -t 9p -o trans=virtio,version=9p2000.L,msize=262144 crucible_inert /mnt/virtfs || test_result=1
            fi

            if [ "$test_result" -eq 0 ]; then
              inert-workload \
                /dev/vda \
                /mnt/virtfs/payload.txt \
                /mnt/virtfs/execution-fingerprint.txt \
                || test_result=1
            fi

            if [ "$test_result" -eq 0 ]; then
              echo 'TEST_RESULT:PASS'
            else
              echo 'TEST_RESULT:FAIL'
            fi

            sync
            sleep 0.2
            poweroff
            INIT
            chmod +x root/init

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
in
  pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-inert";
    version = "0";
    src = null;

    buildDeps =
      [
        pkgs.coreutils
        pkgs.diffutils
        pkgs.gawk
        pkgs.grep
        pkgs.jq
        pkgs.socat
        referenceQemu
        patchedQemu
      ]
      ++ dependencies;

    INITRAMFS = "${initramfs}/initrd.img";
    KERNEL = builtins.toString pkgs.linux;
    PATCH_MICROTESTS_RESULT = "${patchMicrotests}/result";
    RNG_DELIVERY_INERT_RESULT = "${rngDeliveryInert}/result";
    REFERENCE_QEMU = "${referenceQemu}/bin/qemu-system-x86_64";
    REFERENCE_QEMU_IMG = "${referenceQemu}/bin/qemu-img";
    PATCHED_QEMU = "${patchedQemu}/bin/qemu-system-x86_64";
    PATCHED_QEMU_IMG = "${patchedQemu}/bin/qemu-img";

    phases = [
      {
        name = "run-qemu-inert-corpus";
        script = ''
          set -eu

          unset LD_LIBRARY_PATH || true

          fail() {
            echo "FAIL: $*" >&2
            exit 1
          }

          qemu_pid=""

          cleanup_qemu() {
            if [ -n "''${qemu_pid:-}" ]; then
              kill "$qemu_pid" 2>/dev/null || true
              wait "$qemu_pid" 2>/dev/null || true
              qemu_pid=""
            fi
          }

          trap cleanup_qemu EXIT

          json_string() {
            printf '%s\n' "$1" | jq -R .
          }

          qmp_cmd() {
            socket="$1"
            request="$2"
            response="$3"
            response_err="$response.err"

            {
              printf '{"execute":"qmp_capabilities"}\r\n'
              printf '%s\r\n' "$request"
            } | socat -T 2 - "UNIX-CONNECT:$socket" > "$response" 2> "$response_err" || true

            if [ ! -s "$response" ]; then
              cat "$response_err" >&2
              return 1
            fi

            if jq -e -s 'any(.[]; has("error"))' "$response" >/dev/null; then
              cat "$response" >&2
              return 1
            fi
            jq -e -s '[.[] | select(has("return"))] | length >= 2' "$response" >/dev/null
          }

          qmp_cmd_expect_error() {
            socket="$1"
            request="$2"
            response="$3"
            response_err="$response.err"

            {
              printf '{"execute":"qmp_capabilities"}\r\n'
              printf '%s\r\n' "$request"
            } | socat -T 2 - "UNIX-CONNECT:$socket" > "$response" 2> "$response_err" || true

            if [ ! -s "$response" ]; then
              cat "$response_err" >&2
              return 1
            fi

            jq -e -s '
              ([.[] | select(has("return"))] | length) >= 1 and
              ([.[] | select(has("error"))] | length) == 1
            ' "$response" >/dev/null
          }

          wait_for_socket() {
            socket="$1"
            waited=0
            while [ "$waited" -lt 600 ]; do
              if [ -S "$socket" ]; then
                return 0
              fi
              sleep 0.1
              waited=$((waited + 1))
            done
            return 1
          }

          wait_for_guest_pass() {
            serial="$1"
            pid="$2"
            waited=0
            while [ "$waited" -lt 600 ]; do
              if [ -f "$serial" ] && grep -q "TEST_RESULT:PASS" "$serial"; then
                return 0
              fi
              if ! kill -0 "$pid" 2>/dev/null; then
                return 2
              fi
              sleep 0.5
              waited=$((waited + 1))
            done
            return 1
          }

          wait_for_migration() {
            label="$1"
            socket="$2"
            waited=0
            while [ "$waited" -lt 600 ]; do
              if qmp_cmd "$socket" '{"execute":"query-migrate"}' "$TMPDIR/qmp-query-migrate-$label.json"; then
                status=$(jq -r -s '[.[] | select(has("return"))][-1].return.status // empty' "$TMPDIR/qmp-query-migrate-$label.json")
                case "$status" in
                  completed)
                    return 0
                    ;;
                  failed | cancelled)
                    cat "$TMPDIR/qmp-query-migrate-$label.json" >&2
                    return 1
                    ;;
                esac
              fi
              sleep 0.25
              waited=$((waited + 1))
            done
            return 1
          }

          wait_for_job() {
            label="$1"
            socket="$2"
            job="$3"
            waited=0
            while [ "$waited" -lt 600 ]; do
              if qmp_cmd "$socket" '{"execute":"query-jobs"}' "$TMPDIR/qmp-jobs-$label-$job.json"; then
                if jq -e -s --arg job "$job" '
                  [.[] | select(has("return"))][-1].return[]
                  | select(.id == $job)
                  | has("error")
                ' "$TMPDIR/qmp-jobs-$label-$job.json" >/dev/null; then
                  cat "$TMPDIR/qmp-jobs-$label-$job.json" >&2
                  return 1
                fi
                if jq -e -s --arg job "$job" '
                  [.[] | select(has("return"))][-1].return[]
                  | select(.id == $job)
                  | .status == "concluded"
                ' "$TMPDIR/qmp-jobs-$label-$job.json" >/dev/null; then
                  return 0
                fi
              fi
              sleep 0.25
              waited=$((waited + 1))
            done
            return 1
          }

          normalize_serial() {
            input="$1"
            output="$2"
            # This projection is retained only as a focused workload-evidence
            # artifact. The gate separately byte-compares the authoritative
            # raw guest serial prefixes through TEST_RESULT:PASS, so filtering
            # here cannot hide a guest-visible divergence.
            grep -E '^(CRUCIBLE_QEMU_INERT_|TEST_RESULT:)' "$input" > "$output"
          }

          files_identical() {
            cmp -s "$1" "$2"
          }

          compare_files() {
            label="$1"
            left="$2"
            right="$3"
            if ! files_identical "$left" "$right"; then
              diff -u "$left" "$right" > "$TMPDIR/$label.diff" || true
              cat "$TMPDIR/$label.diff" >&2
              fail "$label diverged between unpatched reference and patched sim-off QEMU"
            fi
          }

          validate_execution_evidence() {
            label="$1"
            evidence="$2"
            grep -F -x -q 'format=crucible-qemu-inert-execution-output-v1' "$evidence" \
              || fail "$label execution evidence has the wrong format"
            grep -E -x -q 'block_hash=[0-9a-f]{16}' "$evidence" \
              || fail "$label execution evidence lacks the block hash"
            grep -E -x -q 'ninep_hash=[0-9a-f]{16}' "$evidence" \
              || fail "$label execution evidence lacks the 9p hash"
            grep -E -x -q 'rng_bytes=[0-9a-f]{128}' "$evidence" \
              || fail "$label execution evidence lacks 64 raw RNG bytes"
            grep -F -x -q 'rng_bytes_read=64' "$evidence" \
              || fail "$label execution evidence has the wrong RNG byte count"
            grep -E -x -q 'rng_read_calls=[1-9][0-9]*' "$evidence" \
              || fail "$label execution evidence lacks the RNG read-call count"
            grep -E -x -q 'guest_output_fingerprint=[0-9a-f]{16}' "$evidence" \
              || fail "$label execution evidence lacks the guest output fingerprint"
            grep -E -x -q 'execution_fingerprint_sha256=[0-9a-f]{64}' "$evidence" \
              || fail "$label execution evidence lacks its composite binding"
            test "$(wc -l < "$evidence" | tr -d ' ')" -eq 8 \
              || fail "$label execution evidence has unexpected fields"
            evidence_body="$TMPDIR/$label.execution-evidence.body"
            head -n 7 "$evidence" > "$evidence_body"
            actual_binding=$(sha256sum "$evidence_body" | gawk '{ print $1 }')
            expected_binding=$(gawk -F= '
              /^execution_fingerprint_sha256=/ {
                print $2
                found += 1
              }
              END {
                if (found != 1) {
                  exit 1
                }
              }
            ' "$evidence")
            test "$actual_binding" = "$expected_binding" \
              || fail "$label execution evidence composite binding is invalid"
          }

          exercise_serial_normalization_negative_control() {
            left="$TMPDIR/serial-normalization-left.raw"
            right="$TMPDIR/serial-normalization-right.raw"
            printf 'guest-visible-line-a\nTEST_RESULT:PASS\n' > "$left"
            printf 'guest-visible-line-b\nTEST_RESULT:PASS\n' > "$right"
            normalize_serial "$left" "$TMPDIR/serial-normalization-left.projected"
            normalize_serial "$right" "$TMPDIR/serial-normalization-right.projected"
            files_identical \
              "$TMPDIR/serial-normalization-left.projected" \
              "$TMPDIR/serial-normalization-right.projected" \
              || fail "serial normalization negative-control projections should match"
            if files_identical "$left" "$right"; then
              fail "raw serial comparison failed to expose a filtered guest-visible divergence"
            fi
          }

          bind_execution_evidence() {
            label="$1"
            source="$2"
            destination="$3"
            test "$(wc -l < "$source" | tr -d ' ')" -eq 7 \
              || fail "$label guest evidence has unexpected fields"
            binding=$(sha256sum "$source" | gawk '{ print $1 }')
            {
              cat "$source"
              printf 'execution_fingerprint_sha256=%s\n' "$binding"
            } > "$destination"
            validate_execution_evidence "$label" "$destination"
          }

          exercise_rng_leakage_negative_control() {
            source="$1"
            mutated="$TMPDIR/rng-leakage-negative-control.txt"
            mutated_body="$TMPDIR/rng-leakage-negative-control.body"
            gawk -F= '
              /^rng_read_calls=/ {
                printf "rng_read_calls=%u\n", ($2 + 1)
                changed += 1
                next
              }
              /^execution_fingerprint_sha256=/ { next }
              { print }
              END {
                if (changed != 1) {
                  exit 1
                }
              }
            ' "$source" > "$mutated_body"
            mutated_binding=$(sha256sum "$mutated_body" | gawk '{ print $1 }')
            {
              cat "$mutated_body"
              printf 'execution_fingerprint_sha256=%s\n' "$mutated_binding"
            } > "$mutated"
            validate_execution_evidence rng-leakage-negative-control "$mutated"
            if files_identical "$source" "$mutated"; then
              fail "RNG leakage negative control did not change the request-path evidence"
            fi
            source_hash=$(sha256sum "$source" | gawk '{ print $1 }')
            mutated_hash=$(sha256sum "$mutated" | gawk '{ print $1 }')
            test "$source_hash" != "$mutated_hash" \
              || fail "RNG leakage negative control did not change the evidence digest"
            source_binding=$(gawk -F= '/^execution_fingerprint_sha256=/ { print $2 }' "$source")
            test "$source_binding" != "$mutated_binding" \
              || fail "RNG leakage negative control did not change the composite binding"
            diff -u "$source" "$mutated" \
              > "$TMPDIR/rng-leakage-negative-control.diff" || true
            grep -F -q 'rng_read_calls=' "$TMPDIR/rng-leakage-negative-control.diff" \
              || fail "RNG leakage negative control did not discriminate the RNG behavior field"
            grep -F -q 'execution_fingerprint_sha256=' "$TMPDIR/rng-leakage-negative-control.diff" \
              || fail "RNG leakage negative control did not discriminate the composite binding"
          }

          vmlinuz=$(ls "$KERNEL"/boot/vmlinuz-* | head -1)
          if [ -z "$vmlinuz" ]; then
            fail "no vmlinuz under $KERNEL/boot"
          fi

          grep -q '^PASS$' "$PATCH_MICROTESTS_RESULT" \
            || fail "patch-microtests dependency did not pass"

          grep -q '^PASS$' "$RNG_DELIVERY_INERT_RESULT" \
            || fail "virtio-rng delivery structural inertness proof did not pass"
          grep -q '^rng_completion_icount_equivalence_proven=true$' "$RNG_DELIVERY_INERT_RESULT" \
            || fail "virtio-rng delivery proof did not establish delivery-icount equivalence"
          exercise_serial_normalization_negative_control

          seed="$TMPDIR/seed.bin"
          block_image="$TMPDIR/block.img"
          ninep_root="$TMPDIR/9p-root"
          printf 'crucible-phase2-qemu-inert-seed-v1\n' > "$seed"
          dd if=/dev/zero of="$block_image" bs=1M count=8 status=none
          printf 'CRUCIBLE_QEMU_INERT_BLOCK payload v1\n' \
            | dd of="$block_image" bs=1 seek=0 conv=notrunc status=none
          mkdir -p "$ninep_root"
          dd if=/dev/zero of="$ninep_root/payload.txt" bs=128 count=1 status=none
          {
            printf 'CRUCIBLE_QEMU_INERT_9P payload v1\n'
            printf 'read-only reference payload\n'
          } | dd of="$ninep_root/payload.txt" bs=1 seek=0 conv=notrunc status=none

          run_boot_case() {
            label="$1"
            qemu="$2"
            icount_mode="$3"
            qmp_socket="$TMPDIR/qmp-boot-$label.sock"
            serial="$TMPDIR/serial-$label.log"
            stderr="$TMPDIR/qemu-boot-$label.stderr"
            evidence_source="$ninep_root/execution-fingerprint.txt"
            evidence="$TMPDIR/execution-fingerprint-$label.txt"
            rm -f "$qmp_socket" "$serial" "$stderr" "$evidence_source" "$evidence"

            case "$icount_mode" in
              deterministic)
                icount_args="-icount shift=7,sleep=off,align=off"
                ;;
              plain)
                icount_args="-icount shift=0,sleep=off,align=off"
                ;;
              *)
                fail "unknown icount mode $icount_mode"
                ;;
            esac

            # shellcheck disable=SC2086
            timeout 600 "$qemu" \
              -nodefaults \
              -no-user-config \
              -display none \
              -monitor none \
              -machine q35 \
              -accel tcg,thread=single \
              $icount_args \
              -cpu qemu64,-rdrand,-rdseed \
              -m 1024 \
              -smp 1 \
              -rtc base=2026-01-01T00:00:00,clock=vm \
              -seed 0x0010c001 \
              -fw_cfg name=opt/crucible/seed,file="$seed" \
              -object rng-random,id=inert-rng0,filename=/dev/zero \
              -device virtio-rng-pci,rng=inert-rng0,id=inert-vrng0 \
              -kernel "$vmlinuz" \
              -initrd "$INITRAMFS" \
              -append "console=ttyS0 reboot=k panic=1 rdinit=/init quiet net.ifnames=0 printk.time=0" \
              -drive id=inertblock,file="$block_image",format=raw,if=none,readonly=on,cache=unsafe \
              -device virtio-blk-pci,drive=inertblock \
              -fsdev local,id=fs0,path="$ninep_root",security_model=none \
              -device virtio-9p-pci,fsdev=fs0,mount_tag=crucible_inert \
              -chardev file,id=serial0,path="$serial" \
              -serial chardev:serial0 \
              -qmp "unix:$qmp_socket,server=on,wait=off" \
              -no-reboot \
              2> "$stderr" &
            qemu_pid="$!"

            wait_for_socket "$qmp_socket" || {
              cat "$stderr" >&2 || true
              fail "$label QMP socket did not appear"
            }
            if wait_for_guest_pass "$serial" "$qemu_pid"; then
              gawk '
                { print }
                /^TEST_RESULT:PASS\r?$/ { exit }
              ' "$serial" > "$TMPDIR/authoritative-serial-$label.log"
            else
              wait_status="$?"
              cat "$serial" >&2 || true
              cat "$stderr" >&2 || true
              wait "$qemu_pid" || true
              qemu_pid=""
              case "$wait_status" in
                2)
                  fail "$label QEMU exited before TEST_RESULT:PASS"
                  ;;
                *)
                  fail "$label did not report TEST_RESULT:PASS"
                  ;;
              esac
            fi
            qmp_cmd "$qmp_socket" '{"execute":"quit"}' "$TMPDIR/qmp-quit-$label.json" >/dev/null 2>&1 || true
            wait "$qemu_pid" || true
            qemu_pid=""

            grep -q "CRUCIBLE_QEMU_INERT_DEVICE_IO_DONE" "$serial"
            test -s "$evidence_source" \
              || fail "$label guest did not persist execution/output evidence"
            bind_execution_evidence "$label" "$evidence_source" "$evidence"
            sha256sum "$evidence" | gawk '{ print $1 }' \
              > "$TMPDIR/execution-fingerprint-$label.sha256"
            normalize_serial "$serial" "$TMPDIR/normalized-serial-$label.txt"
          }

          start_paused_qemu() {
            label="$1"
            qemu="$2"
            qemu_img="$3"
            with_vmstate="$4"
            qmp_socket="$TMPDIR/qmp-$label.sock"
            serial="$TMPDIR/serial-$label.log"
            stderr="$TMPDIR/qemu-$label.stderr"
            rm -f "$qmp_socket" "$serial" "$stderr"

            vmstate_args=""
            if [ "$with_vmstate" = yes ]; then
              vmstate="$TMPDIR/vmstate-$label.qcow2"
              "$qemu_img" create -f qcow2 "$vmstate" 32M >/dev/null
              vmstate_args="-blockdev driver=file,filename=$vmstate,node-name=vmfile -blockdev driver=qcow2,file=vmfile,node-name=vmstate"
            fi

            # shellcheck disable=SC2086
            timeout 600 "$qemu" \
              -nodefaults \
              -no-user-config \
              -display none \
              -monitor none \
              -machine q35 \
              -accel tcg,thread=single \
              -cpu qemu64,-rdrand,-rdseed \
              -m 256 \
              -smp 1 \
              -rtc base=2026-01-01T00:00:00,clock=vm \
              -seed 0x0010c001 \
              -chardev file,id=serial0,path="$serial" \
              -serial chardev:serial0 \
              -qmp "unix:$qmp_socket,server=on,wait=off" \
              $vmstate_args \
              -S \
              -no-shutdown \
              -no-reboot \
              2> "$stderr" &
            qemu_pid="$!"

            wait_for_socket "$qmp_socket" || {
              cat "$stderr" >&2 || true
              fail "$label QMP socket did not appear"
            }
          }

          probe_qmp_surface() {
            label="$1"
            qemu="$2"
            qemu_img="$3"
            start_paused_qemu "$label" "$qemu" "$qemu_img" no
            socket="$TMPDIR/qmp-$label.sock"

            qmp_cmd "$socket" '{"execute":"query-commands"}' "$TMPDIR/qmp-commands-$label.json" \
              || fail "$label query-commands failed"
            jq -r -s '[.[] | select(has("return"))][-1].return[].name' "$TMPDIR/qmp-commands-$label.json" \
              | sort > "$TMPDIR/qmp-command-names-$label.txt"
            for command in query-status query-machines query-block query-migrate query-migrate-capabilities migrate snapshot-save snapshot-load; do
              grep -F -x -q "$command" "$TMPDIR/qmp-command-names-$label.txt" \
                || fail "$label missing QMP command $command"
            done

            if [ "$label" = patched ]; then
              grep -F -x -q 'crucible-complete-terminal-lifecycle' \
                "$TMPDIR/qmp-command-names-$label.txt" \
                || fail "patched QEMU omitted the terminal lifecycle control command"
              terminal_digest=$(printf '0%.0s' $(seq 1 64))
              terminal_request=$(printf \
                '{"execute":"crucible-complete-terminal-lifecycle","arguments":{"action-sha256":"%s","evidence-sha256":"%s","process-generation":1}}' \
                "$terminal_digest" "$terminal_digest")
              qmp_cmd "$socket" '{"execute":"query-status"}' \
                "$TMPDIR/qmp-terminal-lifecycle-sim-off-status-before.json" \
                || fail "patched query-status before terminal lifecycle probe failed"
              jq -e -s '
                [.[] | select(has("return"))][-1].return.status
                  | IN("prelaunch", "paused")
              ' "$TMPDIR/qmp-terminal-lifecycle-sim-off-status-before.json" >/dev/null \
                || fail "terminal lifecycle sim-off probe did not begin from a stopped VM"
              jq -S -s '[.[] | select(has("return"))][-1].return.status' \
                "$TMPDIR/qmp-terminal-lifecycle-sim-off-status-before.json" \
                > "$TMPDIR/qmp-terminal-lifecycle-sim-off-status-before.normalized.json"
              qmp_cmd_expect_error "$socket" "$terminal_request" \
                "$TMPDIR/qmp-terminal-lifecycle-sim-off.json" \
                || fail "patched terminal lifecycle sim-off probe failed"
              jq -e -s '
                [.[] | select(has("error"))][-1].error.desc
                  | startswith("Crucible terminal lifecycle completion rejected")
              ' \
                "$TMPDIR/qmp-terminal-lifecycle-sim-off.json" >/dev/null \
                || fail "terminal lifecycle control command returned an unexpected sim-off error"
              qmp_cmd "$socket" '{"execute":"query-status"}' \
                "$TMPDIR/qmp-terminal-lifecycle-sim-off-status-after.json" \
                || fail "patched query-status after terminal lifecycle probe failed"
              jq -S -s '[.[] | select(has("return"))][-1].return.status' \
                "$TMPDIR/qmp-terminal-lifecycle-sim-off-status-after.json" \
                > "$TMPDIR/qmp-terminal-lifecycle-sim-off-status-after.normalized.json"
              cmp -s \
                "$TMPDIR/qmp-terminal-lifecycle-sim-off-status-before.normalized.json" \
                "$TMPDIR/qmp-terminal-lifecycle-sim-off-status-after.normalized.json" \
                || fail "terminal lifecycle sim-off probe changed VM run state"
            else
              if grep -F -x -q 'crucible-complete-terminal-lifecycle' \
                  "$TMPDIR/qmp-command-names-$label.txt"; then
                fail "reference QEMU exposed the Crucible terminal lifecycle command"
              fi
            fi

            qmp_cmd "$socket" '{"execute":"query-machines"}' "$TMPDIR/qmp-machines-$label.json" \
              || fail "$label query-machines failed"
            jq -S -s '[.[] | select(has("return"))][-1].return | map({name, alias, is_default}) | sort_by(.name)' \
              "$TMPDIR/qmp-machines-$label.json" > "$TMPDIR/qmp-machines-$label.normalized.json"

            qmp_cmd "$socket" '{"execute":"query-migrate-capabilities"}' "$TMPDIR/qmp-migrate-capabilities-$label.json" \
              || fail "$label query-migrate-capabilities failed"
            jq -S -s '[.[] | select(has("return"))][-1].return | sort_by(.capability)' \
              "$TMPDIR/qmp-migrate-capabilities-$label.json" > "$TMPDIR/qmp-migrate-capabilities-$label.normalized.json"

            qmp_cmd "$socket" '{"execute":"query-block"}' "$TMPDIR/qmp-block-$label.json" \
              || fail "$label query-block failed"
            jq -S -s '[.[] | select(has("return"))][-1].return | length' \
              "$TMPDIR/qmp-block-$label.json" > "$TMPDIR/qmp-block-$label.normalized.json"

            grep -F -x -v 'crucible-complete-terminal-lifecycle' \
              "$TMPDIR/qmp-command-names-$label.txt" \
              > "$TMPDIR/qmp-upstream-command-names-$label.txt"
            cat "$TMPDIR/qmp-upstream-command-names-$label.txt" > "$TMPDIR/qmp-surface-$label.normalized.txt"
            cat "$TMPDIR/qmp-machines-$label.normalized.json" >> "$TMPDIR/qmp-surface-$label.normalized.txt"
            cat "$TMPDIR/qmp-migrate-capabilities-$label.normalized.json" >> "$TMPDIR/qmp-surface-$label.normalized.txt"
            cat "$TMPDIR/qmp-block-$label.normalized.json" >> "$TMPDIR/qmp-surface-$label.normalized.txt"

            qmp_cmd "$socket" '{"execute":"quit"}' "$TMPDIR/qmp-quit-$label.json" >/dev/null 2>&1 || true
            wait "$qemu_pid" || true
            qemu_pid=""
          }

          probe_migration_stream() {
            label="$1"
            qemu="$2"
            qemu_img="$3"
            start_paused_qemu "$label" "$qemu" "$qemu_img" no
            socket="$TMPDIR/qmp-$label.sock"
            state="$TMPDIR/migration-$label.bin"
            uri=$(json_string "file:$state")
            request=$(printf '{"execute":"migrate","arguments":{"uri":%s}}' "$uri")

            qmp_cmd "$socket" "$request" "$TMPDIR/qmp-migrate-$label.json" \
              || fail "$label migrate command failed"
            wait_for_migration "$label" "$socket" || fail "$label migration did not complete"
            [ -s "$state" ] || fail "$label migration stream is empty"
            sha256sum "$state" | gawk '{print $1}' > "$TMPDIR/migration-$label.sha256"

            qmp_cmd "$socket" '{"execute":"quit"}' "$TMPDIR/qmp-quit-migrate-$label.json" >/dev/null 2>&1 || true
            wait "$qemu_pid" || true
            qemu_pid=""
          }

          probe_snapshot_surface() {
            label="$1"
            qemu="$2"
            qemu_img="$3"
            start_paused_qemu "$label" "$qemu" "$qemu_img" yes
            socket="$TMPDIR/qmp-$label.sock"
            tag_json=$(json_string "qemu-inert-$label")
            save_job_json=$(json_string "save-$label")
            load_job_json=$(json_string "load-$label")
            save_request=$(printf '{"execute":"snapshot-save","arguments":{"job-id":%s,"tag":%s,"vmstate":"vmstate","devices":["vmstate"]}}' "$save_job_json" "$tag_json")
            load_request=$(printf '{"execute":"snapshot-load","arguments":{"job-id":%s,"tag":%s,"vmstate":"vmstate","devices":["vmstate"]}}' "$load_job_json" "$tag_json")

            qmp_cmd "$socket" "$save_request" "$TMPDIR/qmp-snapshot-save-$label.json" \
              || fail "$label snapshot-save failed"
            wait_for_job "$label" "$socket" "save-$label" || fail "$label snapshot-save job did not conclude"
            qmp_cmd "$socket" "$load_request" "$TMPDIR/qmp-snapshot-load-$label.json" \
              || fail "$label snapshot-load failed"
            wait_for_job "$label" "$socket" "load-$label" || fail "$label snapshot-load job did not conclude"

            {
              echo snapshot-save=concluded
              echo snapshot-load=concluded
            } > "$TMPDIR/snapshot-surface-$label.normalized.txt"

            qmp_cmd "$socket" '{"execute":"quit"}' "$TMPDIR/qmp-quit-snapshot-$label.json" >/dev/null 2>&1 || true
            wait "$qemu_pid" || true
            qemu_pid=""
          }

          # Both sim-off comparison profiles use upstream QEMU's instruction
          # clock. A host-realtime TCG clock makes Linux's early PIT/IO-APIC
          # calibration depend on builder CPU starvation, producing spurious
          # guest-visible warnings or panics even when the binaries are
          # identical. This is a platform launch constraint, not a guest
          # workaround: the stock kernel and initramfs remain unchanged.
          run_boot_case reference-tcg "$REFERENCE_QEMU" deterministic
          run_boot_case patched-tcg "$PATCHED_QEMU" deterministic
          compare_files boot-tcg-raw "$TMPDIR/authoritative-serial-reference-tcg.log" "$TMPDIR/authoritative-serial-patched-tcg.log"
          compare_files boot-tcg "$TMPDIR/normalized-serial-reference-tcg.txt" "$TMPDIR/normalized-serial-patched-tcg.txt"
          compare_files execution-output-tcg "$TMPDIR/execution-fingerprint-reference-tcg.txt" "$TMPDIR/execution-fingerprint-patched-tcg.txt"
          compare_files execution-output-tcg-digest "$TMPDIR/execution-fingerprint-reference-tcg.sha256" "$TMPDIR/execution-fingerprint-patched-tcg.sha256"

          run_boot_case reference-icount "$REFERENCE_QEMU" plain
          run_boot_case patched-icount "$PATCHED_QEMU" plain
          compare_files boot-plain-icount-raw "$TMPDIR/authoritative-serial-reference-icount.log" "$TMPDIR/authoritative-serial-patched-icount.log"
          compare_files boot-plain-icount "$TMPDIR/normalized-serial-reference-icount.txt" "$TMPDIR/normalized-serial-patched-icount.txt"
          compare_files execution-output-plain-icount "$TMPDIR/execution-fingerprint-reference-icount.txt" "$TMPDIR/execution-fingerprint-patched-icount.txt"
          compare_files execution-output-plain-icount-digest "$TMPDIR/execution-fingerprint-reference-icount.sha256" "$TMPDIR/execution-fingerprint-patched-icount.sha256"
          exercise_rng_leakage_negative_control "$TMPDIR/execution-fingerprint-reference-icount.txt"

          probe_qmp_surface reference "$REFERENCE_QEMU" "$REFERENCE_QEMU_IMG"
          probe_qmp_surface patched "$PATCHED_QEMU" "$PATCHED_QEMU_IMG"
          comm -23 "$TMPDIR/qmp-command-names-reference.txt" \
            "$TMPDIR/qmp-command-names-patched.txt" \
            > "$TMPDIR/qmp-reference-only-commands.txt"
          comm -13 "$TMPDIR/qmp-command-names-reference.txt" \
            "$TMPDIR/qmp-command-names-patched.txt" \
            > "$TMPDIR/qmp-patched-only-commands.txt"
          test ! -s "$TMPDIR/qmp-reference-only-commands.txt" \
            || fail "patched QEMU omitted reference QMP commands"
          test "$(wc -l < "$TMPDIR/qmp-patched-only-commands.txt" | tr -d ' ')" -eq 1 \
            || fail "patched QEMU exposed an unexpected QMP command-set delta"
          grep -F -x -q 'crucible-complete-terminal-lifecycle' \
            "$TMPDIR/qmp-patched-only-commands.txt" \
            || fail "patched QMP command-set delta was not the terminal lifecycle command"
          compare_files qmp-surface "$TMPDIR/qmp-surface-reference.normalized.txt" "$TMPDIR/qmp-surface-patched.normalized.txt"

          probe_migration_stream reference "$REFERENCE_QEMU" "$REFERENCE_QEMU_IMG"
          probe_migration_stream patched "$PATCHED_QEMU" "$PATCHED_QEMU_IMG"
          compare_files migration-stream "$TMPDIR/migration-reference.sha256" "$TMPDIR/migration-patched.sha256"

          probe_snapshot_surface reference "$REFERENCE_QEMU" "$REFERENCE_QEMU_IMG"
          probe_snapshot_surface patched "$PATCHED_QEMU" "$PATCHED_QEMU_IMG"
          compare_files snapshot-surface "$TMPDIR/snapshot-surface-reference.normalized.txt" "$TMPDIR/snapshot-surface-patched.normalized.txt"

          mkdir -p "$out/corpus"
          cp "$PATCH_MICROTESTS_RESULT" "$out/patch-microtests.result"
          cp "$RNG_DELIVERY_INERT_RESULT" "$out/rng-delivery-inert.result"
          cp "$TMPDIR/serial-reference-tcg.log" "$out/corpus/boot-tcg-reference.raw"
          cp "$TMPDIR/serial-patched-tcg.log" "$out/corpus/boot-tcg-patched.raw"
          cp "$TMPDIR/normalized-serial-reference-tcg.txt" "$out/corpus/boot-tcg-reference.txt"
          cp "$TMPDIR/normalized-serial-patched-tcg.txt" "$out/corpus/boot-tcg-patched.txt"
          cp "$TMPDIR/serial-reference-icount.log" "$out/corpus/boot-icount-reference.raw"
          cp "$TMPDIR/serial-patched-icount.log" "$out/corpus/boot-icount-patched.raw"
          cp "$TMPDIR/normalized-serial-reference-icount.txt" "$out/corpus/boot-icount-reference.txt"
          cp "$TMPDIR/normalized-serial-patched-icount.txt" "$out/corpus/boot-icount-patched.txt"
          cp "$TMPDIR/execution-fingerprint-reference-tcg.txt" "$out/corpus/execution-output-tcg-reference.txt"
          cp "$TMPDIR/execution-fingerprint-patched-tcg.txt" "$out/corpus/execution-output-tcg-patched.txt"
          cp "$TMPDIR/execution-fingerprint-reference-tcg.sha256" "$out/corpus/execution-output-tcg-reference.sha256"
          cp "$TMPDIR/execution-fingerprint-patched-tcg.sha256" "$out/corpus/execution-output-tcg-patched.sha256"
          cp "$TMPDIR/execution-fingerprint-reference-icount.txt" "$out/corpus/execution-output-icount-reference.txt"
          cp "$TMPDIR/execution-fingerprint-patched-icount.txt" "$out/corpus/execution-output-icount-patched.txt"
          cp "$TMPDIR/execution-fingerprint-reference-icount.sha256" "$out/corpus/execution-output-icount-reference.sha256"
          cp "$TMPDIR/execution-fingerprint-patched-icount.sha256" "$out/corpus/execution-output-icount-patched.sha256"
          cp "$TMPDIR/rng-leakage-negative-control.diff" "$out/corpus/rng-leakage-negative-control.diff"
          cp "$TMPDIR/qmp-surface-reference.normalized.txt" "$out/corpus/qmp-surface-reference.txt"
          cp "$TMPDIR/qmp-surface-patched.normalized.txt" "$out/corpus/qmp-surface-patched.txt"
          cp "$TMPDIR/migration-reference.sha256" "$out/corpus/migration-reference.sha256"
          cp "$TMPDIR/migration-patched.sha256" "$out/corpus/migration-patched.sha256"
          cp "$TMPDIR/snapshot-surface-reference.normalized.txt" "$out/corpus/snapshot-surface-reference.txt"
          cp "$TMPDIR/snapshot-surface-patched.normalized.txt" "$out/corpus/snapshot-surface-patched.txt"

          cat > "$out/result" <<'RESULT'
          PASS
          check=${attrPath}
          tasks=${builtins.concatStringsSep "," taskIds}
          open_tasks=${builtins.concatStringsSep "," openTaskIds}
          status=complete
          evidence_scope=full-stack-sim-off-upstream-equivalent-corpus-plus-per-patch-attribution
          gate=gate:qemu-inert
          reference_qemu=${referenceQemu}
          patched_qemu=${patchedQemu}
          qemu_version=${patchedQemu.version}
          plugin_loaded=false
          sim_accel_selected=false
          sim_flags_present=false
          stock_linux_kernel_unmodified=true
          tcg_virtual_clock=upstream-icount
          tcg_virtual_clock_host_load_independent=true
          patch_microtests_dependency_passed=true
          guest_visible_boot_serial_compared_raw=true
          guest_kernel_printk_timestamps_disabled_at_source=true
          serial_normalization_scope=secondary-workload-marker-evidence-only
          serial_normalization_masking_negative_control=red
          reference_vs_patched_boot_tcg_identical=true
          reference_vs_patched_boot_plain_icount_identical=true
          reference_vs_patched_device_io_identical=true
          real_virtio_rng_hwrng_request_exercised=true
          virtio_rng_fixed_zero_backend=true
          raw_serial_authority=through-test-result-pass
          reference_vs_patched_rng_output_tcg_identical=true
          reference_vs_patched_rng_output_plain_icount_identical=true
          reference_vs_patched_rng_read_call_count_tcg_identical=true
          reference_vs_patched_rng_read_call_count_plain_icount_identical=true
          durable_execution_output_evidence=9p-file
          execution_output_evidence_fields=block-hash,9p-hash,rng-bytes,rng-byte-count,rng-read-call-count,guest-output-fingerprint,sha256-composite-binding
          execution_output_composite_binding_validated=true
          reference_vs_patched_execution_output_fingerprint_tcg_identical=true
          reference_vs_patched_execution_output_fingerprint_plain_icount_identical=true
          rng_leakage_negative_control=mutated-rng-read-call-count
          rng_leakage_negative_control_composite_rebound=true
          rng_leakage_negative_control_discriminated=true
          rng_completion_icount_equivalence_proven=true
          rng_completion_icount_equivalence_method=structural-sim-off-inertness
          rng_completion_delivery_only_added_code_is_sim_guarded=true
          rng_completion_delivery_path_sim_off_identical_to_reference=true
          rng_completion_timing_residual=closed-by-structural-sim-off-inertness
          qmp_upstream_command_set_identical=true
          qmp_introspection_surface_identical_after_control_extension=true
          qmp_crucible_control_extension=crucible-complete-terminal-lifecycle
          qmp_crucible_control_extension_sim_off_rejected_without_run_state_change=true
          migration_stream_identical=true
          snapshot_restore_surface_identical=true
          upstream_equivalent_corpus=boot,device-io,virtio-rng-execution-output,qmp,migration,snapshot
          RESULT
        '';
      }
    ];
  }
