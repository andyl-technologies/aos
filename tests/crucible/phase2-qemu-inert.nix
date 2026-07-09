{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.gates.qemuInert",
  taskIds ? ["T-HARN-21" "T-PATCH-3"],
  patchMicrotests ? import ./phase2-patch-microtests.nix {inherit pkgs lib;},
  referenceQemu ? pkgs.qemu-crucible-reference,
  patchedQemu ? pkgs.qemu-crucible,
  dependencies ? [],
}: let
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

          static uint64_t fnv1a(const unsigned char *buf, ssize_t len) {
            uint64_t hash = 1469598103934665603ULL;
            for (ssize_t i = 0; i < len; i++) {
              hash ^= buf[i];
              hash *= 1099511628211ULL;
            }
            return hash;
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

          int main(int argc, char **argv) {
            unsigned char block[128];
            unsigned char ninep[128];
            if (argc != 3) {
              fprintf(stderr, "usage: inert-workload BLOCK_FILE NINEP_FILE\n");
              return 1;
            }
            if (read_prefix(argv[1], block, sizeof(block)) != 0 ||
                read_prefix(argv[2], ninep, sizeof(ninep)) != 0) {
              return 1;
            }
            const char *block_prefix = "CRUCIBLE_QEMU_INERT_BLOCK";
            const char *ninep_prefix = "CRUCIBLE_QEMU_INERT_9P";
            if (memcmp(block, block_prefix, strlen(block_prefix)) != 0 ||
                memcmp(ninep, ninep_prefix, strlen(ninep_prefix)) != 0) {
              fprintf(stderr, "unexpected device payload\n");
              return 1;
            }
            printf("CRUCIBLE_QEMU_INERT_BLOCK_HASH=%016llx\n",
                   (unsigned long long)fnv1a(block, sizeof(block)));
            printf("CRUCIBLE_QEMU_INERT_9P_HASH=%016llx\n",
                   (unsigned long long)fnv1a(ninep, sizeof(ninep)));
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

            for module in 9pnet 9pnet_virtio 9p; do
              modprobe "$module" || test_result=1
            done

            i=0
            while [ "$i" -lt 100 ] && [ ! -b /dev/vda ]; do
              sleep 0.05
              i=$((i + 1))
            done
            [ -b /dev/vda ] || test_result=1

            if [ "$test_result" -eq 0 ]; then
              mount -t 9p -o trans=virtio,version=9p2000.L,msize=262144 crucible_inert /mnt/virtfs || test_result=1
            fi

            if [ "$test_result" -eq 0 ]; then
              inert-workload /dev/vda /mnt/virtfs/payload.txt || test_result=1
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

    buildDeps = [
      pkgs.coreutils
      pkgs.diffutils
      pkgs.gawk
      pkgs.grep
      pkgs.jq
      pkgs.socat
      referenceQemu
      patchedQemu
    ] ++ dependencies;

    INITRAMFS = "${initramfs}/initrd.img";
    KERNEL = builtins.toString pkgs.linux;
    PATCH_MICROTESTS_RESULT = "${patchMicrotests}/result";
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
            grep -E '^(CRUCIBLE_QEMU_INERT_|TEST_RESULT:)' "$input" > "$output"
          }

          compare_files() {
            label="$1"
            left="$2"
            right="$3"
            if ! diff -u "$left" "$right" > "$TMPDIR/$label.diff"; then
              cat "$TMPDIR/$label.diff" >&2
              fail "$label diverged between unpatched reference and patched sim-off QEMU"
            fi
          }

          vmlinuz=$(ls "$KERNEL"/boot/vmlinuz-* | head -1)
          if [ -z "$vmlinuz" ]; then
            fail "no vmlinuz under $KERNEL/boot"
          fi

          grep -q '^PASS$' "$PATCH_MICROTESTS_RESULT" \
            || fail "patch-microtests dependency did not pass"

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
            rm -f "$qmp_socket" "$serial" "$stderr"

            case "$icount_mode" in
              none)
                icount_args=""
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
              -kernel "$vmlinuz" \
              -initrd "$INITRAMFS" \
              -append "console=ttyS0 reboot=k panic=1 rdinit=/init quiet net.ifnames=0" \
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
              :
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

            cat "$TMPDIR/qmp-command-names-$label.txt" > "$TMPDIR/qmp-surface-$label.normalized.txt"
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

          run_boot_case reference-tcg "$REFERENCE_QEMU" none
          run_boot_case patched-tcg "$PATCHED_QEMU" none
          compare_files boot-tcg "$TMPDIR/normalized-serial-reference-tcg.txt" "$TMPDIR/normalized-serial-patched-tcg.txt"

          run_boot_case reference-icount "$REFERENCE_QEMU" plain
          run_boot_case patched-icount "$PATCHED_QEMU" plain
          compare_files boot-plain-icount "$TMPDIR/normalized-serial-reference-icount.txt" "$TMPDIR/normalized-serial-patched-icount.txt"

          probe_qmp_surface reference "$REFERENCE_QEMU" "$REFERENCE_QEMU_IMG"
          probe_qmp_surface patched "$PATCHED_QEMU" "$PATCHED_QEMU_IMG"
          compare_files qmp-surface "$TMPDIR/qmp-surface-reference.normalized.txt" "$TMPDIR/qmp-surface-patched.normalized.txt"

          probe_migration_stream reference "$REFERENCE_QEMU" "$REFERENCE_QEMU_IMG"
          probe_migration_stream patched "$PATCHED_QEMU" "$PATCHED_QEMU_IMG"
          compare_files migration-stream "$TMPDIR/migration-reference.sha256" "$TMPDIR/migration-patched.sha256"

          probe_snapshot_surface reference "$REFERENCE_QEMU" "$REFERENCE_QEMU_IMG"
          probe_snapshot_surface patched "$PATCHED_QEMU" "$PATCHED_QEMU_IMG"
          compare_files snapshot-surface "$TMPDIR/snapshot-surface-reference.normalized.txt" "$TMPDIR/snapshot-surface-patched.normalized.txt"

          mkdir -p "$out/corpus"
          cp "$PATCH_MICROTESTS_RESULT" "$out/patch-microtests.result"
          cp "$TMPDIR/normalized-serial-reference-tcg.txt" "$out/corpus/boot-tcg-reference.txt"
          cp "$TMPDIR/normalized-serial-patched-tcg.txt" "$out/corpus/boot-tcg-patched.txt"
          cp "$TMPDIR/normalized-serial-reference-icount.txt" "$out/corpus/boot-icount-reference.txt"
          cp "$TMPDIR/normalized-serial-patched-icount.txt" "$out/corpus/boot-icount-patched.txt"
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
          gate=gate:qemu-inert
          reference_qemu=${referenceQemu}
          patched_qemu=${patchedQemu}
          qemu_version=${patchedQemu.version}
          plugin_loaded=false
          sim_accel_selected=false
          sim_flags_present=false
          patch_microtests_dependency_passed=true
          reference_vs_patched_boot_tcg_identical=true
          reference_vs_patched_boot_plain_icount_identical=true
          reference_vs_patched_device_io_identical=true
          qmp_command_set_identical=true
          qmp_introspection_surface_identical=true
          migration_stream_identical=true
          snapshot_restore_surface_identical=true
          upstream_equivalent_corpus=boot,device-io,qmp,migration,snapshot
          RESULT
        '';
      }
    ];
  }
