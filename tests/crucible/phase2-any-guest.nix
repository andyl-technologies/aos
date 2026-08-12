{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.anyGuest",
  taskIds ? ["T-DET-22" "T-HARN-16"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  anyGuestTest = builtins.readFile ../../crates/crucible-qemu/tests/gate_any_guest.rs;
  gateCatalog = builtins.readFile ../../crates/crucible-harness/src/lib.rs;
  gateTargets = builtins.readFile ../../crates/crucible-harness/src/gate_targets.rs;
  gateTargetMapping = builtins.readFile ./phase1-gate-target-mapping.nix;
  defaultChecks = builtins.readFile ./default.nix;
  determinismContract = builtins.readFile ../../docs/rfcs/0010-crucible/04-determinism-contract.md;
  harnessTesting = builtins.readFile ../../docs/rfcs/0010-crucible/24-determinism-harness-testing.md;
  guestNonModification = builtins.readFile ./phase1-guest-non-modification.nix;
  whiteboxGate = import ./phase2-plugin-whitebox-doorbell.nix {inherit pkgs lib;};

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/04-determinism-contract.md" determinismContract [
      {
        label = "any-guest completion gate";
        needle = "checks.crucible.phase2.gates.anyGuest";
      }
      {
        label = "white-box non-perturbing scope";
        needle = "enabled but unused";
      }
      {
        label = "white-box live-QEMU non-claim";
        needle = "not live any-guest boot fingerprint evidence";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" harnessTesting [
      {
        label = "any-guest real-QEMU evidence";
        needle = "diskless cadence fingerprint streams match exactly";
      }
      {
        label = "any-guest initial fixture matrix scope";
        needle = "Broader off-the-shelf guest image coverage remains outside";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/lib.rs" gateCatalog [
      {
        label = "gate:any-guest implemented catalog status";
        needle = ''          name: "gate:any-guest",
                  phase: GatePhase::Phase2,
                  owner: "crucible-qemu",
                  status: GateStatus::Implemented,'';
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/gate_targets.rs" gateTargets [
      {
        label = "gate:any-guest non-placeholder target";
        needle = ''          gate: "gate:any-guest",
                  package: "crucible-qemu",
                  test_target: "gate_any_guest",
                  required_features: &[],
                  placeholder: false,'';
      }
    ]
    ++ failuresFor "tests/crucible/phase1-gate-target-mapping.nix" gateTargetMapping [
      {
        label = "gate:any-guest mapping non-placeholder";
        needle = ''          gate = "gate:any-guest";
                package = "crucible-qemu";
                testTarget = "gate_any_guest";
                requiredFeatures = [];
                placeholder = false;'';
      }
    ]
    ++ failuresFor "crates/crucible-qemu/tests/gate_any_guest.rs" anyGuestTest [
      {
        label = "host-side launch contract test";
        needle = "gate_any_guest_launch_profile_requires_host_side_guest_operation";
      }
      {
        label = "white-box host-plugin configuration test";
        needle = "gate_any_guest_whitebox_switch_is_host_plugin_configuration_without_agent_content";
      }
      {
        label = "whitebox-on plugin arg assertion";
        needle = "whitebox=on";
      }
      {
        label = "no in-guest content negative assertion";
        needle = "GuestInjectedContent";
      }
      {
        label = "fingerprint gate driver";
        needle = "run_single_vm_fingerprint_gate";
      }
    ]
    ++ forbiddenFor "crates/crucible-qemu/tests/gate_any_guest.rs" anyGuestTest [
      {
        label = "ignored any-guest test";
        needle = "#[ignore";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes anyGuest task check";
        needle = "anyGuest = import ./phase2-any-guest.nix";
      }
      {
        label = "phase2 any-guest gate is not red placeholder";
        needle = "attrPath = \"checks.crucible.phase2.gates.anyGuest\"";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-guest-non-modification.nix" guestNonModification [
      {
        label = "guest non-modification references real any-guest gate";
        needle = "real_qemu_any_guest_gate=checks.crucible.phase2.gates.anyGuest";
      }
    ];

  stockWorkload = pkgs.mkDerivation {
    pname = "crucible-phase2-any-guest-stock-workload";
    version = "0";
    src = null;

    phases = [
      {
        name = "build-stock-workload";
        script = ''
          mkdir -p "$out/bin"

          cat > stock-spin.c <<'STOCK_SPIN_C'
          #include <stdint.h>

          enum {
            ITERS = 1000
          };

          static volatile uint64_t sink;

          int main(void) {
            uint64_t state = 0x0010a0657a7e0001ULL;

            for (uint64_t i = 0; i < ITERS; i++) {
              state ^= i + 0x9e3779b97f4a7c15ULL;
              state = (state << 9) | (state >> 55);
              state *= 0xbf58476d1ce4e5b9ULL;
            }

            sink = state;
            return sink == 0 ? 1 : 0;
          }
          STOCK_SPIN_C

          cc -std=c11 -O2 stock-spin.c -o "$out/bin/stock-spin"

          cat > stock-disk-touch.c <<'STOCK_DISK_TOUCH_C'
          #include <fcntl.h>
          #include <stdint.h>
          #include <stdio.h>
          #include <string.h>
          #include <unistd.h>

          int main(int argc, char **argv) {
            const char *expected = "aos-any-guest-base-image-v1\n";
            const char *marker = "aos-any-guest-overlay-write-v1\n";
            char prefix[32] = {0};
            int fd;

            if (argc != 2) {
              fprintf(stderr, "usage: stock-disk-touch BLOCK_DEVICE\n");
              return 1;
            }

            fd = open(argv[1], O_RDWR);
            if (fd < 0) {
              perror(argv[1]);
              return 1;
            }

            if (pread(fd, prefix, strlen(expected), 0) != (ssize_t)strlen(expected)) {
              perror("pread");
              close(fd);
              return 1;
            }
            if (memcmp(prefix, expected, strlen(expected)) != 0) {
              fprintf(stderr, "unexpected block-device prefix\n");
              close(fd);
              return 1;
            }
            if (pwrite(fd, marker, strlen(marker), 4096) != (ssize_t)strlen(marker)) {
              perror("pwrite");
              close(fd);
              return 1;
            }
            if (fsync(fd) != 0) {
              perror("fsync");
              close(fd);
              return 1;
            }

            close(fd);
            return 0;
          }
          STOCK_DISK_TOUCH_C

          cc -std=gnu11 -O2 stock-disk-touch.c -o "$out/bin/stock-disk-touch"

        '';
      }
    ];
  };

  baseImage = pkgs.mkDerivation {
    pname = "crucible-phase2-any-guest-base-image";
    version = "0";
    src = null;

    buildDeps = [
      pkgs.coreutils
    ];

    phases = [
      {
        name = "build-base-image";
        script = ''
          mkdir -p "$out"
          dd if=/dev/zero of="$out/base.img" bs=1M count=4 status=none
          printf 'aos-any-guest-base-image-v1\n' \
            | dd of="$out/base.img" bs=1 seek=0 conv=notrunc status=none
        '';
      }
    ];
  };

  initramfs = let
    initramfsDeps = [
      pkgs.bash
      pkgs.coreutils
      pkgs.util-linux
      stockWorkload
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
      pname = "crucible-phase2-any-guest-initramfs";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.findutils
        pkgs.grep
        pkgs.cpio
        pkgs.pigz
      ];

      exportReferencesGraph = graphPairs;

      phases = [
        {
          name = "build-initramfs";
          script = ''
            set -eu

            grep -h '^/nix/store/' closure-* | sort -u > closure-paths

            mkdir -p root/bin root/sbin root/nix/store root/tmp root/proc root/sys root/dev root/run
            while IFS= read -r p; do
              cp -a "$p" root"$p"
            done < closure-paths

            ln -sfn ${pkgs.bash}/bin/bash root/bin/sh
            ln -sfn ${pkgs.bash}/bin/bash root/bin/bash

            cat > root/init <<'INIT'
            #!${pkgs.bash}/bin/bash
            export PATH="/bin:/sbin:${depPaths}"
            export HOME=/tmp

            mount -t proc proc /proc
            mount -t sysfs sysfs /sys
            mount -t devtmpfs devtmpfs /dev
            mount -t tmpfs tmpfs /tmp
            mount -t tmpfs tmpfs /run

            echo 'AOS_ANY_GUEST_READY'
            stock-spin

            case "$(cat /proc/cmdline)" in
              *aos.any_guest.disk=cow*)
                i=0
                while [ "$i" -lt 100 ] && [ ! -b /dev/vda ]; do
                  sleep 0.05
                  i=$((i + 1))
                done
                if [ ! -b /dev/vda ]; then
                  echo 'AOS_ANY_GUEST_FAIL'
                  while :; do
                    :
                  done
                fi

                if ! stock-disk-touch /dev/vda; then
                  echo 'AOS_ANY_GUEST_FAIL'
                  while :; do
                    :
                  done
                fi
                echo 'AOS_ANY_GUEST_BLOCK_WRITTEN'
                ;;
            esac

            echo 'AOS_ANY_GUEST_DONE'
            while :; do
              :
            done
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
  if failures != []
  then throw "crucible phase2 any-guest gate failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-any-guest";
      version = "0";
      src = crucibleSrc;

      buildDeps =
        [
          pkgs.coreutils
          pkgs.diffutils
          pkgs.gawk
          pkgs.grep
          pkgs.jq
          pkgs.qemu-crucible
          pkgs.crucible-qemu-trace-plugin
          pkgs.rust
          pkgs.sed
          pkgs.socat
        ]
        ++ dependencies;

      INITRAMFS = "${initramfs}/initrd.img";
      KERNEL = builtins.toString pkgs.linux;
      BASE_IMAGE = "${baseImage}/base.img";
      PLUGIN = "${pkgs.crucible-qemu-trace-plugin}/lib/qemu/plugins/crucible-qemu-trace-plugin.so";
      QEMU = "${pkgs.qemu-crucible}/bin/qemu-system-x86_64";
      QEMU_IMG = "${pkgs.qemu-crucible}/bin/qemu-img";
      CADENCE = "100000000";

      phases = [
        {
          name = "unpack";
          script = ''
            cp -R "$src" source
            chmod -R u+w source
            cd source
          '';
        }
        {
          name = "configure";
          script = ''
            export CARGO_HOME="$TMPDIR/cargo"
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            mkdir -p "$CARGO_HOME" .cargo
            if [ -f "${cargoDeps}/.cargo/config.toml" ]; then
              sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
            else
              printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoDeps}"\n\n' \
                > .cargo/config.toml
            fi
          '';
        }
        {
          name = "run-any-guest";
          script = ''
            set -eu

            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-any-guest-target" \
              --manifest-path Cargo.toml \
              -p crucible-qemu \
              --test gate_any_guest \
              -- --test-threads=1

            cd "$TMPDIR"
            unset LD_LIBRARY_PATH || true

            fail() {
              echo "FAIL: $*" >&2
              exit 1
            }

            qemu_pid=""
            cleanup_qemu() {
              if [ -n "$qemu_pid" ]; then
                kill "$qemu_pid" 2>/dev/null || true
                wait "$qemu_pid" 2>/dev/null || true
                qemu_pid=""
              fi
            }

            trap cleanup_qemu EXIT

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

            wait_for_guest_ready() {
              serial="$1"
              waited=0
              while [ "$waited" -lt 1200 ]; do
                if [ -f "$serial" ] && grep -q 'AOS_ANY_GUEST_READY' "$serial"; then
                  return 0
                fi
                if [ -f "$serial" ] && grep -q 'AOS_ANY_GUEST_FAIL' "$serial"; then
                  cat "$serial" >&2
                  return 1
                fi
                sleep 0.25
                waited=$((waited + 1))
              done
              [ ! -f "$serial" ] || cat "$serial" >&2
              return 1
            }

            wait_for_guest_done() {
              serial="$1"
              waited=0
              while [ "$waited" -lt 1200 ]; do
                if [ -f "$serial" ] && grep -q 'AOS_ANY_GUEST_DONE' "$serial"; then
                  return 0
                fi
                if [ -f "$serial" ] && grep -q 'AOS_ANY_GUEST_FAIL' "$serial"; then
                  cat "$serial" >&2
                  return 1
                fi
                sleep 0.25
                waited=$((waited + 1))
              done
              [ ! -f "$serial" ] || cat "$serial" >&2
              return 1
            }

            qmp_quit() {
              socket="$1"
              {
                printf '%s\n' '{"execute":"qmp_capabilities"}'
                printf '%s\n' '{"execute":"quit"}'
              } | socat -T 2 - "UNIX-CONNECT:$socket" >/dev/null 2>"$TMPDIR/qmp-quit.err" || true
            }

            wait_for_qemu_exit() {
              label="$1"
              waited=0
              while [ "$waited" -lt 100 ]; do
                if ! kill -0 "$qemu_pid" 2>/dev/null; then
                  wait "$qemu_pid" || fail "$label QEMU exited unsuccessfully"
                  qemu_pid=""
                  return 0
                fi
                sleep 0.1
                waited=$((waited + 1))
              done

              kill "$qemu_pid" 2>/dev/null || true
              wait "$qemu_pid" 2>/dev/null || true
              qemu_pid=""
              fail "$label QEMU did not exit after QMP quit"
            }

            vmlinuz=$(ls "$KERNEL"/boot/vmlinuz-* | head -1)
            if [ -z "$vmlinuz" ]; then
              fail "no vmlinuz under $KERNEL/boot"
            fi

            seed="$TMPDIR/seed.bin"
            printf 'aos-phase2-any-guest-seed-v1\n' > "$seed"

            mkdir -p "$out"
            : > "$TMPDIR/case-results.txt"

            run_guest() {
              case_name="$1"
              run_name="$2"
              disk_mode="$3"
              label="$case_name-$run_name"
              qmp_socket="$TMPDIR/qmp-$case_name.sock"
              serial="$TMPDIR/serial-$case_name.log"
              trace="$TMPDIR/trace-$case_name.jsonl"
              rm -f "$qmp_socket" "$serial" "$trace"

              # Stock guest cmdline (D-31): no entropy-suppression flags. Determinism
              # is sealed host-side (fixed -cpu without RDRAND/RDSEED, seeded fw_cfg
              # entropy, -icount), so KASLR/ASLR stay enabled and remain reproducible.
              append="console=ttyS0 reboot=k panic=1 rdinit=/init quiet net.ifnames=0"

              set -- "$QEMU" \
                -nodefaults \
                -no-user-config \
                -display none \
                -monitor none \
                -machine q35 \
                -accel sim,thread=single \
                -icount shift=0,sleep=off,align=off \
                -cpu qemu64,-rdrand,-rdseed \
                -m 256 \
                -smp 1 \
                -rtc base=2026-01-01T00:00:00,clock=vm \
                -seed 0x0010a065 \
                -fw_cfg name=opt/aos/seed,file="$seed" \
                -kernel "$vmlinuz" \
                -initrd "$INITRAMFS" \
                -append "$append" \
                -chardev file,id=serial0,path="$serial" \
                -serial chardev:serial0 \
                -qmp "unix:$qmp_socket,server=on,wait=off" \
                -plugin "$PLUGIN",out="$trace",cadence="$CADENCE",extended=on,mem_events=off,vcpus=1 \
                -no-reboot

              case "$disk_mode" in
                diskless)
                  ;;
                cow)
                  cow_append="$append aos.any_guest.disk=cow"
                  base="$TMPDIR/base-$case_name.img"
                  overlay="$TMPDIR/overlay-$case_name.qcow2"
                  if [ ! -f "$base" ]; then
                    cp "$BASE_IMAGE" "$base"
                    chmod u+w "$base"
                    sha256sum "$base" | gawk '{print $1}' > "$TMPDIR/base-$case_name.before"
                  fi
                  rm -f "$overlay"
                  "$QEMU_IMG" create -f qcow2 -F raw -b "$base" "$overlay" >/dev/null
                  set -- "$QEMU" \
                    -nodefaults \
                    -no-user-config \
                    -display none \
                    -monitor none \
                    -machine q35 \
                    -accel sim,thread=single \
                    -icount shift=0,sleep=off,align=off \
                    -cpu qemu64,-rdrand,-rdseed \
                    -m 256 \
                    -smp 1 \
                    -rtc base=2026-01-01T00:00:00,clock=vm \
                    -seed 0x0010a065 \
                    -fw_cfg name=opt/aos/seed,file="$seed" \
                    -kernel "$vmlinuz" \
                    -initrd "$INITRAMFS" \
                    -append "$cow_append" \
                    -drive id=guestdisk,file="$overlay",format=qcow2,if=none,cache=unsafe \
                    -device virtio-blk-pci,drive=guestdisk,id=guestdisk0 \
                    -chardev file,id=serial0,path="$serial" \
                    -serial chardev:serial0 \
                    -qmp "unix:$qmp_socket,server=on,wait=off" \
                    -plugin "$PLUGIN",out="$trace",cadence="$CADENCE",extended=on,mem_events=off,vcpus=1 \
                    -no-reboot
                  ;;
                *)
                  fail "unknown disk mode: $disk_mode"
                  ;;
              esac

              printf '%s\n' "$@" > "$TMPDIR/qemu-args-$label.txt"
              if grep -q 'crucible-guest' "$TMPDIR/qemu-args-$label.txt"; then
                fail "$label launch unexpectedly references crucible-guest"
              fi

              timeout 900 "$@" &
              qemu_pid="$!"

              wait_for_socket "$qmp_socket" || fail "$label QMP socket did not appear"
              wait_for_guest_ready "$serial" || fail "$label did not boot to ready marker"
              wait_for_guest_done "$serial" || fail "$label did not reach deterministic shutdown marker"
              qmp_quit "$qmp_socket"
              wait_for_qemu_exit "$label"

              jq -e -s '
                length >= 1
                and all(.[]; (
                  .tracked_vcpus == 1
                  and .stop_at == 0
                  and .sample_register_failures == 0
                  and .register_read_failures == 0
                  and .ram_bytes > 0
                  and .memory_events_enabled == false
                  and .device_event_capture == false
                  and .device_event_hash == null
                  and (.register_digests | type == "array")
                  and (.register_digests | length) == 1
                  and (.register_counts | type == "array")
                  and (.register_counts | length) == 1
                  and .register_counts[0] > 0
                ))
                and any(.[]; .final != true)
                and any(.[]; .final == true)
              ' "$trace" >/dev/null || fail "$label trace failed any-guest structural assertions"

              jq -c 'select(.final != true)' "$trace" > "$TMPDIR/trace-$label-cadence.jsonl"
              samples=$(wc -l < "$TMPDIR/trace-$label-cadence.jsonl")
              cadence_hash=$(jq -r 'select(.final != true) | .extended_hash' "$trace" | tail -1)
              printf '%s %s %s %s\n' "$case_name" "$run_name" "$samples" "$cadence_hash" >> "$TMPDIR/case-results.txt"

              cp "$serial" "$out/serial-$label.log"
              cp "$TMPDIR/trace-$label-cadence.jsonl" "$out/trace-$label-cadence.jsonl"
              jq -c . "$trace" > "$out/trace-$label.jsonl"
              cp "$TMPDIR/qemu-args-$label.txt" "$out/qemu-args-$label.txt"
            }

            compare_case() {
              case_name="$1"
              if ! diff -u "$TMPDIR/trace-$case_name-a-cadence.jsonl" "$TMPDIR/trace-$case_name-b-cadence.jsonl" > "$out/trace-$case_name.diff"; then
                cat "$out/trace-$case_name.diff" >&2
                fail "$case_name any-guest fingerprint mismatch"
              fi
            }

            run_guest diskless a diskless
            run_guest diskless b diskless
            compare_case diskless

            run_guest cow_block a cow
            run_guest cow_block b cow
            grep -q 'AOS_ANY_GUEST_BLOCK_WRITTEN' "$out/serial-cow_block-a.log"
            grep -q 'AOS_ANY_GUEST_BLOCK_WRITTEN' "$out/serial-cow_block-b.log"

            sha256sum "$TMPDIR/base-cow_block.img" | gawk '{print $1}' > "$TMPDIR/base-cow_block.after"
            if ! cmp -s "$TMPDIR/base-cow_block.before" "$TMPDIR/base-cow_block.after"; then
              fail "CoW overlay run mutated the copied base image"
            fi

            cp "$TMPDIR/base-cow_block.before" "$out/base-cow-block.before.sha256"
            cp "$TMPDIR/base-cow_block.after" "$out/base-cow-block.after.sha256"
            cp "${whiteboxGate}/result" "$out/whitebox-doorbell.result"
            grep -q '^PASS$' "$out/whitebox-doorbell.result"
            grep -q '^off_mode=disabled-plan-installs-no-trap$' "$out/whitebox-doorbell.result"
            grep -q '^black_box_remains_functional=true$' "$out/whitebox-doorbell.result"

            diskless_final=$(awk '$1 == "diskless" && $2 == "a" { print $4 }' "$TMPDIR/case-results.txt")
            cow_final=$(awk '$1 == "cow_block" && $2 == "a" { print $4 }' "$TMPDIR/case-results.txt")
            {
              echo PASS
              echo check=${attrPath}
              echo tasks=${taskList}
              echo gate=gate:any-guest
              echo rust_test=crucible-qemu::gate_any_guest
              echo real_qemu_launch_matrix=diskless,cow_block
              echo guest_fixture=aos-linux-generated-initramfs
              echo guest_fixture_count=1
              echo launch_profile_count=2
              echo runs_per_guest=2
              echo run_model=boot-cadence-run-twice-and-diff-through-host-qmp-quit-after-serial-marker
              echo black_box_fingerprint_scope=diskless-generic-guest
              echo diskless_black_box_fingerprints_match=true
              echo cow_block_fingerprints_compared=false
              echo cow_block_trace_scope=structural-plus-guest-visible-overlay-write
              echo diskless_fingerprint="$diskless_final"
              echo cow_block_reference_fingerprint="$cow_final"
              echo base_image_mutation=false
              echo cow_overlay_only=true
              echo cow_block_scope=guest-visible-virtio-blk-overlay-backed
              echo cow_overlay_guest_visible=true
              echo guest_visible_block_write_coverage=true
              echo cow_block_device=/dev/vda
              echo base_image_hash_before="$(cat "$TMPDIR/base-cow_block.before")"
              echo base_image_hash_after="$(cat "$TMPDIR/base-cow_block.after")"
              echo in_guest_crucible_agent_required=false
              echo in_guest_crucible_content_required=false
              echo guest_boot_readiness=generic-init-serial-marker-with-host-qmp-quit
              echo whitebox_contract_consumed=separate-host-plugin-doorbell-gate
              echo whitebox_real_qemu_any_guest_enabled=false
              echo whitebox_live_doorbell_events=0
              echo whitebox_contract_source=checks.crucible.phase2.qemuPluginWhiteboxDoorbell
              echo trace_plugin=host-side-black-box-fingerprint
              echo qemu_package_version=${pkgs.qemu-crucible.version}
            } > "$out/result"
          '';
        }
      ];
    }
