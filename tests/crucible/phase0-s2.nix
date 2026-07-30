{
  pkgs,
  lib,
}: let
  operationCount = 32;
  ninepWarmupCount = 8;
  idleThresholdPpm = 900000;
  workloadSource = builtins.readFile ./phase0-s2-workload.c;
  pluginSource = builtins.readFile ./phase0-s2-io-idle-plugin.c;

  workload = pkgs.mkDerivation {
    pname = "crucible-phase0-s2-workload";
    version = "0";
    src = null;

    source = workloadSource;
    passAsFile = ["source"];

    phases = [
      {
        name = "build-workload";
        script = ''
          cp "$sourcePath" phase0-s2-workload.c
          cc -std=c11 -O2 -Wall -Wextra phase0-s2-workload.c -o s2-io-workload
        '';
      }
      {
        name = "install-workload";
        script = ''
          mkdir -p "$out/bin"
          cp s2-io-workload "$out/bin/"
        '';
      }
    ];
  };

  blockImage = pkgs.mkDerivation {
    pname = "crucible-phase0-s2-block-image";
    version = "0";
    src = null;

    buildDeps = [
      pkgs.coreutils
    ];

    phases = [
      {
        name = "build-block-image";
        script = ''
          mkdir -p "$out"
          dd if=/dev/zero of="$out/block.img" bs=1M count=8 status=none
        '';
      }
    ];
  };

  poweroffHelper = pkgs.mkDerivation {
    pname = "crucible-phase0-s2-poweroff";
    version = "0";
    src = null;

    phases = [
      {
        name = "build-poweroff-helper";
        script = ''
          mkdir -p "$out/bin"

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

          cc poweroff.c -o "$out/bin/s2-poweroff"
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
      poweroffHelper
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
      pname = "crucible-phase0-s2-initramfs";
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
            ln -sfn ${poweroffHelper}/bin/s2-poweroff root/sbin/poweroff

            cat > root/init <<'INIT'
            #!${pkgs.bash}/bin/bash
            export PATH="/bin:/sbin:${depPaths}"
            export HOME=/tmp

            mount -t proc proc /proc
            mount -t sysfs sysfs /sys
            mount -t devtmpfs devtmpfs /dev
            mount -t tmpfs tmpfs /tmp
            mount -t tmpfs tmpfs /run

            echo "CRUCIBLE_S2_READY"
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
              mount -t 9p -o trans=virtio,version=9p2000.L,msize=262144 crucible_s2 /mnt/virtfs || test_result=1
            fi

            if [ "$test_result" -eq 0 ]; then
              s2-io-workload /dev/vda /mnt/virtfs || test_result=1
            fi

            if [ "$test_result" -eq 0 ]; then
              echo 'TEST_RESULT:PASS'
            else
              echo 'TEST_RESULT:FAIL'
            fi

            sync
            sleep 0.5
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

      meta = {
        description = "Crucible Phase 0 S2 initramfs for block and 9p idle characterization";
      };
    };
in
  pkgs.mkDerivation {
    pname = "crucible-phase0-s2-hlt-busy-poll";
    version = "0";
    src = null;

    plugin = pluginSource;
    passAsFile = ["plugin"];

    buildDeps = [
      pkgs.coreutils
      pkgs.gawk
      pkgs.glib
      pkgs.grep
      pkgs.pkg-config
      pkgs.qemu-crucible
    ];

    BLOCK_IMAGE = "${blockImage}/block.img";
    INITRAMFS = "${initramfs}/initrd.img";
    KERNEL = builtins.toString pkgs.linux;
    QEMU = "${pkgs.qemu-crucible}/bin/qemu-system-x86_64";
    IDLE_THRESHOLD_PPM = builtins.toString idleThresholdPpm;
    OPERATION_COUNT = builtins.toString operationCount;
    NINEP_WARMUP_COUNT = builtins.toString ninepWarmupCount;

    phases = [
      {
        name = "build-plugin";
        script = ''
          cp "$pluginPath" phase0-s2-io-idle-plugin.c
          cc -fPIC -shared -O2 -Wall -Wextra \
            $(pkg-config --cflags glib-2.0) \
            -I${pkgs.qemu-crucible}/include \
            phase0-s2-io-idle-plugin.c \
            -o phase0-s2-io-idle-plugin.so

        '';
      }
      {
        name = "run-s2";
        script = ''
          set -eu

          unset LD_LIBRARY_PATH || true

          vmlinuz=$(ls "$KERNEL"/boot/vmlinuz-* | head -1)
          plugin="$PWD/phase0-s2-io-idle-plugin.so"
          seed="$TMPDIR/seed.bin"
          serial="$TMPDIR/serial.log"
          plugin_out="$TMPDIR/plugin.txt"
          qemu_args="$TMPDIR/qemu-args.txt"
          ninep_root="$TMPDIR/9p-root"

          printf 'crucible-phase0-s2-seed-v1\n' > "$seed"
          mkdir -p "$ninep_root"
          i=0
          while [ "$i" -lt "$OPERATION_COUNT" ]; do
            dd if=/dev/zero of="$ninep_root/$(printf 'file-%02d.bin' "$i")" bs=4096 count=1 status=none
            i=$((i + 1))
          done
          i=0
          while [ "$i" -lt "$NINEP_WARMUP_COUNT" ]; do
            dd if=/dev/zero of="$ninep_root/$(printf 'warmup-%02d.bin' "$i")" bs=4096 count=1 status=none
            i=$((i + 1))
          done

          cat > "$qemu_args" <<EOF
          -nodefaults
          -no-user-config
          -display none
          -monitor none
          -machine q35
          -accel sim,thread=single
          -icount shift=0,sleep=off,align=off
          -cpu qemu64
          -m 1024
          -smp 1
          -rtc base=2026-01-01T00:00:00,clock=vm
          -seed 0x0010c001
          -fw_cfg name=opt/crucible/seed,file=$seed
          -kernel $vmlinuz
          -initrd $INITRAMFS
          -append console=ttyS0 reboot=k panic=1 rdinit=/init quiet nokaslr norandmaps random.trust_cpu=off net.ifnames=0
          -drive id=s2block,file=$BLOCK_IMAGE,format=raw,if=none,readonly=on,cache=unsafe,throttling.iops-read=20
          -device virtio-blk-pci,drive=s2block
          -fsdev local,id=fs0,path=$ninep_root,security_model=none,throttling.iops-read=20
          -device virtio-9p-pci,fsdev=fs0,mount_tag=crucible_s2
          -chardev file,id=serial0,path=$serial
          -serial chardev:serial0
          -plugin $plugin,out=$plugin_out
          -no-reboot
          EOF

          "$QEMU" \
            -nodefaults \
            -no-user-config \
            -display none \
            -monitor none \
            -machine q35 \
            -accel sim,thread=single \
            -icount shift=0,sleep=off,align=off \
            -cpu qemu64 \
            -m 1024 \
            -smp 1 \
            -rtc base=2026-01-01T00:00:00,clock=vm \
            -seed 0x0010c001 \
            -fw_cfg name=opt/crucible/seed,file="$seed" \
            -kernel "$vmlinuz" \
            -initrd "$INITRAMFS" \
            -append "console=ttyS0 reboot=k panic=1 rdinit=/init quiet nokaslr norandmaps random.trust_cpu=off net.ifnames=0" \
            -drive id=s2block,file="$BLOCK_IMAGE",format=raw,if=none,readonly=on,cache=unsafe,throttling.iops-read=20 \
            -device virtio-blk-pci,drive=s2block \
            -fsdev local,id=fs0,path="$ninep_root",security_model=none,throttling.iops-read=20 \
            -device virtio-9p-pci,fsdev=fs0,mount_tag=crucible_s2 \
            -chardev file,id=serial0,path="$serial" \
            -serial chardev:serial0 \
            -plugin "$plugin",out="$plugin_out" \
            -no-reboot &
          qemu_pid=$!

          waited=0
          while kill -0 "$qemu_pid" 2>/dev/null; do
            if grep -q "TEST_RESULT:PASS" "$serial" 2>/dev/null; then
              break
            fi
            if [ "$waited" -ge 300 ]; then
              kill "$qemu_pid" 2>/dev/null || true
              wait "$qemu_pid" || true
              echo "FAIL: timed out waiting for S2 guest result" >&2
              exit 1
            fi
            sleep 1
            waited=$((waited + 1))
          done

          if ! grep -q "TEST_RESULT:PASS" "$serial"; then
            wait "$qemu_pid" || true
            echo "FAIL: S2 guest exited before PASS" >&2
            exit 1
          fi
          kill "$qemu_pid" 2>/dev/null || true
          wait "$qemu_pid" || true

          grep -q "TEST_RESULT:PASS" "$serial"
          grep -q "CRUCIBLE_S2_BLOCK_DIRECT=1" "$serial"
          grep -q "CRUCIBLE_S2_BLOCK_DONE" "$serial"
          grep -q "CRUCIBLE_S2_9P_DONE" "$serial"
          grep -q "CRUCIBLE_S2_DONE" "$serial"

          get_value() {
            key="$1"
            gawk -F= -v key="$key" '$1 == key {print $2}' "$plugin_out"
          }

          require_eq() {
            key="$1"
            expected="$2"
            actual=$(get_value "$key")
            [ "$actual" = "$expected" ] || {
              echo "FAIL: $key expected $expected, got $actual" >&2
              exit 1
            }
          }

          require_ge() {
            key="$1"
            minimum="$2"
            actual=$(get_value "$key")
            [ -n "$actual" ] || {
              echo "FAIL: $key missing" >&2
              exit 1
            }
            [ "$actual" -ge "$minimum" ] || {
              echo "FAIL: $key expected >= $minimum, got $actual" >&2
              exit 1
            }
          }

          require_le() {
            key="$1"
            maximum="$2"
            actual=$(get_value "$key")
            [ -n "$actual" ] || {
              echo "FAIL: $key missing" >&2
              exit 1
            }
            [ "$actual" -le "$maximum" ] || {
              echo "FAIL: $key expected <= $maximum, got $actual" >&2
              exit 1
            }
          }

          require_eq marker_errors 0
          require_eq open_operation false
          require_eq block_operations "$OPERATION_COUNT"
          require_eq block_completed_operations "$OPERATION_COUNT"
          minimum_idled_operations=$(( (OPERATION_COUNT * IDLE_THRESHOLD_PPM + 999999) / 1000000 ))
          maximum_busy_polled_operations=$(( OPERATION_COUNT - minimum_idled_operations ))
          require_ge block_idled_operations "$minimum_idled_operations"
          require_le block_busy_polled_operations "$maximum_busy_polled_operations"
          require_eq block_operations_with_io_events "$OPERATION_COUNT"
          require_eq block_operations_without_io_events 0
          require_eq ninep_operations "$OPERATION_COUNT"
          require_eq ninep_completed_operations "$OPERATION_COUNT"
          require_ge ninep_idled_operations "$minimum_idled_operations"
          require_le ninep_busy_polled_operations "$maximum_busy_polled_operations"
          require_eq ninep_operations_with_io_events "$OPERATION_COUNT"
          require_eq ninep_operations_without_io_events 0
          require_ge io_events 1
          require_ge block_idle_fraction_ppm "$IDLE_THRESHOLD_PPM"
          require_ge ninep_idle_fraction_ppm "$IDLE_THRESHOLD_PPM"
          require_ge block_total_operation_instructions 1
          require_ge block_total_io_events 1
          require_ge block_total_hlt_events 1
          require_ge ninep_total_operation_instructions 1
          require_ge ninep_total_io_events 1
          require_ge ninep_total_hlt_events 1
          require_eq block_max_busy_poll_instructions 0
          require_eq ninep_max_busy_poll_instructions 0

          block_idle_fraction=$(get_value block_idle_fraction_ppm)
          ninep_idle_fraction=$(get_value ninep_idle_fraction_ppm)

          if [ "$block_idle_fraction" -ge "$IDLE_THRESHOLD_PPM" ]; then
            block_idle_threshold_met=true
          else
            block_idle_threshold_met=false
          fi
          if [ "$ninep_idle_fraction" -ge "$IDLE_THRESHOLD_PPM" ]; then
            ninep_idle_threshold_met=true
          else
            ninep_idle_threshold_met=false
          fi
          if [ "$block_idle_threshold_met" = true ] && [ "$ninep_idle_threshold_met" = true ]; then
            fallback_adopted=false
            mitigation_decision=not_needed_for_measured_delayed_sync_read_path
          else
            fallback_adopted=true
            mitigation_decision=adopt_exactness_preserving_busy_poll_fast_forward_before_relying_on_idle_io_perf
          fi

          mkdir -p "$out"
          {
            echo PASS
            echo spike=hlt-vs-busy-poll-io-idle
            echo check=checks.crucible.phase0.s2HltBusyPoll
            echo target_guest=stock_linux_initramfs
            echo qemu_accel=sim_tcg_thread_single
            echo icount=shift0_sleep_off_align_off
            echo workload_block_reads="$OPERATION_COUNT"
            echo workload_9p_reads="$OPERATION_COUNT"
            echo block_outstanding_wait_source=qemu_block_read_throttle_iops_20
            echo ninep_outstanding_wait_source=qemu_9p_read_throttle_iops_20
            echo idle_threshold_ppm="$IDLE_THRESHOLD_PPM"
            echo block_idle_fraction_requirement=ge_900000
            echo block_busy_poll_fraction_requirement=le_100000
            echo block_idled_operations="$(get_value block_idled_operations)"
            echo block_busy_polled_operations="$(get_value block_busy_polled_operations)"
            echo block_idle_fraction_ppm="$block_idle_fraction"
            echo block_operations_with_io_events="$OPERATION_COUNT"
            echo block_operations_without_io_events=0
            echo block_busy_poll_instruction_distribution=empty
            echo block_hlt_observed=true
            echo block_io_events_observed_per_operation=true
            echo block_idle_threshold_met="$block_idle_threshold_met"
            echo ninep_idle_fraction_requirement=ge_900000
            echo ninep_busy_poll_fraction_requirement=le_100000
            echo ninep_idled_operations="$(get_value ninep_idled_operations)"
            echo ninep_busy_polled_operations="$(get_value ninep_busy_polled_operations)"
            echo ninep_idle_fraction_ppm="$ninep_idle_fraction"
            echo ninep_operations_with_io_events="$OPERATION_COUNT"
            echo ninep_operations_without_io_events=0
            echo ninep_busy_poll_instruction_distribution=empty
            echo ninep_hlt_observed=true
            echo ninep_io_events_observed_per_operation=true
            echo ninep_idle_threshold_met="$ninep_idle_threshold_met"
            echo fallback_adopted="$fallback_adopted"
            echo correctness_dependency=none_busy_poll_remains_bit_correct
            echo busy_poll_mitigation_decision="$mitigation_decision"
            echo fallback=not_adopted_for_measured_delayed_sync_read_path
            echo s2_complete=true
          } > "$out/result"
          cp "$serial" "$out/serial.log"
          cp "$qemu_args" "$out/qemu-args.txt"
        '';
      }
    ];

    meta = {
      description = "Crucible Phase 0 S2 HLT-vs-busy-poll I/O idle characterization";
    };
  }
