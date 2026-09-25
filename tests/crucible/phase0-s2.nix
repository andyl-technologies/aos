{
  pkgs,
  lib,
}: let
  operationCount = 32;
  ninepWarmupCount = 8;
  idleThresholdPpm = 900000;
  # Linux's 100 ms LAPIC calibration costs about two billion instructions at
  # 50 ps/instruction. The focused companion below covers LAPIC exactness.
  kernelCommandLine = lib.concatStringsSep " " [
    "console=ttyS0 reboot=k panic=1 rdinit=/init quiet noapic nolapic"
    "nokaslr norandmaps random.trust_cpu=off net.ifnames=0"
  ];
  workloadSource = builtins.readFile ./phase0-s2-workload.c;
  pluginSource = builtins.readFile ./phase0-s2-io-idle-plugin.c;
  lapicGuestSource = builtins.readFile ./phase0-s2-lapic-guest.S;
  lapicPluginSource = builtins.readFile ./phase0-s2-lapic-plugin.c;

  workload = pkgs.mkDerivation {
    pname = "crucible-phase0-s2-workload";
    version = "0";
    src = null;

    source = workloadSource;
    passAsFile = ["source"];

    buildDeps = [
      pkgs.binutils
      pkgs.gawk
    ];

    phases = [
      {
        name = "build-workload";
        script = ''
          cp "$sourcePath" phase0-s2-workload.c
          cc -std=c11 -O2 -Wall -Wextra -fno-PIE -no-pie \
            phase0-s2-workload.c \
            -o s2-io-workload

          activation_vaddr=$(
            nm -n s2-io-workload \
              | gawk '$3 == "marker_observation_enable" { print "0x" $1 }'
          )
          [ -n "$activation_vaddr" ] || {
            echo "FAIL: observation-enable marker symbol is missing" >&2
            exit 1
          }
          [ "$(printf '%s\n' "$activation_vaddr" | wc -l)" -eq 1 ] || {
            echo "FAIL: observation-enable marker symbol is not unique" >&2
            exit 1
          }
          printf '%s\n' "$activation_vaddr" > activation-vaddr
        '';
      }
      {
        name = "install-workload";
        script = ''
          mkdir -p "$out/bin" "$out/share/crucible-phase0-s2"
          cp s2-io-workload "$out/bin/"
          cp activation-vaddr "$out/share/crucible-phase0-s2/"
        '';
      }
    ];
  };

  lapicGuest = pkgs.mkDerivation {
    pname = "crucible-phase0-s2-lapic-guest";
    version = "0";
    src = null;

    guest = lapicGuestSource;
    passAsFile = ["guest"];
    buildDeps = [pkgs.binutils];

    phases = [
      {
        name = "build-lapic-guest";
        script = ''
          set -eu
          cp "$guestPath" guest.S
          as --32 guest.S -o guest.o
          cat > guest.ld <<'GUEST_LD'
          ENTRY(_start)
          PHDRS {
            text PT_LOAD FLAGS(5);
            data PT_LOAD FLAGS(6);
          }
          SECTIONS {
            . = 0x00100000;
            .multiboot : { KEEP(*(.multiboot)) } :text
            .text : { *(.text*) } :text
            .data : { *(.data*) } :data
            .bss : { *(.bss*) *(COMMON) } :data
          }
          GUEST_LD
          ld -m elf_i386 -T guest.ld guest.o -o guest.elf
          mkdir -p "$out"
          cp guest.elf "$out/"
        '';
      }
    ];
  };

  lapicExactness = pkgs.mkDerivation {
    pname = "crucible-phase0-s2-default-lapic-timer";
    version = "0";
    src = null;

    plugin = lapicPluginSource;
    passAsFile = ["plugin"];

    buildDeps = [
      pkgs.coreutils
      pkgs.gawk
      pkgs.glib
      pkgs.glib.dev
      pkgs.pkg-config
      pkgs.qemu-crucible
    ];

    phases = [
      {
        name = "run-default-lapic-timer";
        script = ''
          set -eu

          cp "$pluginPath" lapic-plugin.c
          cc -fPIC -shared -O2 -Wall -Wextra \
            $(pkg-config --cflags glib-2.0) \
            -I${pkgs.qemu-crucible}/include \
            lapic-plugin.c \
            -o lapic-plugin.so

          printf 'crucible-phase0-s2-lapic-seed-v1\n' > seed.bin
          cat > trace-events <<'TRACE_EVENTS'
          apic_local_deliver
          apic_register_write
          crucible_sim_determinism_idle
          crucible_sim_determinism_timer
          TRACE_EVENTS

          set +e
          timeout 30 ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
            -nodefaults \
            -no-user-config \
            -display none \
            -monitor none \
            -serial none \
            -machine pc \
            -accel sim,thread=single \
            -icount shift=0,sleep=off,align=off \
            -cpu qemu64 \
            -m 64 \
            -smp 1 \
            -seed 0x0010c002 \
            -fw_cfg name=opt/crucible/seed,file=seed.bin \
            -kernel ${lapicGuest}/guest.elf \
            -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
            -plugin "$PWD/lapic-plugin.so" \
            -trace events=trace-events,file=trace.log \
            -no-reboot
          status=$?
          set -e
          [ "$status" -eq 33 ] || {
            cat trace.log >&2
            echo "FAIL: LAPIC guest exited with status $status" >&2
            exit 1
          }

          if ! gawk '
            function field(prefix,    i) {
              for (i = 1; i <= NF; i++) {
                if (index($i, prefix) == 1) {
                  return substr($i, length(prefix) + 1)
                }
              }
              return ""
            }
            function fail(code, message) {
              print "FAIL: " message > "/dev/stderr"
              error_code = code
              exit code
            }
            /^crucible_sim_determinism_timer / {
              candidate_expire = field("expire_ps=")
              candidate_current = field("current_ps=")
              candidate_raw = field("raw=")
              next
            }
            /^crucible_sim_determinism_idle phase=request / {
              if (field("target_tick=") != field("deadline_ps=")) {
                fail(5, "idle request target differs from deadline")
              }
              idle_requests++
              next
            }
            /^crucible_sim_determinism_idle phase=complete / {
              if (field("target_tick=") != field("virtual_ps=")) {
                fail(6, "idle completion target differs from virtual time")
              }
              idle_completions++
              next
            }
            /^apic_register_write register 0x32 = 0x20030$/ {
              timer_configured = 1
              next
            }
            /^apic_local_deliver vector 0 delivery mode 0$/ && timer_configured {
              if (candidate_expire == "" || awaiting_eoi) {
                fail(2, "LAPIC delivery lacks a unique preceding timer")
              }
              if (candidate_expire != candidate_current) {
                fail(3, "timer fired away from its exact expiry")
              }
              deliveries++
              expire[deliveries] = candidate_expire
              raw[deliveries] = candidate_raw
              candidate_expire = ""
              awaiting_eoi = 1
              next
            }
            /^apic_register_write register 0x0b = 0x0$/ {
              if (awaiting_eoi) {
                eois++
                awaiting_eoi = 0
              }
            }
            END {
              if (error_code) {
                exit error_code
              }
              if (deliveries != 4 || eois != 4 || awaiting_eoi ||
                  idle_requests != 4 || idle_completions != 4) {
                printf "FAIL: LAPIC lifecycle counts request=%d complete=%d delivery=%d eoi=%d pending_eoi=%d\n", \
                  idle_requests, idle_completions, deliveries, eois, awaiting_eoi \
                  > "/dev/stderr"
                exit 4
              }
              for (i = 1; i <= deliveries; i++) {
                printf "%d %s %s\n", i, expire[i], raw[i]
              }
            }
          ' trace.log > lapic-events.txt; then
            cat trace.log >&2
            exit 1
          fi

          first_expire_ps=$(gawk 'NR == 1 { print $2 }' lapic-events.txt)
          period_ps=$(gawk 'NR == 2 { print $2 - previous } { previous = $2 }' lapic-events.txt)
          gawk -v period="$period_ps" '
            NR > 1 && $2 - previous != period { exit 1 }
            { previous = $2 }
          ' lapic-events.txt
          [ "$period_ps" -eq 1001000 ]
          [ "$first_expire_ps" -eq 290371300 ]
          first_program_raw=$(( (first_expire_ps - period_ps) / 50 ))
          [ "$((first_program_raw * 50 + period_ps))" -eq "$first_expire_ps" ]

          mkdir -p "$out"
          cp trace.log lapic-events.txt "$out/"
          {
            echo PASS
            echo check=crucible-phase0-s2-default-lapic-timer
            echo guest=fixed_default_lapic_periodic_vector48
            echo deliveries=4
            echo eois=4
            echo idle_advances=4
            echo first_expire_ps="$first_expire_ps"
            echo period_ps="$period_ps"
            echo initial_count_program_raw_icount="$first_program_raw"
            echo physical_relation=first_expire_ps_equals_program_raw_times_50_plus_period
            echo delivery_order=timer_then_configured_vector48_lvt_then_eoi
          } > "$out/result"
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
    graphPairs = lib.concatLists (
      lib.imap (i: dep: [
          "closure-${builtins.toString i}"
          dep
        ])
      initramfsDeps
    );
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
      pkgs.glib.dev
      pkgs.grep
      pkgs.pkg-config
      pkgs.qemu-crucible
      lapicExactness
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
          activation_vaddr=$(cat ${workload}/share/crucible-phase0-s2/activation-vaddr)
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
            -append ${kernelCommandLine}
          -drive id=s2block,file=$BLOCK_IMAGE,format=raw,if=none,readonly=on,cache=unsafe,throttling.iops-read=20
          -device virtio-blk-pci,drive=s2block
          -fsdev local,id=fs0,path=$ninep_root,security_model=none,throttling.iops-read=20
          -device virtio-9p-pci,fsdev=fs0,mount_tag=crucible_s2
          -chardev file,id=serial0,path=$serial
          -serial chardev:serial0
          -plugin $plugin,out=$plugin_out,activate-vaddr=$activation_vaddr
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
              -append "${kernelCommandLine}" \
            -drive id=s2block,file="$BLOCK_IMAGE",format=raw,if=none,readonly=on,cache=unsafe,throttling.iops-read=20 \
            -device virtio-blk-pci,drive=s2block \
            -fsdev local,id=fs0,path="$ninep_root",security_model=none,throttling.iops-read=20 \
            -device virtio-9p-pci,fsdev=fs0,mount_tag=crucible_s2 \
            -chardev file,id=serial0,path="$serial" \
            -serial chardev:serial0 \
            -plugin "$plugin",out="$plugin_out",activate-vaddr="$activation_vaddr" \
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
              echo "--- S2 serial tail ---" >&2
              tail -c 16384 "$serial" >&2 || true
              echo "--- S2 plugin state ---" >&2
              cat "$plugin_out" >&2 || true
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
            require_eq activation_marker_callbacks 1
          require_eq reset_completion_callbacks 1
          require_eq block_warmup_retranslated true
          require_eq ninep_warmup_retranslated true
          require_eq open_operation false
          require_eq block_operations "$OPERATION_COUNT"
          require_eq block_completed_operations "$OPERATION_COUNT"
          block_classified_operations=$((
            $(get_value block_idled_operations)
            + $(get_value block_inline_operations)
            + $(get_value block_busy_polled_operations)
          ))
          [ "$block_classified_operations" -eq "$OPERATION_COUNT" ] || {
            echo "FAIL: block classified operations expected $OPERATION_COUNT, got $block_classified_operations" >&2
            exit 1
          }
          require_eq block_busy_polled_operations 0
          require_le block_max_inline_instructions 40000
          require_eq block_operations_with_io_events "$OPERATION_COUNT"
          require_eq block_operations_without_io_events 0
          require_eq ninep_operations "$OPERATION_COUNT"
          require_eq ninep_completed_operations "$OPERATION_COUNT"
          minimum_idled_operations=$(( (OPERATION_COUNT * IDLE_THRESHOLD_PPM + 999999) / 1000000 ))
          maximum_busy_polled_operations=$(( OPERATION_COUNT - minimum_idled_operations ))
          require_ge ninep_idled_operations "$minimum_idled_operations"
          require_le ninep_busy_polled_operations "$maximum_busy_polled_operations"
          require_eq ninep_operations_with_io_events "$OPERATION_COUNT"
          require_eq ninep_operations_without_io_events 0
          require_ge io_events 1
          require_ge ninep_idle_fraction_ppm "$IDLE_THRESHOLD_PPM"
          require_ge block_total_operation_instructions 1
          require_ge block_total_io_events 1
          require_ge ninep_total_operation_instructions 1
          require_ge ninep_total_io_events 1
          require_ge ninep_total_hlt_events 1
          require_eq block_max_busy_poll_instructions 0
          require_eq ninep_max_busy_poll_instructions 0

          block_idle_fraction=$(get_value block_idle_fraction_ppm)
          ninep_idle_fraction=$(get_value ninep_idle_fraction_ppm)

          block_inline_completion_bounded=true
          if [ "$ninep_idle_fraction" -ge "$IDLE_THRESHOLD_PPM" ]; then
            ninep_idle_threshold_met=true
          else
            ninep_idle_threshold_met=false
          fi
          if [ "$block_inline_completion_bounded" = true ] && [ "$ninep_idle_threshold_met" = true ]; then
            fallback_adopted=false
            mitigation_decision=not_needed_for_measured_inline_block_and_delayed_9p_paths
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
            echo guest_irq_mode=legacy_pic_noapic_single_vcpu
            echo default_lapic_companion=${lapicExactness}
            echo observation_activation=guest_marker_then_plugin_reset
            echo measured_path_retranslation=block_and_ninep_warmups_observed
            echo qemu_accel=sim_tcg_thread_single
            echo icount=fixed_50ps_per_instruction_sleep_off_align_off
            echo workload_block_reads="$OPERATION_COUNT"
            echo workload_9p_reads="$OPERATION_COUNT"
            echo block_completion_mode=bounded_inline_or_hlt_idle
            echo ninep_outstanding_wait_source=qemu_9p_read_throttle_iops_20
            echo idle_threshold_ppm="$IDLE_THRESHOLD_PPM"
            echo block_inline_instruction_requirement=le_40000
            echo block_idled_operations="$(get_value block_idled_operations)"
            echo block_inline_operations="$(get_value block_inline_operations)"
            echo block_busy_polled_operations="$(get_value block_busy_polled_operations)"
            echo block_idle_fraction_ppm="$block_idle_fraction"
            echo block_operations_with_io_events="$OPERATION_COUNT"
            echo block_operations_without_io_events=0
            echo block_inline_max_instructions="$(get_value block_max_inline_instructions)"
            echo block_busy_poll_instruction_distribution=empty
            echo block_hlt_required=false_but_permitted
            echo block_io_events_observed_per_operation=true
            echo block_inline_completion_bounded="$block_inline_completion_bounded"
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
            echo fallback=not_adopted_for_bounded_inline_block_and_delayed_9p_paths
            echo s2_complete=true
          } > "$out/result"
          cp "$serial" "$out/serial.log"
          cp "$plugin_out" "$out/plugin.txt"
          cp "$qemu_args" "$out/qemu-args.txt"
        '';
      }
    ];

    meta = {
      description = "Crucible Phase 0 S2 HLT-vs-busy-poll I/O idle characterization";
    };
  }
