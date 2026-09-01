{
  pkgs,
  lib,
  index,
  qemuPackage ? pkgs.qemu-crucible,
  buildDrv,
  attrPath ? "drop-one-live-io",
}: let
  isBlock = index == 17;
  isNinep = index == 19;
  liveIoRunner = import ./_live-io-runner.nix {inherit pkgs lib;};
  blockInitramfs = import ./phase2-qemu-live-block-io-guest.nix {inherit pkgs;};
  ninepInitramfs = import ./phase2-qemu-live-9p-io-guest.nix {inherit pkgs;};
  ninepKernel = pkgs.linuxWith ''
    CONFIG_NET_9P=y
    CONFIG_NET_9P_VIRTIO=y
    CONFIG_9P_FS=y
    CONFIG_9P_FS_POSIX_ACL=y
    CONFIG_NETFS_SUPPORT=y
  '';
  fullGate =
    if isBlock
    then import ./phase2-qemu-live-block-io.nix {inherit pkgs lib;}
    else if isNinep
    then import ./phase2-qemu-live-9p-io.nix {inherit pkgs lib;}
    else throw "_drop-one-live-io.nix: unsupported patch index ${toString index}";
  variantQemu = pkgs.mkDerivation {
    pname = "crucible-drop-one-live-io-qemu-${toString index}";
    version = "0";
    src = null;
    buildDeps = [pkgs.coreutils];
    runtimeDeps = [buildDrv qemuPackage];
    BUILD_DRV = "${buildDrv}";
    VARIANT_QEMU = "${buildDrv}/variant-qemu-system-x86_64";
    QEMU_DATA_DIR = "${qemuPackage}/share/qemu";
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          if [ "$(cat "$BUILD_DRV/outcome")" != built ]; then
            exit 0
          fi
          test -x "$VARIANT_QEMU"
          cat > "$out/bin/qemu-system-x86_64" <<WRAPPER
          #!${pkgs.bash}/bin/bash
          exec "$VARIANT_QEMU" -L "$QEMU_DATA_DIR" "\$@"
          WRAPPER
          chmod 0755 "$out/bin/qemu-system-x86_64"
        '';
      }
    ];
  };
  guestKernel =
    if isBlock
    then pkgs.linux
    else ninepKernel;
  guestInitrd =
    if isBlock
    then blockInitramfs
    else ninepInitramfs;
  runnerName =
    if isBlock
    then "crucible-qemu-live-block-io"
    else "crucible-qemu-live-ninep-io";
  semanticForm =
    if index == 17
    then "variant-zero-byte-block-completion-corrupts-request-token-order"
    else "variant-live-9p-forward-path-unavailable";
in
  pkgs.mkDerivation {
    pname = "crucible-drop-one-live-io-${toString index}";
    version = "0";
    src = null;

    buildDeps = [
      pkgs.coreutils
      pkgs.gawk
      pkgs.grep
      pkgs.crucible-qemu-plugin
      liveIoRunner
      variantQemu
    ];

    FULL_GATE = "${fullGate}";
    BUILD_DRV = "${buildDrv}";
    RUNNER = "${liveIoRunner}/bin/${runnerName}";
    VARIANT_QEMU = "${variantQemu}/bin/qemu-system-x86_64";
    PLUGIN = "${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so";
    GUEST_KERNEL = builtins.toString guestKernel;
    GUEST_INITRD = "${guestInitrd}/initrd.img";
    GUEST_FIRMWARE = "${qemuPackage}/share/qemu/bios-256k.bin";
    DROP_INDEX = toString index;
    SEMANTIC_FORM = semanticForm;
    ATTR_PATH = attrPath;

    phases = [
      {
        name = "probe-live-io-variant";
        script = ''
          set -eu
          export LC_ALL=C
          mkdir -p "$out"

          if [ "$(cat "$BUILD_DRV/outcome")" != built ]; then
            cat > "$out/result" <<RESULT
          PASS
          check=$ATTR_PATH
          gate=gate:patch-microtests
          drop_index=$DROP_INDEX
          sim_discriminator_classification=not-applicable
          reason=variant-not-built
          RESULT
            exit 0
          fi

          cp "$FULL_GATE/result" "$out/full.result"

          if [ "$DROP_INDEX" -eq 17 ]; then
            grep -Eq '^write_frames_processed=[1-9][0-9]*$' "$out/full.result"
            grep -Fxq 'last_device_io_active=false' "$out/full.result"
            grep -Fxq 'guest_progressed_past_block_io=true' "$out/full.result"
          else
            grep -Fxq 'sim_leg_forwarded=true' "$out/full.result"
            grep -Fxq 'guest_progressed_past_ninep_io=true' "$out/full.result"
            grep -Fxq 'tcg_control_issued_9p=true' "$out/full.result"
          fi

          vmlinuz=$(ls "$GUEST_KERNEL"/boot/vmlinuz-* | head -1)
          test -n "$vmlinuz"

          run_variant() {
            label="$1"
            run_dir="$TMPDIR/variant-$label"
            report="$out/variant-$label.result"
            mkdir -p "$run_dir"
            set +e
            if [ "$DROP_INDEX" -eq 17 ]; then
              GUEST_KERNEL_APPEND='console=ttyS0 rdinit=/init quiet nokaslr norandmaps random.trust_cpu=off net.ifnames=0 nohz=off' \
              CRUCIBLE_BLOCK_IO_BUSY_CEILING=10000000000 \
              CRUCIBLE_BLOCK_IO_TIMEOUT_SECS=20 \
              CRUCIBLE_BLOCK_IO_SECOND_RUN_SCHEDULER_PREEMPTION=0 \
                timeout -k 15 300 \
                  "$RUNNER" \
                  "$VARIANT_QEMU" \
                  "$PLUGIN" \
                  "$vmlinuz" \
                  "$GUEST_FIRMWARE" \
                  "$run_dir" \
                  "$GUEST_INITRD" \
                  > "$report" 2>&1
            else
              CRUCIBLE_9P_IO_BUSY_CEILING=4000000000 \
              CRUCIBLE_9P_IO_TIMEOUT_SECS=20 \
              CRUCIBLE_9P_IO_SECOND_RUN_SCHEDULER_PREEMPTION=0 \
                timeout -k 15 300 \
                  "$RUNNER" \
                  "$VARIANT_QEMU" \
                  "$PLUGIN" \
                  "$vmlinuz" \
                  "$GUEST_FIRMWARE" \
                  "$run_dir" \
                  "$GUEST_INITRD" \
                  > "$report" 2>&1
            fi
            status=$?
            set -e
            printf '%s\n' "$status" > "$out/variant-$label.status"
            cat "$report" >&2

            if [ "$DROP_INDEX" -eq 17 ]; then
              test "$status" -eq 0
              grep -Fq 'block response request id 0 does not match token 1' "$report"
              grep -Fxq 'last_device_io_active=true' "$report"
              grep -Fxq 'guest_progressed_past_block_io=false' "$report"
              printf '%s\n' zero-byte-completion-corrupts-token-order
            else
              test "$status" -ne 0
              grep -Eiq '9p|ninep|device|advance|timed out|timeout|stalled' "$report"
              if [ "$status" -eq 124 ]; then
                printf '%s\n' timeout
              else
                printf '%s\n' gate-failure
              fi
            fi
          }

          class_a=$(run_variant a)
          class_b=$(run_variant b)
          test "$class_a" = "$class_b"

          cat > "$out/result" <<RESULT
          PASS
          check=$ATTR_PATH
          gate=gate:patch-microtests
          drop_index=$DROP_INDEX
          sim_discriminator_classification=differs
          semantic_form=$SEMANTIC_FORM
          full_live_io_gate=$FULL_GATE
          full_live_effect_present=true
          variant_live_effect_absent=true
          variant_failure_class=$class_a
          variant_runs=2
          variant_diverges=false
          runs_to_diverge=0
          RESULT
        '';
      }
    ];
  }
