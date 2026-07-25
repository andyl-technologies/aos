{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuLivePluginPreemption",
  taskIds ? ["T-PLUG-25"],
  openTaskIds ? [],
  ceilingStep ? "4000000",
  timeoutSecs ? "250",
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };
  guest = import ./phase2-qemu-live-plugin-quantum-guest.nix {inherit pkgs;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-live-plugin-preemption";
    version = "0";
    src = crucibleSrc;

    buildDeps = [
      pkgs.coreutils
      pkgs.crucible-qemu-plugin
      pkgs.grep
      pkgs.qemu-crucible
      pkgs.rust
      pkgs.sed
    ];

    GUEST_KERNEL = builtins.toString pkgs.linux;
    GUEST_INITRD = "${guest}/initrd.img";
    GUEST_FIRMWARE = "${pkgs.qemu-crucible}/share/qemu/bios-256k.bin";
    GUEST_KERNEL_APPEND = "console=ttyS0 rdinit=/init quiet nokaslr norandmaps random.trust_cpu=off net.ifnames=0 nohz=off";
    CRUCIBLE_PREEMPTION_CEILING_STEP = ceilingStep;
    CRUCIBLE_PREEMPTION_TIMEOUT_SECS = timeoutSecs;
    CRUCIBLE_PREEMPTION_SECOND_RUN_LOAD = "1";
    TASK_IDS = builtins.concatStringsSep "," taskIds;
    OPEN_TASK_IDS = builtins.concatStringsSep "," openTaskIds;
    ATTR_PATH = attrPath;

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
        name = "run-live-plugin-preemption";
        script = ''
          set -eu
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          vmlinuz=$(ls "$GUEST_KERNEL"/boot/vmlinuz-* | head -1)
          test -n "$vmlinuz"
          cargo build \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/live-plugin-preemption-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --example crucible-qemu-live-plugin-preemption

          run_dir="$TMPDIR/live-plugin-preemption-run"
          mkdir -p "$run_dir"
          report="$TMPDIR/live-plugin-preemption.result"
          export CRUCIBLE_PREEMPTION_FIRMWARE="$GUEST_FIRMWARE"
          timeout -k 15 590 \
            "$TMPDIR/live-plugin-preemption-target/debug/examples/crucible-qemu-live-plugin-preemption" \
            ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
            ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
            "$vmlinuz" \
            /dev/null \
            "$run_dir" \
            "$GUEST_INITRD" \
            "$GUEST_KERNEL_APPEND" \
            > "$report"

          cat "$report"
          grep -Fxq PASS "$report"
          grep -Fxq 'gate=gate:live-plugin-preemption' "$report"
          grep -Fxq 'smp_vcpus=2' "$report"
          grep -Eq '^switch_icount=[1-9][0-9]*$' "$report"
          grep -Eq '^switch_from_vcpu=[01]$' "$report"
          grep -Eq '^switch_to_vcpu=[01]$' "$report"
          from=$(sed -n 's/^switch_from_vcpu=//p' "$report")
          to=$(sed -n 's/^switch_to_vcpu=//p' "$report")
          test "$from" -ne "$to"
          grep -Fxq 'switch_consumed_sequence=1' "$report"
          grep -Eq '^interrupt_icount=[1-9][0-9]*$' "$report"
          grep -Eq '^interrupt_target_vcpu=[01]$' "$report"
          grep -Fxq 'interrupt_vector=241' "$report"
          grep -Fxq 'interrupt_consumed_sequence=2' "$report"
          grep -Eq '^terminal_icount=[1-9][0-9]*$' "$report"
          grep -Fxq 'deterministic_under_host_load=true' "$report"
          grep -Fxq 'host_load_applied=true' "$report"
          grep -Fxq 'sim_double_schedule_matches=true' "$report"
          grep -Eq '^execution_fingerprint=[0-9a-f]{64}$' "$report"

          mkdir -p "$out"
          cp "$report" "$out/result"
          {
            printf 'attr_path=%s\n' "$ATTR_PATH"
            printf 'task_ids=%s\n' "$TASK_IDS"
            printf 'open_task_ids=%s\n' "$OPEN_TASK_IDS"
            printf 'proven=live-smp-vcpu-switch,live-smp-commanded-interrupt,exact-icount-fail-stop,mailbox-ack,host-load-repeat,sim-double-schedule\n'
          } >> "$out/result"
        '';
      }
    ];
  }
