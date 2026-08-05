{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuLivePluginPreemption",
  taskIds ? ["T-PLUG-25" "T-DET-30"],
  openTaskIds ? [],
  ceilingStep ? "4000000",
  timeoutSecs ? "250",
  rrSwitchQuantums ? ["4096"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
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
    RR_SWITCH_QUANTUMS = builtins.concatStringsSep " " rrSwitchQuantums;
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
          sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
              > .cargo/config.toml
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
            --features test-support \
            --example crucible-qemu-live-plugin-preemption

          run_root="$TMPDIR/live-plugin-preemption-run"
          mkdir -p "$run_root"
          all_reports="$TMPDIR/live-plugin-preemption.result"
          : > "$all_reports"
          export CRUCIBLE_PREEMPTION_FIRMWARE="$GUEST_FIRMWARE"
          for requested_quantum in $RR_SWITCH_QUANTUMS; do
            run_dir="$run_root/quantum-$requested_quantum"
            mkdir -p "$run_dir"
            report="$TMPDIR/live-plugin-preemption-$requested_quantum.result"
            export CRUCIBLE_PREEMPTION_RR_SWITCH_QUANTUM="$requested_quantum"
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
            grep -Fxq 'gate=gate:single-vm-fingerprint' "$report"
            grep -Fxq 'smp_vcpus=2' "$report"
            grep -Eq '^switch_icount=[1-9][0-9]*$' "$report"
            grep -Eq '^switch_from_vcpu=[01]$' "$report"
            grep -Eq '^switch_to_vcpu=[01]$' "$report"
            from=$(sed -n 's/^switch_from_vcpu=//p' "$report")
            to=$(sed -n 's/^switch_to_vcpu=//p' "$report")
            test "$from" -ne "$to"
            grep -Fxq 'switch_consumed_sequence=1' "$report"
            grep -Eq '^interrupt_icount=[1-9][0-9]*$' "$report"
            grep -Eq '^ipi_send_icount=[1-9][0-9]*$' "$report"
            grep -Fxq 'ipi_fixed_latency_icount=17' "$report"
            grep -Eq '^ipi_earliest_delivery_icount=[1-9][0-9]*$' "$report"
            grep -Fxq "ipi_rr_switch_quantum=$requested_quantum" "$report"
            grep -Eq '^interrupt_sender_vcpu=[01]$' "$report"
            grep -Eq '^interrupt_target_vcpu=[01]$' "$report"
            sender=$(sed -n 's/^interrupt_sender_vcpu=//p' "$report")
            target=$(sed -n 's/^interrupt_target_vcpu=//p' "$report")
            test "$sender" -ne "$target"
            send_icount=$(sed -n 's/^ipi_send_icount=//p' "$report")
            latency=$(sed -n 's/^ipi_fixed_latency_icount=//p' "$report")
            earliest=$(sed -n 's/^ipi_earliest_delivery_icount=//p' "$report")
            delivery=$(sed -n 's/^interrupt_icount=//p' "$report")
            quantum=$(sed -n 's/^ipi_rr_switch_quantum=//p' "$report")
            test "$earliest" -eq "$((send_icount + latency))"
            test "$delivery" -ge "$earliest"
            test "$((delivery % quantum))" -eq 0
            test "$((delivery - earliest))" -lt "$quantum"
            grep -Fxq 'interrupt_vector=241' "$report"
            grep -Fxq 'interrupt_consumed_sequence=2' "$report"
            grep -Eq '^terminal_icount=[1-9][0-9]*$' "$report"
            grep -Fxq 'deterministic_under_host_load=true' "$report"
            grep -Fxq 'host_load_applied=true' "$report"
            grep -Fxq 'sim_double_schedule_matches=true' "$report"
            grep -Eq '^execution_fingerprint=[0-9a-f]{64}$' "$report"
            cat "$report" >> "$all_reports"
          done

          mkdir -p "$out"
          cp "$all_reports" "$out/result"
          {
            printf 'tested_rr_switch_quantums=%s\n' "$(printf '%s' "$RR_SWITCH_QUANTUMS" | tr ' ' ',')"
            printf 'attr_path=%s\n' "$ATTR_PATH"
            printf 'task_ids=%s\n' "$TASK_IDS"
            printf 'open_task_ids=%s\n' "$OPEN_TASK_IDS"
            printf 'proven=live-smp-vcpu-switch,live-smp-commanded-interrupt,fixed-latency-ipi,next-rr-switch-delivery,exact-icount-fail-stop,mailbox-ack,host-load-repeat,sim-double-schedule\n'
          } >> "$out/result"
        '';
      }
    ];
  }
