{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.qemuHostParallel",
  taskIds ? ["T-PERF-29"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  idleInitramfs = import ./phase2-qemu-live-plugin-quantum-guest.nix {inherit pkgs;};
  taskList = builtins.concatStringsSep "," taskIds;
in
  pkgs.mkDerivation {
    pname = "crucible-phase7-qemu-host-parallel";
    version = "0";
    src = crucibleSrc;

    buildDeps =
      [
        pkgs.coreutils
        pkgs.crucible-qemu-plugin
        pkgs.grep
        pkgs.qemu-crucible
        pkgs.rust
        pkgs.sed
      ]
      ++ dependencies;

    GUEST_KERNEL = builtins.toString pkgs.linux;
    GUEST_INITRD = "${idleInitramfs}/initrd.img";
    GUEST_FIRMWARE = "${pkgs.qemu-crucible}/share/qemu/bios-256k.bin";
    CRUCIBLE_HOST_PARALLEL_KERNEL_APPEND = "console=ttyS0 rdinit=/init quiet nokaslr norandmaps random.trust_cpu=off net.ifnames=0 nohz=off";
    CRUCIBLE_HOST_PARALLEL_TIMEOUT_SECS = "240";

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
        name = "run-live-host-parallel";
        script = ''
          set -eu
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          vmlinuz=$(ls "$GUEST_KERNEL"/boot/vmlinuz-* | head -1)
          test -n "$vmlinuz"

          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/live-host-parallel-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --test host_worker_pool \
            qemu_host_worker_allows_the_complete_network_retry_budget \
            -- \
            --exact

          cargo build \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/live-host-parallel-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --example crucible-qemu-live-host-parallel

          report="$TMPDIR/live-host-parallel.result"
          timeout -k 15 1100 \
            "$TMPDIR/live-host-parallel-target/debug/examples/crucible-qemu-live-host-parallel" \
            ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
            ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
            "$vmlinuz" \
            "$GUEST_FIRMWARE" \
            "$TMPDIR/live-host-parallel-run" \
            "$GUEST_INITRD" \
            > "$report"

          cat "$report"
          grep -Fxq PASS "$report"
          grep -Fxq 'gate=gate:live-host-parallel' "$report"
          grep -Fxq 'backend=real-qemu-node' "$report"
          grep -Fxq 'serial_realized_parallelism=1' "$report"
          grep -Fxq 'parallel_realized_parallelism=2' "$report"
          grep -Eq '^serial_dispatch_wall_us=[1-9][0-9]*$' "$report"
          grep -Eq '^parallel_dispatch_wall_us=[1-9][0-9]*$' "$report"
          grep -Fxq 'state_bit_identical=true' "$report"
          grep -Fxq 'time_bit_identical=true' "$report"
          grep -Fxq 'canonical_log_bit_identical=true' "$report"
          grep -Fxq 'worker_count_in_content_hash=false' "$report"
          serial_hash=$(sed -n 's/^serial_evidence_hash=//p' "$report")
          parallel_hash=$(sed -n 's/^parallel_evidence_hash=//p' "$report")
          test -n "$serial_hash"
          test "$serial_hash" = "$parallel_hash"

          mkdir -p "$out"
          cp "$report" "$out/result"
          {
            printf 'check=%s\n' "${attrPath}"
            printf 'tasks=%s\n' "${taskList}"
            printf 'scope=real-qemu-scheduler-host-worker-path\n'
            printf 'proven=bounded-worker-pool,completion-key-order,serial-parallel-S-T-log-identity,worker-neutral-content-hash,measured-realized-P\n'
          } >> "$out/result"
        '';
      }
    ];
  }
