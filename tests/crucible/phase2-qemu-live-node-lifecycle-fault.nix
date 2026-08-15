{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuLiveNodeLifecycleFault",
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-live-node-lifecycle-fault";
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
    GUEST_FIRMWARE = "${pkgs.qemu-crucible}/share/qemu/bios-256k.bin";
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
        name = "run-live-node-lifecycle-fault";
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
            --target-dir "$TMPDIR/live-node-lifecycle-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --example crucible-qemu-live-node-lifecycle-fault

          run_dir="$TMPDIR/live-node-lifecycle-run"
          mkdir -p "$run_dir"
          report="$TMPDIR/live-node-lifecycle.result"
          timeout -k 15 590 \
            "$TMPDIR/live-node-lifecycle-target/debug/examples/crucible-qemu-live-node-lifecycle-fault" \
            ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
            ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
            "$vmlinuz" \
            "$GUEST_FIRMWARE" \
            "$run_dir" \
            > "$report"

          cat "$report"
          grep -Fxq PASS "$report"
          grep -Fxq 'gate=gate:live-node-lifecycle-fault' "$report"
          grep -Fxq 'backend=production-qemu-signal-runtime' "$report"
          grep -Fxq 'effect=node.lifecycle' "$report"
          grep -Fxq 'transition=crash' "$report"
          grep -Eq '^observed_icount=[1-9][0-9]*$' "$report"
          grep -Eq '^action=[0-9a-f]{64}$' "$report"
          grep -Eq '^evidence=[0-9a-f]{64}$' "$report"
          grep -Fxq 'exit_code=70' "$report"
          grep -Fxq 'signal_impulse_applied=true' "$report"

          mkdir -p "$out"
          cp "$report" "$out/result"
          printf 'attr_path=%s\n' "$ATTR_PATH" >> "$out/result"
          printf 'proven=typed-event,binding-evaluation,capability-admission,shared-command-ring,safe-boundary,typed-occurrence,authorized-process-exit\n' >> "$out/result"
        '';
      }
    ];
  }
