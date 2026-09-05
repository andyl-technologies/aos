{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.signalSharedCause",
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  guest = import ./phase7-signal-shared-cause-guest.nix {inherit pkgs;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase7-signal-shared-cause";
    version = "0";
    src = crucibleSrc;

    buildDeps = [
      pkgs.coreutils
      pkgs.crucible-fixtures
      pkgs.crucible-qemu-plugin
      pkgs.grep
      pkgs.qemu-crucible
      pkgs.rust
      pkgs.sed
    ];

    GUEST_KERNEL = builtins.toString pkgs.linux;
    GUEST_INITRD = "${guest}/initrd.img";
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
        name = "run-signal-shared-cause";
        script = ''
          set -eu
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          vmlinuz=$(ls "$GUEST_KERNEL"/boot/vmlinuz-* | head -1)
          root_image=${pkgs.crucible-fixtures}/share/crucible/fixtures/root/aos-minimal-root.ext4
          target="$TMPDIR/signal-shared-cause-target"
          cargo build \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-api \
            --example crucible-qemu-signal-shared-cause

          # The production lifecycle adds scenario, run, node, and QEMU role
          # components below this root. Keep the Nix-build prefix short enough
          # for Linux AF_UNIX socket addresses.
          run_dir=/tmp/r
          mkdir -p "$run_dir"
          timeout -k 15 900 \
            "$target/debug/examples/crucible-qemu-signal-shared-cause" \
            ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
            ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
            "$vmlinuz" \
            "$root_image" \
            "$GUEST_INITRD" \
            "$run_dir" \
            > result

          cat result
          grep -Fxq PASS result
          grep -Fxq 'gate=gate:signal-shared-cause' result
          grep -Fxq 'backend=production-qemu-lifecycle' result
          grep -Fxq 'pre_event_queue_and_volatile_cache=true' result
          grep -Fxq 'pre_event_queue_finish_after_event=true' result
          grep -Fxq 'network_storage_node_same_event=true' result
          grep -Fxq 'shared_event_effect_records=3' result
          grep -Fxq 'node_effective_icount_authenticated=true' result
          grep -Fxq 'exact_checkpoint_evidence_match=true' result
          grep -Fxq 'locked_effect_replay_evidence_match=true' result
          grep -Fxq 'inactive_world_exact_trigger_without_run=true' result
          grep -Fxq 'inactive_world_checkpoint_event_log_match=true' result
          grep '^terminal_row=' result > terminal-rows
          test "$(wc -l < terminal-rows)" -eq 2
          test "$(sort -u terminal-rows | wc -l)" -eq 2
          grep -Fxq 'terminal_row=node-a|transition=power_off|generation_delta=1|service_state=powered_off|scheduler_activity=halted|process_ownership=exact' terminal-rows
          grep -Fxq 'terminal_row=node-b|transition=permanent_failure|generation_delta=0|service_state=permanently_failed|scheduler_activity=done|process_ownership=absent' terminal-rows
          mkdir -p "$out"
          cp result "$out/result"
          printf 'attr_path=%s\n' "$ATTR_PATH" >> "$out/result"
        '';
      }
    ];
  }
