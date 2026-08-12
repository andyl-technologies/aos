{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuLivePluginInstall",
  taskIds ? ["T-PLUG-3" "T-PLUG-16" "T-PLUG-17" "T-PLUG-18" "T-PLUG-19" "T-PROTO-6"],
  openTaskIds ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  # Reuse the standalone, uninstrumented multiboot guest and an empty root image
  # from the loaded-QEMU coverage gate. The Rust control plugin is the sole
  # plugin loaded here, so it owns virtual-time advancement with no observer.
  guestImage = import ./phase6-basic-block-coverage-guest.nix {inherit pkgs;};

  rootImage = pkgs.mkDerivation {
    pname = "crucible-live-plugin-install-root-image";
    version = "0";
    src = null;

    buildDeps = [
      pkgs.coreutils
      pkgs.qemu-crucible
    ];

    phases = [
      {
        name = "build-empty-qcow2";
        script = ''
          set -eu
          mkdir -p "$out"
          qemu-img create -q -f qcow2 "$out/root.qcow2" 64M
          qemu-img create -q -f qcow2 "$out/overlay.qcow2" 64M
        '';
      }
    ];
  };

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;
in
  pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-live-plugin-install";
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

    TASK_IDS = taskList;
    OPEN_TASK_IDS = openTaskList;
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
        name = "run-live-plugin-install";
        script = ''
          set -eu
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi

          cargo build \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/live-plugin-install-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --example crucible-qemu-live-plugin-install

          run_dir="$TMPDIR/live-plugin-install-run"
          mkdir -p "$run_dir"
          # The deterministic launch profile boots the guest through a writable
          # root overlay backed by the immutable root image, so stage a fresh
          # overlay in the run directory before the child inherits its cwd.
          cp ${rootImage}/overlay.qcow2 "$run_dir/crucible-root-overlay.qcow2"
          chmod u+w "$run_dir/crucible-root-overlay.qcow2"
          report="$TMPDIR/live-plugin-install.result"
          timeout -k 15 180 \
            "$TMPDIR/live-plugin-install-target/debug/examples/crucible-qemu-live-plugin-install" \
            ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
            ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
            ${guestImage}/coverage-guest.elf \
            ${rootImage}/root.qcow2 \
            "$run_dir" \
            > "$report"

          grep -Fxq PASS "$report"
          grep -Fxq 'gate=gate:plugin-install-lifecycle' "$report"
          grep -Fxq 'plugin_loaded=rust-control-cdylib' "$report"
          grep -Fxq 'time_authority=rust-plugin' "$report"
          grep -Fxq 'setup_ack_ready=true' "$report"
          grep -Fxq 'handshake_slot=0' "$report"
          grep -Eq '^handshake_proto_version=[0-9]+$' "$report"
          grep -Eq '^handshake_abi_version=[0-9]+$' "$report"
          grep -Eq '^handshake_node_count=[1-9][0-9]*$' "$report"
          grep -Eq '^shmem_region_len=[1-9][0-9]*$' "$report"
          grep -Fxq 'boot_barrier_ceiling_enforced=true' "$report"
          grep -Eq '^completed_icount=[1-9][0-9]*$' "$report"
          grep -Eq '^execution_fingerprint=[0-9a-f]{64}$' "$report"
          grep -Fxq 'run_control_silent=true' "$report"
          grep -Fxq 'plugin_quit_consumed=true' "$report"
          grep -Fxq 'orderly_child_exit=true' "$report"
          grep -Fxq 'time_authority_is_rust_plugin=true' "$report"

          mkdir -p "$out"
          cp "$report" "$out/result"
          {
            printf 'attr_path=%s\n' "$ATTR_PATH"
            printf 'task_ids=%s\n' "$TASK_IDS"
            printf 'open_task_ids=%s\n' "$OPEN_TASK_IDS"
            printf 'scope=rust-plugin-install-lifecycle-live-not-fingerprint-migration\n'
            printf 'plugins_loaded=rust-control-plugin-only\n'
            printf 'time_authority=rust-plugin-sim-shmem-dispatch\n'
            printf 'lifecycle=handshake-scmrights-shmem-setupack-bootbarrier-run-silent-quit-exit\n'
          } >> "$out/result"
        '';
      }
    ];
  }
