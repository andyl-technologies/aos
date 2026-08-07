{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuLiveBlockRealization",
  taskIds ? [],
  openTaskIds ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;
in
  pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-live-block-realization";
    version = "0";
    src = crucibleSrc;

    buildDeps = [
      pkgs.coreutils
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
        name = "run-live-block-realization";
        script = ''
          set -eu
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi

          cargo build \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/live-block-realization-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --example crucible-qemu-live-block-realization

          run_dir="$TMPDIR/live-block-realization-run"
          mkdir -p "$run_dir"
          report="$TMPDIR/live-block-realization.result"
          # The crucible-shmem block driver is opened through its typed
          # `-blockdev driver=crucible-shmem` QAPI path with the guest frozen at
          # reset; reaching prelaunch proves the schema, driver registration,
          # and `bdrv_open` all succeeded.
          timeout -k 15 120 \
            "$TMPDIR/live-block-realization-target/debug/examples/crucible-qemu-live-block-realization" \
            ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
            "$run_dir" \
            4194304 \
            > "$report"

          grep -Fxq PASS "$report"
          grep -Fxq 'gate=gate:block-realization' "$report"
          grep -Fxq 'block_driver=crucible-shmem' "$report"
          grep -Fxq 'open_interface=blockdev-qapi' "$report"
          grep -Fxq 'driver_opened=true' "$report"
          grep -Fxq 'run_state=prelaunch' "$report"
          grep -Fxq 'orderly_child_exit=true' "$report"

          mkdir -p "$out"
          cp "$report" "$out/result"
          {
            printf 'attr_path=%s\n' "$ATTR_PATH"
            printf 'task_ids=%s\n' "$TASK_IDS"
            printf 'open_task_ids=%s\n' "$OPEN_TASK_IDS"
            printf 'scope=crucible-shmem-block-driver-runtime-realization-probe\n'
            printf 'open_interface=typed-blockdev-qapi-enum\n'
            printf 'guest_execution=frozen-at-reset-no-guest-io\n'
          } >> "$out/result"
        '';
      }
    ];
  }
