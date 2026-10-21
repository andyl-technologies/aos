{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuLiveBlockRealization",
  taskIds ? [],
  openTaskIds ? [],
  campaignComposition ? null,
  testing ? import ../../lib/testing {inherit pkgs lib;},
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleBinaries workspaceTests;

  # The probe is compiled once by the debug test family; the host gate and
  # the campaign-mode guest both run this copy instead of compiling.
  probe = mkCrucibleBinaries {
    pname = "crucible-qemu-live-block-realization";
    builds = [workspaceTests.apacheTests];
    executables.crucible-qemu-live-block-realization = "build -p crucible-qemu --example crucible-qemu-live-block-realization";
  };

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;
  runtimeInputs = [
    pkgs.coreutils
    pkgs.grep
    pkgs.qemu-crucible
    pkgs.sed
  ];
  runtimeEnvironment = {
    TASK_IDS = taskList;
    OPEN_TASK_IDS = openTaskList;
    ATTR_PATH = attrPath;
  };
  executorPhases = [
    {
      name = "run-live-block-realization";
      script = ''
        set -eu

        run_dir="$TMPDIR/live-block-realization-run"
        mkdir -p "$run_dir"
        report="$TMPDIR/live-block-realization.result"
        # The crucible-shmem block driver is opened through its typed
        # `-blockdev driver=crucible-shmem` QAPI path with the guest frozen at
        # reset; reaching prelaunch proves the schema, driver registration,
        # and `bdrv_open` all succeeded.
        timeout -k 15 120 \
          ${probe}/bin/crucible-qemu-live-block-realization \
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
  runtimeScript = ''
    cd "$TMPDIR"
    ${builtins.concatStringsSep "\n" (map (phase: phase.script) executorPhases)}
  '';
  authoritativeGate = pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-live-block-realization";
    version = "0";
    src = null;
    buildDeps = runtimeInputs;
    TASK_IDS = taskList;
    OPEN_TASK_IDS = openTaskList;
    ATTR_PATH = attrPath;
    phases = executorPhases;
  };
in
  if campaignComposition != null
  then
    import ./phase9-campaign-mode-system-gate.nix {
      inherit
        pkgs
        lib
        testing
        runtimeScript
        ;
      inherit runtimeInputs runtimeEnvironment;
      inherit (campaignComposition) mode system;
      gateName = "gate:block-realization";
      authoritativeAttr = attrPath;
      executionFamily = "qemu-runtime";
      name = "qemu-live-block-realization";
      runtimeClosures = [probe];
      timeout = 3600;
      memoryMiB = 4096;
      varSizeMiB = 8192;
    }
  else authoritativeGate
