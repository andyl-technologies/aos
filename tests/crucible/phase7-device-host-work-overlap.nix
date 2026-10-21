{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.deviceHostWorkOverlap",
  taskIds ? ["T-PERF-31"],
  dependencies ? [],
  campaignComposition ? null,
  testing ? import ../../lib/testing {inherit pkgs lib;},
}: let
  source = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  testGate = import ./_test-gate.nix {inherit pkgs lib;};
  # The campaign-mode guest runs the same prebuilt test executable as the
  # host gate; only that executable enters the guest closure.
  vmRuntime = testGate.mkCrucibleVmRuntime {
    src = source;
    subset = testGate.mkCrucibleTestSubset {
      pname = "crucible-device-host-work-overlap-tests";
      requests = ["crucible-qemu"];
      targets = ["lib:crucible_qemu"];
    };
  };
  taskList = builtins.concatStringsSep "," taskIds;
  exactTest = "supervision::device_host_work::tests::synchronous_host_wins_and_guest_wins_preserve_completion_and_canonical_log";
  verifyScript = ''
    set -eu
    exact_test=${lib.escapeShellArg exactTest}

    listing=$(crucible-cargo test -p crucible-qemu --lib "$exact_test" \
      -- --list)
    test "$(printf '%s\n' "$listing" | grep -Fxc "$exact_test: test")" -eq 1
    crucible-cargo test -p crucible-qemu --lib "$exact_test" \
      -- --exact --nocapture

    mkdir -p "$out"
    cat > "$out/result" <<'RESULT'
    PASS
    check=${attrPath}
    gate=gate:device-host-work-overlap
    tasks=${taskList}
    status=complete
    admission_class=B
    production_path=QemuLiveHostIoRuntime/QemuLiveBlockHostWorkPool
    dispatch=request-observation-time
    completion_coordinate=pinned-before-worker-dispatch
    requester_behavior=stall-at-pinned-coordinate
    synchronous_async_completion_icounts_identical=true
    synchronous_async_canonical_logs_identical=true
    canonical_log=complete-response-region-and-ordered-service-steps
    completion_pinned_before_dispatch=true
    host_wins_race_proven=true
    guest_wins_race_proven=true
    RESULT
  '';
  authoritativeGate = testGate.mkCrucibleTestGate {
    pname = "crucible-phase7-device-host-work-overlap";
    src = source;

    buildDeps = [pkgs.coreutils pkgs.grep] ++ dependencies;

    phases = [
      {
        name = "verify-production-device-host-work";
        script = verifyScript;
      }
    ];
  };
  modeScript = ''
    ${vmRuntime.script}
    ${verifyScript}
  '';
in
  if campaignComposition != null
  then
    import ./phase9-campaign-mode-system-gate.nix {
      inherit pkgs lib testing;
      inherit (campaignComposition) mode system;
      gateName = "gate:device-host-work-overlap";
      authoritativeAttr = attrPath;
      executionFamily = "qemu-runtime";
      name = "device-host-work-overlap";
      runtimeInputs = [pkgs.coreutils pkgs.grep pkgs.sed] ++ dependencies;
      runtimeClosures = vmRuntime.closures;
      runtimeScript = modeScript;
      timeout = 1800;
      memoryMiB = 4096;
      varSizeMiB = 8192;
    }
  else authoritativeGate
