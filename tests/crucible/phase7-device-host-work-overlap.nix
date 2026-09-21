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
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  taskList = builtins.concatStringsSep "," taskIds;
  exactTest = "supervision::device_host_work::tests::synchronous_host_wins_and_guest_wins_preserve_completion_and_canonical_log";
  verifyScript = ''
    set -eu
    exact_test=${lib.escapeShellArg exactTest}
    export CARGO_HOME="$TMPDIR/cargo"
    mkdir -p "$CARGO_HOME" .cargo
    sed "s|@vendor@|${cargoDeps}|g" \
      "${cargoDeps}/.cargo/config.toml" > .cargo/config.toml

    listing=$(cargo test --frozen --offline \
      --manifest-path crates/Cargo.toml \
      --target-dir "$TMPDIR/target" \
      -p crucible-qemu --lib "$exact_test" \
      -- --list)
    test "$(printf '%s\n' "$listing" | grep -Fxc "$exact_test: test")" -eq 1
    cargo test --frozen --offline \
      --manifest-path crates/Cargo.toml \
      --target-dir "$TMPDIR/target" \
      -p crucible-qemu --lib "$exact_test" \
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
  authoritativeGate = pkgs.mkDerivation {
    pname = "crucible-phase7-device-host-work-overlap";
    version = "0";
    src = source;

    buildDeps = [pkgs.coreutils pkgs.grep pkgs.rust] ++ dependencies;

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
        name = "verify-production-device-host-work";
        script = verifyScript;
      }
    ];
  };
  modeScript = ''
    cp -R ${source} source
    chmod -R u+w source
    cd source
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
      runtimeInputs = [pkgs.coreutils pkgs.grep pkgs.rust pkgs.sed] ++ dependencies;
      runtimeClosures = [source cargoDeps];
      runtimeScript = modeScript;
      timeout = 1800;
      memoryMiB = 4096;
      varSizeMiB = 8192;
    }
  else authoritativeGate
