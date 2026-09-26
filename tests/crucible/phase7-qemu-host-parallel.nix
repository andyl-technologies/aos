{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.qemuHostParallel",
  taskIds ? ["T-PERF-29"],
  productionPluginFlight,
  campaignComposition ? null,
  testing ? import ../../lib/testing {inherit pkgs lib;},
}: let
  source = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  scheduler = builtins.readFile ../../crates/crucible/src/scheduler/event_log/backend_loop.rs;
  lifecycle = builtins.readFile ../../crates/crucible-api/src/vm_lifecycle/quantum_loop.rs;
  lifecycleConfig = builtins.readFile ../../crates/crucible-api/src/vm_lifecycle/config.rs;
  nodeSet = builtins.readFile ../../crates/crucible-qemu/src/node_set.rs;
  concurrentNodeSet = builtins.readFile ../../crates/crucible-qemu/src/node_set/concurrent.rs;
  taskList = builtins.concatStringsSep "," taskIds;
  inherit (import ./_lib.nix {inherit lib;}) failuresFor hasInfix;

  failures =
    failuresFor "crates/crucible/src/scheduler/event_log/backend_loop.rs" scheduler [
      {
        label = "speculative scheduler preparation";
        needle = ".prepare_concurrent_quantum(request)?";
      }
      {
        label = "backend completion precedes scheduler commit";
        needle = "self.backend.execute_concurrent_runs(runs, max_host_workers)";
      }
      {
        label = "scheduler installs only completed staged publication";
        needle = "*self.loop_impl.borrow_mut() = staged_scheduler;";
      }
      {
        label = "interceptor installs only completed staged publication";
        needle = "self.network_output_interceptor = staged_interceptor;";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/vm_lifecycle/quantum_loop.rs" lifecycle [
      {
        label = "production lifecycle concurrent dispatch";
        needle = "crucible_session::drive_engine_concurrent_quantum(";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/vm_lifecycle/config.rs" lifecycleConfig [
      {
        label = "operational host dispatch ceiling";
        needle = "pub const fn maximum_host_workers";
      }
      {
        label = "host worker ceiling remains outside canonical scheduler state";
        needle = "it does not enter canonical scheduler state";
      }
      {
        label = "operational host worker configuration";
        needle = "pub const fn with_maximum_host_workers";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/node_set/concurrent.rs" concurrentNodeSet [
      {
        label = "production QEMU backend concurrency";
        needle = "impl ConcurrentSimulationBackend for QemuNodeSet";
      }
    ]
    ++ lib.optionals (hasInfix "host_worker_pool" nodeSet) [
      "crates/crucible-qemu/src/node_set.rs: superseded facade remains reachable"
    ];
  liveLog =
    if campaignComposition == null
    then "${productionPluginFlight}/serial.log"
    else "${productionPluginFlight}/raw-result";
  liveResult =
    if campaignComposition == null
    then "${productionPluginFlight}/result"
    else "${productionPluginFlight}/raw-result";
  modeDependencyAuthentication = lib.optionalString (campaignComposition != null) ''
    grep -Fxq PASS ${productionPluginFlight}/raw-result
    grep -Fxq 'gate=gate:production-rust-plugin-flight' ${productionPluginFlight}/raw-result
    grep -Fxq ${lib.escapeShellArg "campaign_mode=${campaignComposition.mode}"} ${productionPluginFlight}/raw-result
    grep -Fxq ${lib.escapeShellArg "campaign_configuration_identity=${campaignComposition.system.config.aos.services.crucibleCampaign._runtimeIdentity}"} ${productionPluginFlight}/raw-result
    grep -Fxq ${lib.escapeShellArg "campaign_toplevel=${campaignComposition.system.config.system.build.toplevel}"} ${productionPluginFlight}/raw-result
  '';
  verifyScript = ''
    set -eu
    ${modeDependencyAuthentication}
    live=${lib.escapeShellArg liveLog}
    export CARGO_HOME="$TMPDIR/cargo"
    mkdir -p "$CARGO_HOME" .cargo
    sed "s|@vendor@|${cargoDeps}|g" \
      "${cargoDeps}/.cargo/config.toml" > .cargo/config.toml
    for exact_test in \
      scheduler::tests::concurrent::concurrent_prepare_is_private_until_canonical_commit \
      scheduler::tests::concurrent::concurrent_backend_failure_leaves_scheduler_uncommitted \
      scheduler::tests::concurrent::concurrent_publication_failure_leaves_logical_state_uncommitted_and_poisons
    do
      listing=$(cargo test --frozen --offline \
        --manifest-path crates/Cargo.toml \
        --target-dir "$TMPDIR/target" \
        -p crucible --lib "$exact_test" -- --list)
      test "$(printf '%s\n' "$listing" | grep -Fxc "$exact_test: test")" -eq 1
      cargo test --frozen --offline \
        --manifest-path crates/Cargo.toml \
        --target-dir "$TMPDIR/target" \
        -p crucible --lib "$exact_test" -- --exact
    done

    grep -Fxq PASS ${lib.escapeShellArg liveResult}
    grep -Fxq 'production_host_parallel_requested_runs=2' "$live"
    grep -Fxq 'production_host_parallel_maximum_workers=2' "$live"
    grep -Fxq 'production_host_parallel_realized_parallelism=2' "$live"
    grep -Fxq 'production_host_parallel_commit_order=curl,io-probe' "$live"
    grep -Fxq 'production_host_parallel_state_identity=true' "$live"
    grep -Fxq 'production_host_parallel_time_identity=true' "$live"
    grep -Fxq 'production_host_parallel_canonical_log_identity=true' "$live"
    grep -Fxq 'production_host_parallel_worker_count_absent_from_checkpoint=true' "$live"
    grep -Fxq 'production_vm_lifecycle_path=true' "$live"
    grep -Fxq 'production_host_parallel_failure_healthy_peer_advanced=true' "$live"
    grep -Fxq 'production_host_parallel_failure_logical_state_uncommitted=true' "$live"
    grep -Fxq 'production_host_parallel_failure_retry_poisoned=true' "$live"
    grep -Fxq 'production_host_parallel_authenticated_exact_recovery=true' "$live"

    mkdir -p "$out"
    cp "$live" "$out/production-flight.log"
    cat > "$out/result" <<'RESULT'
    PASS
    check=${attrPath}
    gate=gate:qemu-host-parallel
    tasks=${taskList}
    status=complete
    scheduler_commit=after-all-fixed-runs-complete
    backend=qemu-node-set
    production_lifecycle=ProductionVmLifecycleLoop
    real_nodes=2
    realized_parallelism=2
    canonical_commit_order=curl,io-probe
    state_identity=bit-identical
    time_identity=bit-identical
    canonical_log_identity=bit-identical
    worker_count_in_scheduler_checkpoint=absent
    failed_round_healthy_peer=physically-advanced
    mid_round_failure=terminally-poisoned
    failed_round_logical_commit=none
    recovery=authenticated-exact-checkpoint
    RESULT
  '';
  authoritativeGate = pkgs.mkDerivation {
    pname = "crucible-qemu-host-parallel";
    version = "0";
    src = source;
    buildDeps = [pkgs.coreutils pkgs.grep pkgs.rust pkgs.sed productionPluginFlight];

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
        name = "test";
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
  if failures != []
  then throw "crucible QEMU host-parallel check failed:\n${builtins.concatStringsSep "\n" failures}"
  else if campaignComposition != null
  then
    import ./phase9-campaign-mode-system-gate.nix {
      inherit pkgs lib testing;
      inherit (campaignComposition) mode system;
      gateName = "gate:qemu-host-parallel";
      authoritativeAttr = attrPath;
      executionFamily = "qemu-runtime";
      name = "qemu-host-parallel";
      runtimeInputs = [pkgs.coreutils pkgs.grep pkgs.rust pkgs.sed];
      runtimeClosures = [source cargoDeps productionPluginFlight];
      runtimeScript = modeScript;
      timeout = 3600;
      memoryMiB = 4096;
      varSizeMiB = 8192;
    }
  else authoritativeGate
