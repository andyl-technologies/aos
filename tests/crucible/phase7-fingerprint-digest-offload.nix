{
  pkgs,
  lib,
  productionPluginFlight,
  attrPath ? "checks.crucible.phase7.fingerprintDigestOffload",
  taskIds ? ["T-PERF-30"],
  campaignComposition ? null,
  testing ? import ../../lib/testing {inherit pkgs lib;},
}: let
  taskList = builtins.concatStringsSep "," taskIds;
  workerSource = builtins.readFile ../../crates/crucible-qemu-plugin/src/runtime/live_callbacks/fingerprint_worker.rs;
  callbackSource = builtins.readFile ../../crates/crucible-qemu-plugin/src/runtime/live_callbacks.rs;
  inherit (import ./_lib.nix {inherit lib;}) failuresFor forbiddenFor;

  failures =
    failuresFor "fingerprint_worker.rs" workerSource [
      {
        label = "bounded digest queue";
        needle = "mpsc::sync_channel::<LiveFingerprintDigestWork>(1)";
      }
      {
        label = "worker-owned digest";
        needle = "let sample = work.captured.digest();";
      }
      {
        label = "worker-owned acknowledgement";
        needle = ".acknowledge_capture_v1(work.capture_request)";
      }
    ]
    ++ failuresFor "live_callbacks.rs" callbackSource [
      {
        label = "production asynchronous submission";
        needle = "fingerprint.worker.submit(captured, capture_request)";
      }
    ]
    ++ forbiddenFor "live_callbacks.rs" callbackSource [
      {
        label = "synchronous digest wait";
        needle = "submit_and_wait";
      }
      {
        label = "callback-owned capture acknowledgement";
        needle = "acknowledge_capture_v1(capture_request)";
      }
    ];
  liveLog =
    if campaignComposition == null
    then "${productionPluginFlight}/serial.log"
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
    grep -Fxq 'rust_plugin_loaded=true' "$live"
    grep -Fxq 'sample_stream_restart_identical=true' "$live"
    grep -Fxq 'on_demand_worker_acknowledgements=24' "$live"
    grep -Fxq 'on_demand_boundary_stream_bit_identical=true' "$live"
    grep -Fxq 'sample_target_icounts=2000000,2000001,4000000,8000000' "$live"
    grep -Fxq 'bounded_scheduler_preemption_applied=true' "$live"
    grep -Fxq 'component_failures=0' "$live"

    mkdir -p "$out"
    cp "$live" "$out/live-plugin-flight.log"
    cat > "$out/result" <<'RESULT'
    PASS
    check=${attrPath}
    gate=gate:fingerprint-digest-offload
    tasks=${taskList}
    status=complete
    admission_class=A
    capture=exact-boundary-sealed-descriptor-preimage
    digest_thread=crucible-fingerprint-digest
    callback_waits_for_digest=false
    acknowledgement_owner=digest-worker
    bounded_queue=1
    live_production_fingerprint_run=true
    run_twice_fingerprints_identical=true
    on_demand_sample_coordinates_unchanged=true
    authenticated_on_demand_requests_acknowledged=24
    on_demand_boundary_stream_bit_identical=true
    RESULT
  '';
in
  if failures != []
  then throw "crucible fingerprint digest offload check failed:\n${builtins.concatStringsSep "\n" failures}"
  else if campaignComposition != null
  then
    import ./phase9-campaign-mode-system-gate.nix {
      inherit pkgs lib testing;
      inherit (campaignComposition) mode system;
      gateName = "gate:fingerprint-digest-offload";
      authoritativeAttr = attrPath;
      executionFamily = "qemu-runtime";
      name = "fingerprint-digest-offload";
      runtimeInputs = [pkgs.coreutils pkgs.grep];
      runtimeClosures = [productionPluginFlight];
      runtimeScript = verifyScript;
      timeout = 3600;
      memoryMiB = 4096;
      varSizeMiB = 8192;
    }
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-fingerprint-digest-offload";
      version = "0";
      buildDeps = [pkgs.coreutils pkgs.grep productionPluginFlight];

      phases = [
        {
          name = "verify-production-fingerprint-offload";
          script = verifyScript;
        }
      ];
    }
