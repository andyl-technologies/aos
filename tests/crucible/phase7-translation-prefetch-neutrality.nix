{
  pkgs,
  lib,
  productionPluginFlight,
  attrPath ? "checks.crucible.phase7.translationPrefetchNeutrality",
  taskIds ? ["T-PERF-32"],
  campaignComposition ? null,
  testing ? import ../../lib/testing {inherit pkgs lib;},
}: let
  taskList = builtins.concatStringsSep "," taskIds;
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
    grep -Fxq 'translation_prefetch_default_off=true' "$live"
    grep -Fxq 'translation_prefetch_helper_started=true' "$live"
    grep -Eq '^translation_prefetch_requests=[1-9][0-9]*$' "$live"
    grep -Eq '^translation_prefetch_completions=[1-9][0-9]*$' "$live"
    grep -Fxq 'translation_prefetch_on_off_fingerprint_identical=true' "$live"
    grep -Fxq 'translation_prefetch_preempted_identity=true' "$live"
    grep -Fxq 'sample_target_icounts=2000000,2000001,4000000,8000000' "$live"
    grep -Fxq 'on_demand_boundary_stream_bit_identical=true' "$live"

    mkdir -p "$out"
    cp "$live" "$out/live-plugin-flight.log"
    cat > "$out/result" <<'RESULT'
    PASS
    check=${attrPath}
    gate=gate:translation-prefetch-neutrality
    tasks=${taskList}
    status=complete
    admission_class=A
    mechanism=dedicated-default-off-tcg-translation-worker
    fingerprint_projection=production-rust-plugin
    host_adversary=bounded-scheduler-preemption
    fingerprints_bit_identical=true
    on_demand_boundary_stream_bit_identical=true
    translation_requests=positive-and-fully-completed
    RESULT
  '';
in
  if campaignComposition != null
  then
    import ./phase9-campaign-mode-system-gate.nix {
      inherit pkgs lib testing;
      inherit (campaignComposition) mode system;
      gateName = "gate:translation-prefetch-neutrality";
      authoritativeAttr = attrPath;
      executionFamily = "qemu-runtime";
      name = "translation-prefetch-neutrality";
      runtimeInputs = [pkgs.coreutils pkgs.grep];
      runtimeClosures = [productionPluginFlight];
      runtimeScript = verifyScript;
      timeout = 3600;
      memoryMiB = 4096;
      varSizeMiB = 8192;
    }
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-translation-prefetch-neutrality";
      version = "0";
      buildDeps = [pkgs.coreutils pkgs.grep productionPluginFlight];

      phases = [
        {
          name = "verify-translation-prefetch-neutrality";
          script = verifyScript;
        }
      ];
    }
