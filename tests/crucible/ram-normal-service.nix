# Runs the authored service module and client in the same disposable kernel VM.
# The semantic and test-PKI inputs grant no native resource authority. Actual
# native support refusal remains a test failure before controls.
{
  pkgs,
  lib,
  mkSystem,
  attrPath,
  serviceModule,
  fixtureInputs,
  campaign,
  attemptFile,
  clientAuthorityFile,
  clientCertificateFile,
  clientKeyFile,
  idempotencyKey,
  preparation,
  inputDependencies,
  nativeQemu ? pkgs.qemu-crucible,
  nativePlugin ? pkgs.crucible-qemu-plugin,
}: let
  system = mkSystem {
    modules = [../../systems/server.nix serviceModule];
    specialArgs.normalServiceFixtureInputs = fixtureInputs;
    systemName = "normal-managed-ram-kernel";
  };
  normalServiceConfig = system.config;
  service = normalServiceConfig.aos.crucibleCampaign;
  client = import ./_ram-normal-service-client.nix {
    inherit pkgs lib service campaign attemptFile;
    inherit clientAuthorityFile clientCertificateFile clientKeyFile idempotencyKey;
  };
  clientScript = pkgs.writeTextFile {
    name = "normal-service-ram-client";
    text = client;
  };
in
  assert service.enable && service.executor != null;
  assert builtins.elem campaign service.executor.campaigns;
  assert service.executor.guestAssets.qemu == "${nativeQemu}/bin/qemu-system-x86_64";
  assert service.executor.guestAssets.plugin == "${nativePlugin}/lib/libcrucible_qemu_plugin.so";
    import ./ram-native-flight.nix {
      inherit pkgs lib attrPath nativeQemu nativePlugin normalServiceConfig;
      pname = "crucible-normal-managed-ram-kernel-flight";
      gateId = "gate:normal-service-ram-control";
      testName = "";
      successMarker = "NORMAL_SERVICE_RAM_CONTROL_PASS";
      lanes = ["resident" "paged"];
      outerCpuSlots = 4;
      outerMemoryMiB = 4096;
      evidencePrefix = "normal_service";
      innerPreparation = preparation;
      innerInvocation = _: "${pkgs.bash}/bin/bash ${clientScript}";
      extraRootfsDeps = inputDependencies ++ [clientScript pkgs.jq pkgs.sed];
      innerEvidence = {buildGraph}: ''
        echo normal_service_build_graph=${buildGraph}
        echo normal_service_main_elf=${pkgs.crucible.passthru.controller}/bin/crucible
      '';
      outerEvidence = _: ''
        for observation in \
          normal_service_main_client_authenticated=true \
          normal_service_stale_target_refused=true \
          normal_service_policy_retry_same_request=true; do
          test "$(${pkgs.grep}/bin/grep -Fxc "$observation" "$out/serial.log")" -eq 1
        done
      '';
    }
