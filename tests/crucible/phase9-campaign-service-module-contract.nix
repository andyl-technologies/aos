{
  pkgs,
  mkSystem,
  attrPath ? "checks.crucible.phase9.gates.campaignServiceModuleContract",
}: let
  processResources = import ./campaign-process-resources-fixture.nix;
  evaluate = campaignConfig:
    builtins.tryEval (
      let
        evaluated = mkSystem {
          modules = [
            ../../systems/server.nix
            ./_campaign-service-module-contract-input.nix
          ];
          specialArgs.campaignServiceContractInput = campaignConfig;
          systemName = "campaign-service-contract";
        };
      in
        builtins.deepSeq evaluated.config.system.build.toplevel true
    );
  valid = evaluate {
    inherit processResources;
    enable = true;
    listenAddress = "127.0.0.1:18080";
    socketPath = "/run/crucible-campaign/service.sock";
    stateDirectory = "/var/lib/crucible-campaign";
  };
  invalid = [
    (evaluate {enable = true;})
    (evaluate {
      enable = true;
      processResources = processResources // {sqliteHeapBytes = processResources.memoryMaxBytes;};
    })
    (evaluate {
      enable = true;
      processResources = processResources // {blockingThreads = processResources.tasksMax;};
    })
    (evaluate {listenAddress = "0.0.0.0:18080";})
    (evaluate {listenAddress = "localhost:18080";})
    (evaluate {listenAddress = "127.0.0.1:0";})
    (evaluate {listenAddress = "127.0.0.1:65536";})
    (evaluate {listenAddress = "127.0.0.1:18080\nextra";})
    (evaluate {socketPath = "/";})
    (evaluate {socketPath = "relative.sock";})
    (evaluate {socketPath = "/run/crucible-campaign/../escape.sock";})
    (evaluate {socketPath = "/tmp/crucible-campaign.sock";})
    (evaluate {stateDirectory = "/";})
    (evaluate {stateDirectory = "relative";})
    (evaluate {stateDirectory = "/var/lib/crucible-campaign/../escape";})
    (evaluate {stateDirectory = "/tmp/crucible-campaign";})
  ];
  configuration = executor:
    (mkSystem {
      modules = [
        ../../systems/server.nix
        ./_campaign-service-module-contract-input.nix
      ];
      specialArgs.campaignServiceContractInput = {
        inherit processResources executor;
        enable = true;
      };
      systemName = "campaign-service-contract-projection";
    }).config;
  ordinary = configuration null;
  # Evaluation-only documents exercise the emitted contract. They are never
  # parsed by a live executor and issue no Native, Main or resource authority.
  normal = configuration {
    deploymentFile = builtins.toFile "module-contract-executor.toml" "schema = \"module-contract-input-only\"\n";
    socketPath = "/run/crucible-campaign/executor.sock";
    campaigns = ["normal-ram"];
    userfaultfdGroupId = 29000;
    componentAuthorityFile = "/etc/crucible/module-contract-authority.bin";
    importManifests = ["/etc/crucible/module-contract-import.toml"];
    transport = {
      serverCertificateFile = "/etc/crucible/server.pem";
      serverKeyFile = "/etc/crucible/server.key";
      clientCaFile = "/etc/crucible/ca.pem";
      operatorCertificateFingerprints = ["0000000000000000000000000000000000000000000000000000000000000000"];
    };
    guestAssets = {
      qemu = "${pkgs.crucible.passthru.qemu}/bin/qemu-system-x86_64";
      plugin = "${pkgs.crucible.passthru.plugin}/lib/libcrucible_qemu_plugin.so";
      kernel = "/etc/crucible/module-contract-kernel";
      rootImage = "/etc/crucible/module-contract-root";
      initrd = "/etc/crucible/module-contract-initrd";
      architecture = "x86_64";
      kernelCommandLine = "";
      runStateRoot = "/var/lib/crucible-campaign/run";
    };
  };
  # Parse exact generated text without treating its package references as parser
  # authority. The production files and service keep their store dependencies.
  processPolicy = configured:
    builtins.fromTOML (builtins.unsafeDiscardStringContext configured.environment.etc."crucible/campaign-process.toml".text);
  campaignPolicy = configured:
    builtins.fromTOML (builtins.unsafeDiscardStringContext configured.environment.etc."crucible/campaign-policy.toml".text);
  actualMainElf = "${pkgs.crucible.passthru.controller}/bin/crucible";
  retainsSuiteLaunch = configured:
    builtins.match (builtins.unsafeDiscardStringContext "(.|\n)*exec ${pkgs.crucible}/bin/crucible serve(.|\n)*")
    configured.systemd.services.crucible-campaign.script
    != null;
  extraOperations = ["get-campaign-status" "apply-campaign-command" "explain-campaign-attempt"];
  extraGrants =
    builtins.filter (grant: builtins.elem grant.operation extraOperations)
    (campaignPolicy normal).grants;
  scopedOperatorGrants =
    builtins.length extraGrants
    == builtins.length extraOperations
    && builtins.all (grant: grant.principal == "operator" && grant.campaign == "normal-ram") extraGrants
    && builtins.all (operation: builtins.any (grant: grant.operation == operation) extraGrants) extraOperations;
  ordinaryPolicyUnchanged =
    (campaignPolicy ordinary).grants
    == [
      {
        principal = "operator";
        operation = "list-campaigns";
        campaign = "*";
      }
      {
        principal = "operator";
        operation = "get-campaign";
        campaign = "*";
      }
      {
        principal = "operator";
        operation = "create-campaign";
        campaign = "*";
      }
      {
        principal = "operator";
        operation = "attach-campaign-runtime";
        campaign = "*";
      }
    ];
  identityContract =
    (processPolicy ordinary).executable
    == actualMainElf
    && (processPolicy normal).executable == actualMainElf
    && retainsSuiteLaunch ordinary
    && retainsSuiteLaunch normal;
  validContract =
    valid.success
    && builtins.all (result: !result.success) invalid
    && identityContract
    && scopedOperatorGrants
    && ordinaryPolicyUnchanged;
in
  if !validContract
  then throw "Crucible campaign service path contract accepted an unsafe configuration"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase9-campaign-service-module-contract";
      version = "0";
      src = null;
      phases = [
        {
          name = "record-contract";
          script = ''
            mkdir -p "$out"
            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            loopback_only=true
            runtime_values_control_free=true
            socket_path_service_owned=true
            state_directory_service_owned=true
            main_identity_is_selected_controller_elf=true
            suite_wrapper_launch_preserved=true
            normal_operator_grants_campaign_scoped=true
            ordinary_operator_policy_unchanged=true
            RESULT
          '';
        }
      ];
    }
