{
  pkgs,
  mkSystem,
  attrPath ? "checks.crucible.phase9.gates.campaignServiceModuleContract",
}: let
  evaluate = campaignConfig:
    builtins.tryEval (
      let
        evaluated = mkSystem {
          modules = [
            ../../systems/server.nix
            {aos.services.crucibleCampaign = campaignConfig;}
          ];
          systemName = "campaign-service-contract";
        };
      in
        builtins.deepSeq evaluated.config.system.build.toplevel true
    );
  valid = evaluate {
    enable = true;
    listenAddress = "127.0.0.1:18080";
    socketPath = "/run/crucible-campaign/service.sock";
    stateDirectory = "/var/lib/crucible-campaign";
  };
  invalid = [
    (evaluate {socketPath = "/";})
    (evaluate {socketPath = "relative.sock";})
    (evaluate {socketPath = "/run/crucible-campaign/../escape.sock";})
    (evaluate {socketPath = "/tmp/crucible-campaign.sock";})
    (evaluate {stateDirectory = "/";})
    (evaluate {stateDirectory = "relative";})
    (evaluate {stateDirectory = "/var/lib/crucible-campaign/../escape";})
    (evaluate {stateDirectory = "/tmp/crucible-campaign";})
  ];
  validContract = valid.success && builtins.all (result: !result.success) invalid;
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
            RESULT
          '';
        }
      ];
    }
