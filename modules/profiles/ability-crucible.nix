##! Optional RFC-0022 baseline Crucible instrumentation profile.
##!
##! The profile connects the ordinary native ability executor's protected
##! boundary observer to generic Crucible guest markers. It is disabled by
##! default and does not provide typed choices, structured measurements, or an
##! exact marker-synchronized interruption facility.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.profiles.abilityCrucible;
  socket = "/run/aos-instrumentation/controller.sock";
  observerConfig = builtins.toJSON {
    schema = "aos.ability-execution-observer/v1";
    inherit socket;
  };
  adapterConfig = builtins.toJSON {
    schema = "aos.ability-crucible-adapter/v1";
    inherit socket;
    ready_command = "${pkgs.systemd}/bin/systemd-notify";
    required_instruction_abi = 1;
    required_marker_kinds = [
      "assertion"
      "coverage"
      "event"
      "lifecycle"
    ];
  };
in {
  options.aos.profiles.abilityCrucible.enable = lib.mkOption {
    type = lib.types.bool;
    default = false;
    description = ''
      Enable the baseline AOS guest adapter for a Crucible test environment.
      The profile emits existing generic guest markers from the production
      ability executor and fails activation when required marker delivery or
      acknowledgement fails. It does not enable PR #194 campaign features.
    '';
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [pkgs.aos-ability-crucible];

    environment.etc = {
      "aos/ability-crucible-adapter.json" = {
        text = adapterConfig;
        mode = "0444";
      };
      "aos/ability-execution-observer.json" = {
        text = observerConfig;
        mode = "0444";
      };
    };

    systemd.services = {
      aos-ability-crucible = {
        description = "Publish AOS ability boundaries to Crucible";
        requiredBy = ["aos-activate.service"];
        before = ["aos-activate.service"];
        serviceConfig = {
          Type = "notify";
          NotifyAccess = "all";
          RuntimeDirectory = "aos-instrumentation";
          RuntimeDirectoryMode = "0700";
          Restart = "on-failure";
          RestartSec = "1s";
          TimeoutStartSec = "30s";
          ProtectSystem = "strict";
          ProtectHome = true;
          PrivateTmp = true;
          UMask = "0077";
          ReadWritePaths = ["/run/aos-instrumentation"];
        };
        script = ''
          exec ${pkgs.aos-ability-crucible}/bin/aos-ability-crucible \
            --config /etc/aos/ability-crucible-adapter.json
        '';
      };

      aos-activate = {
        requires = ["aos-ability-crucible.service"];
        after = ["aos-ability-crucible.service"];
      };
    };
  };
}
