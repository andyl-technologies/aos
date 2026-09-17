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
    aos.services.abilityCrucible.enable = true;
    aos.abilities.bindings."ability-crucible:observer-endpoint" = {
      request = "aos-ability-crucible:observer-endpoint";
      implementation = "aos-ability-crucible:execution-observer-endpoint";
      providerInstance = "aos-ability-crucible:ability-crucible";
      slot = "observer";
    };
    aos.abilities.executionObserver = lib.mkDefault {
      request = "aos-ability-crucible:observer-endpoint";
      resourceOutput = "resource";
      socketOutput = "socket-path";
    };
  };
}
