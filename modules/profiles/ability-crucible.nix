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
    aos.packages.aos-ability-crucible = {
      package = pkgs.aos-ability-crucible;
      bundle = true;
    };
    aos.activation.stages.host.configuration = [
      (builtins.path {
        path = ./_ability-crucible-enable.nix;
        name = "aos-ability-crucible-policy.nix";
      })
    ];
  };
}
