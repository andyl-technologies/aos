##! Preserves systemd's former one-month journal retention default.
let
  lib = import ../../lib {system = "x86_64-linux";};
  evaluate = overrides:
    lib.evalModules {
      inherit lib;
      modules = [
        ../../lib/effects/module.nix
        ../../pkgs/system/_service-management/configuration.nix
        ../../pkgs/system/_aos-host-policy/journald.nix
        ../../pkgs/system/_systemd-abilities/journald-policy.nix
        overrides
      ];
    };
  defaults = evaluate {};
  overridden = evaluate {aos.journald.maxRetentionSeconds = 86400;};
  journal = evaluated: evaluated.config.aos.journald.files."systemd/journald.conf".text;
in {
  oneMonthDefault = defaults.config.aos.journald.maxRetentionSeconds == 2629800;
  backendPreservesOneMonth = lib.hasInfix "MaxRetentionSec=2629800s\n" (journal defaults);
  explicitRetentionPreserved = lib.hasInfix "MaxRetentionSec=86400s\n" (journal overridden);
}
