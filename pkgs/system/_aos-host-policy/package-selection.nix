##! Declares host-selected package requirements before module resolution.
##!
##! Declares the small package-name seed that must be known before registry
##! config modules can be resolved. The stage-2 evaluator reads this projection
##! from authenticated host.nix first, resolves those packages, then evaluates
##! the complete runtime configuration fixpoint.
{lib, ...}: {
  options.aos.apm.desiredPackages = lib.mkOption {
    type = lib.types.listOf (lib.types.strMatching "[A-Za-z0-9][A-Za-z0-9+._=-]*");
    default = [];
    extensible = true;
    description = ''
      Registry package names selected by host.nix. This list seeds the on-host
      config-module fixpoint; package derivations never appear in host policy.
    '';
  };
}
