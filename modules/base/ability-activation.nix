##! Deployment inputs for structured ability activation.
{
  lib,
  ...
}: {
  options.aos.abilities.activationInput = lib.mkOption {
    type = lib.types.nullOr lib.types.attrs;
    default = null;
    description = ''
      Immutable desired-state and authenticated-policy sidecars used to plan
      structured ability effects. The on-host evaluator replaces package
      coordinates from the authenticated runtime resolution and validates the
      complete activation input before publishing a configuration generation.
    '';
  };
}
