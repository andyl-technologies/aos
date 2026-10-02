##! Enables the selected host firewall without imposing policy on its primitive contract.
{
  config,
  options,
  lib,
  ...
}: {
  config = lib.mkIf ((config.aos.boot.stage or "host") == "host") (
    lib.optionalAttrs (options.aos ? networkPolicy) {
      # Security presets and operator policy take precedence over the host default.
      aos.networkPolicy.enable = lib.mkOverride 1500 true;
    }
  );
}
