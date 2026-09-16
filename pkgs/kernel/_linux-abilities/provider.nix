##! Checked planning output for the selected Linux kernel artifact.
{lib, ...}: let
  selectedKernel = lib.abilities.packageOutput {};
  provide = context: {
    requests = {};
    resourceFragments = {};
    outputs =
      builtins.mapAttrs (_: _: {
        selected-kernel = selectedKernel;
      })
      context.requests;
  };
in {
  config.aos.abilities.implementations.kernel.provide = provide;
}
