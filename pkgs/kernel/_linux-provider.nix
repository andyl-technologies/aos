##! Checked planning output for the selected Linux kernel artifact.
{
  artifactLocatorFor ? selector: throw "Linux kernel provider has no authenticated locator for ${builtins.toJSON selector}",
  lib,
  ...
}: let
  selectedKernelReference = {
    _type = "aos-artifact-reference";
  }
  // (artifactLocatorFor (lib.abilities.packageOutput {})).artifactReference;
  provide = context: {
    requests = {};
    outputs = builtins.mapAttrs (_: _: {
      selected-kernel = selectedKernelReference;
    }) context.requests;
  };
in {
  config.aos.abilities.implementations.kernel.provide = provide;
}
