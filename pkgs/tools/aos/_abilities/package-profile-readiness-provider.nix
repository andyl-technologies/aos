##! Publishes the package-owned profile convergence lifecycle resource.
{packageName, ...}: let
  alias = "package-profile-readiness";
  lifecycleRequest = "${packageName}:package-profile-convergence-lifecycle";
  emptyProvision = {
    requests = {};
    resourceFragments = {};
  };
  provide = {
    planningOutputs,
    requests,
    ...
  }: let
    lifecycleOutput =
      planningOutputs.${lifecycleRequest}.resource
      or (throw "package-profile readiness requires the convergence lifecycle planning output");
  in
    emptyProvision
    // {
      outputs = builtins.mapAttrs (_: _: {resource = lifecycleOutput.value;}) requests;
    };
in {
  config.aos.abilities.implementations.${alias}.provide = provide;
}
