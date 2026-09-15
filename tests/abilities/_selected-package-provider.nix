##! Resolves a package provider through its public contract and output.
{
  lib,
  package,
  implementation,
}: let
  provider =
    lib.findFirst
    (candidate: candidate.name == implementation)
    (throw "${package.pname} package contract does not expose the ${implementation} provider")
    package.contract.value.implementation.providers;
  locator =
    provider.provider_module
    or (throw "${package.pname}:${implementation} has no provider module locator");
  selectedOutput =
    if locator.artifact.package != package.pname
    then throw "${package.pname}:${implementation} selects another package's provider module"
    else package.${locator.artifact.output}
      or (throw "${package.pname}:${implementation} selects an absent package output");
  root = builtins.toString selectedOutput;
in {
  name = package.pname;
  packageVersion = package.version;
  configRoot = root;
  module = "${root}/${locator.path}";
  outputs = {
    self = root;
    dependencies = {};
  };
  artifactLocators = {};
}
