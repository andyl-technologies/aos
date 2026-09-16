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
  packageOutputs = package.outputs or ["out"];
  root =
    if
      locator.artifact.package == package.pname
      && builtins.elem locator.artifact.output packageOutputs
      && builtins.readFileType package.module.evaluation.configRoot == "directory"
    then
      package.module.evaluation.configRoot
      or (throw "${package.pname}:${implementation} has no evaluator module root")
    else throw "${package.pname}:${implementation} selects a non-canonical provider module output";
in {
  name = package.pname;
  version = package.version;
  configRoot = root;
  module = root + "/${locator.path}";
  outputs = {
    self = builtins.toString package;
    dependencies = {};
  };
}
