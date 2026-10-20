##! Bounded package output and execution-platform assembly invariants.
{
  lib,
  pkgs,
}: let
  probe = pkgs.mkDerivation {
    pname = "native-named-output-probe";
    version = "1";
    src = null;
    outputs = ["out" "dev"];
    propagatedDeps = [pkgs.pcre2];
    phases = [];
  };
  derivations = import ../../lib/derivations.nix {system = "x86_64-linux";};
  executable = cpu:
    derivations.mkDerivation {
      pname = "native-build-execution-probe";
      buildExecutionSystem = "aarch64-linux";
      meta.execute = {
        inherit cpu;
        os = "linux";
      };
    };
  compatible = builtins.tryEval (executable "aarch64");
  schedulingOnly = builtins.tryEval (executable "x86_64");
in {
  namedOutputDependencies = assert map builtins.toString probe.dev.propagatedDeps == [(builtins.toString pkgs.pcre2)]; true;
  namedOutputIdentity = assert probe.dev.pname == probe.pname; assert probe.dev.deployment.package.path == toString probe.dev; assert probe.deployment.package.path == toString probe; assert probe.dev.deployment.package.outputs == probe.deployment.package.outputs; assert probe.dev.deploymentArtifact != probe.deploymentArtifact; true;
  buildExecutionIdentity = assert compatible.success; assert !schedulingOnly.success; true;
}
