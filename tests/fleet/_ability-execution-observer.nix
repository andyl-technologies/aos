##! Selects an explicit native observer endpoint in admitted test configuration.
{
  lib,
  pkgs,
  external ? false,
  forwardToCrucible ? false,
  crucibleSocket ? "/run/aos/ability-crucible/controller.sock",
}: let
  package = pkgs.aos-ability-boundary-observer;
  settings = import ../../pkgs/tests/_aos-ability-boundary-observer/settings.nix;
  observerConfig = {
    enable = true;
    activationOwner = "manager";
    mode =
      if external
      then "external-test-mount"
      else "managed-service";
    forwardSocketPath =
      if forwardToCrucible
      then crucibleSocket
      else null;
  };
  asNix = value: "builtins.fromJSON ${builtins.toJSON (builtins.toJSON value)}";
  source = builtins.toFile "aos-execution-observer-policy.nix" ''
    { ... }: {
      aos.tests.executionObserver = ${asNix observerConfig};
    }
  '';
in {
  inherit package settings source;
  controller = package;
  module = {
    aos.packages.aos-ability-boundary-observer = {
      inherit package;
      bundle = true;
    };
    aos.activation.stages.host.configuration = [source];
  };
  hostModule = ''
    imports = [ ${builtins.toJSON (builtins.toString source)} ];
  '';
}
