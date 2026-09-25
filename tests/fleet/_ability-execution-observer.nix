##! Selects the package-owned fleet execution observer in test systems.
{
  lib,
  pkgs,
  external ? false,
  forwardToCrucible ? false,
}: let
  package = pkgs.aos-ability-boundary-observer;
  mode =
    if external
    then "external-test-mount"
    else "managed-service";
  observerConfig = {
    enable = true;
    inherit mode;
    forwardToSelectedEndpoint = forwardToCrucible;
  };
  endpointRequest = {
    request = "aos-ability-boundary-observer:endpoint";
    resourceOutput = "resource";
    socketOutput = "socket-path";
  };
  endpointBinding = {
    inherit (endpointRequest) request;
    implementation = "aos-ability-boundary-observer:execution-observer-endpoint";
    providerInstance = "aos-ability-boundary-observer:boundary-observer";
    slot = "observer";
  };
  forwardBinding = {
    request = "aos-ability-boundary-observer:forward-endpoint";
    implementation = "aos-ability-crucible:execution-observation-endpoint";
    providerInstance = "aos-ability-crucible:ability-crucible";
    slot = "forward-observer";
  };
  bindings =
    {"fleet-observer:endpoint" = endpointBinding;}
    // lib.optionalAttrs forwardToCrucible {
      "fleet-observer:forward-endpoint" = forwardBinding;
    };
  hostSettings = {
    aos.tests.executionObserver = observerConfig;
    aos.abilities.executionObserver = endpointRequest;
    aos.abilities.bindings = bindings;
  };
  asNix = value: "builtins.fromJSON ${builtins.toJSON (builtins.toJSON value)}";
in {
  inherit package;
  controller = package;

  module = {
    aos.packages.aos-ability-boundary-observer = {
      inherit package;
      bundle = true;
    };
    aos.abilities.stages.host.modules = [hostSettings];
  };

  hostModule = ''
    aos.apm.desiredPackages = lib.mkAfter [ "aos-ability-boundary-observer" ];
    aos.tests.executionObserver = ${asNix observerConfig};
    aos.abilities.executionObserver = ${asNix endpointRequest};
    aos.abilities.bindings = ${asNix bindings};
  '';
}
