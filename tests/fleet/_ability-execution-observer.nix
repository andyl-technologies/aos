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
  forwardHostConfig =
    if !forwardToCrucible
    then ''
      aos.tests.executionObserver.forwardToSelectedEndpoint = false;
    ''
    else ''
      aos.tests.executionObserver.forwardToSelectedEndpoint = true;
      aos.abilities.bindings."fleet-observer:forward-endpoint" = {
        request = "aos-ability-boundary-observer:forward-endpoint";
        implementation = "aos-ability-crucible:execution-observer-endpoint";
        providerInstance = "aos-ability-crucible:ability-crucible";
        slot = "forward-observer";
      };
    '';
in {
  inherit package;
  controller = package;

  module = {
    environment.systemPackages = [package];
    aos.tests.executionObserver = observerConfig;
    aos.abilities.executionObserver = {
      request = "aos-ability-boundary-observer:endpoint";
      resourceOutput = "resource";
      socketOutput = "socket-path";
    };
    aos.abilities.bindings =
      {
        "fleet-observer:endpoint" = {
          request = "aos-ability-boundary-observer:endpoint";
          implementation = "aos-ability-boundary-observer:execution-observer-endpoint";
          providerInstance = "aos-ability-boundary-observer:boundary-observer";
          slot = "observer";
        };
      }
      // lib.optionalAttrs forwardToCrucible {
        "fleet-observer:forward-endpoint" = {
          request = "aos-ability-boundary-observer:forward-endpoint";
          implementation = "aos-ability-crucible:execution-observer-endpoint";
          providerInstance = "aos-ability-crucible:ability-crucible";
          slot = "forward-observer";
        };
      };
  };

  hostModule = ''
    aos.apm.desiredPackages = lib.mkAfter [ "aos-ability-boundary-observer" ];
    aos.tests.executionObserver.enable = true;
    aos.tests.executionObserver.mode = ${builtins.toJSON mode};
    aos.abilities.executionObserver = {
      request = "aos-ability-boundary-observer:endpoint";
      resourceOutput = "resource";
      socketOutput = "socket-path";
    };
    aos.abilities.bindings."fleet-observer:endpoint" = {
      request = "aos-ability-boundary-observer:endpoint";
      implementation = "aos-ability-boundary-observer:execution-observer-endpoint";
      providerInstance = "aos-ability-boundary-observer:boundary-observer";
      slot = "observer";
    };
    ${forwardHostConfig}
  '';
}
