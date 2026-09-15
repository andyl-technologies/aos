##! Selects the package-owned fleet execution observer in test systems.
{
  lib,
  pkgs,
  external ? false,
  forwardEndpoint ? null,
}: let
  package = pkgs.aos-ability-boundary-observer;
  mode =
    if external
    then "external-test-mount"
    else "managed-service";
  forwardSocket =
    if forwardEndpoint == null
    then null
    else lib.abilities.resultOf forwardEndpoint.request forwardEndpoint.socketOutput;
  forwardPrerequisites =
    if forwardEndpoint == null
    then []
    else [
      (lib.abilities.resultOf forwardEndpoint.request forwardEndpoint.resourceOutput)
    ];
  observerConfig = {
    enable = true;
    inherit mode forwardSocket forwardPrerequisites;
  };
  forwardHostConfig =
    if forwardEndpoint == null
    then ''
      aos.tests.executionObserver.forwardSocket = null;
      aos.tests.executionObserver.forwardPrerequisites = [];
    ''
    else ''
      aos.tests.executionObserver.forwardSocket = lib.abilities.resultOf \
        ${builtins.toJSON forwardEndpoint.request} \
        ${builtins.toJSON forwardEndpoint.socketOutput};
      aos.tests.executionObserver.forwardPrerequisites = [
        (lib.abilities.resultOf
          ${builtins.toJSON forwardEndpoint.request}
          ${builtins.toJSON forwardEndpoint.resourceOutput})
      ];
    '';
in {
  inherit package;
  controller = package;

  module = {
    environment.systemPackages = [package];
    aos.tests.executionObserver = observerConfig;
    aos.abilities.executionObserver = {
      request = "aos-ability-boundary-observer:endpoint";
      resourceOutput = "retained-resource";
      socketOutput = "socket-path";
    };
    aos.abilities.bindings."fleet-observer:endpoint" = {
      request = "aos-ability-boundary-observer:endpoint";
      implementation = "aos-ability-boundary-observer:execution-observer-endpoint";
      providerInstance = "aos-ability-boundary-observer:boundary-observer";
      slot = "observer";
    };
  };

  hostModule = ''
    aos.apm.desiredPackages = lib.mkAfter [ "aos-ability-boundary-observer" ];
    aos.tests.executionObserver.enable = true;
    aos.tests.executionObserver.mode = ${builtins.toJSON mode};
    aos.abilities.executionObserver = {
      request = "aos-ability-boundary-observer:endpoint";
      resourceOutput = "retained-resource";
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
