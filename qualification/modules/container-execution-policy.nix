##! Declares execution-stage qualification evidence and open blockers.
{
  config,
  lib,
  ...
}: let
  types = import ./_types.nix {inherit lib;};
  stagePolicy = types.closed {
    scope = types.text "Package-declared execution scope that implements this stage.";
    status = types.option (lib.types.enum ["missing" "qualified"]) "Qualification disposition for this stage.";
    blockers = (types.strings "Open work that prevents qualification.") // {default = [];};
    evidence = (types.strings "Production checks that provide qualification evidence.") // {default = [];};
  };
in {
  options.qualification.containerExecution.stages = lib.mkOption {
    type = lib.types.attrsOf stagePolicy;
    default = {};
    description = "Execution-stage evidence policy resolved against selected package declarations.";
  };

  config.qualification = {
    containerExecution.stages = {
      application-container = {
        scope = "application-container-process";
        status = "qualified";
        evidence = ["checks.fleet.ability-native-foreground-container"];
      };
      host = {
        scope = "host-manager";
        status = "qualified";
        evidence = ["checks.fleet.runtime-module-composition"];
      };
      system-container = {
        scope = "host-manager";
        status = "missing";
        blockers = [
          "pr232-authenticated-backend-readiness"
          "pr232-broker-host-apply"
          "pr232-resource-view-lease-handoff"
          "pr232-shifted-payload-pid-namespace-proof"
          "pr232-scoped-local-manager-endpoint"
          "pr232-durable-lifecycle-observation-evidence"
        ];
      };
    };

    assertions = [
      {
        assertion = builtins.all (stage: let
          policy = config.qualification.containerExecution.stages.${stage};
        in
          if policy.status == "qualified"
          then policy.blockers == [] && policy.evidence != []
          else policy.blockers != [] && policy.evidence == [])
        (builtins.attrNames config.qualification.containerExecution.stages);
        message = "Container execution stages must pair qualified status with evidence and missing status with blockers.";
      }
    ];
  };
}
