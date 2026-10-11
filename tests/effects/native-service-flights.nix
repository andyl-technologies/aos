##! Checks that service flights consume concrete native resources and dependencies.
let
  lib = import ../../lib {system = "x86_64-linux";};
  package = {
    type = "derivation";
    name = "native-flight-payload";
    outPath = toString (import ./_fixture-payload.nix "native-flight-payload");
    meta.mainProgram = "native-flight-payload";
  };
  controlled = ../abilities/native-service-qualification/module/module.nix;
  evaluate = extra:
    lib.evalModules {
      inherit lib;
      specialArgs = {inherit package;};
      modules = [
        ../../lib/effects/module.nix
        ../../pkgs/system/_service-management/module.nix
        ../../pkgs/filesystem/_aos-filesystem-provider/module.nix
        controlled
        {
          aos.abilities = {
            serviceManagement.operations.realize.handler.program = package;
            identity.operations = lib.genAttrs ["group" "principal" "membership"] (_: {handler.program = package;});
          };
        }
        extra
      ];
    };
  original = evaluate {};
  absent = evaluate {aos.nativeServiceQualification.enabled = lib.genAttrs ["service" "group" "principal" "membership"] (_: false);};
  dependency = evaluate {
    imports = [../abilities/native-dependency-barrier/module/module.nix ../fleet/_native-service-dependency.nix];
  };
  dependencyNodes = builtins.attrValues dependency.config.aos.activation.graph.nodes;
  dependencySelect = ability: operation: instance: builtins.head (builtins.filter
    (node: lib.drop (builtins.length node.identity - 3) node.identity == [ability operation instance]) dependencyNodes);
  dependencyPairs = [
    {control = "service"; ability = "serviceManagement"; operation = "realize";}
    {control = "group"; ability = "identity"; operation = "group";}
    {control = "principal"; ability = "identity"; operation = "principal";}
    {control = "membership"; ability = "identity"; operation = "membership";}
  ];
  baseline = evaluate ../fleet/_native-service-baseline.nix;
  baselineNodes = builtins.attrValues baseline.config.aos.activation.graph.nodes;
  originalNodes = builtins.attrValues original.config.aos.activation.graph.nodes;
  absentNodes = builtins.attrValues absent.config.aos.activation.graph.nodes;
  select = ability: operation: instance: builtins.head (builtins.filter (node: lib.drop (builtins.length node.identity - 3) node.identity == [ability operation instance]) originalNodes);
  process = select "serviceManagement" "realize" "native-service-qualification";
  membership = select "identity" "membership" "native-service-qualification";
  deadline = select "serviceManagement" "realize" "native-service-deadline";
  deadlineRemove = select "serviceManagement" "realize" "native-service-deadline-remove";
  foreign = select "identity" "membership" "native-service-foreign";
in {
  actualParentAndSuccessorEdgesCoverEveryControlledOperation = builtins.all (pair: let
    selected = dependencySelect pair.ability pair.operation "native-service-qualification";
    parent = dependencySelect "nativeDependencyBarrier" "ensure" "${pair.control}-parent";
    child = dependencySelect "nativeDependencyBarrier" "ensure" "${pair.control}-child";
  in builtins.elem (builtins.hashString "sha256" (builtins.toJSON parent.identity)) selected.dependencies
    && builtins.elem (builtins.hashString "sha256" (builtins.toJSON selected.identity)) child.dependencies) dependencyPairs;
  foreignMarkerHasNoSelectedDependency =
    (dependencySelect "nativeDependencyBarrier" "ensure" "foreign-marker").dependencies == [];
  deadlineCommandsRemainBoundedByNativeInvocation =
    deadline.input.lifecycle.execution_model == "oneshot"
    && deadline.input.lifecycle.start_timeout_unbounded
    && deadlineRemove.input.lifecycle.stop_timeout_unbounded
    && deadline.timeout_ms > 0
    && deadlineRemove.timeout_ms > 0;
  deadlineRemovalRunsActualPinnedStopCommand =
    (builtins.head deadlineRemove.input.lifecycle.stop).executable.arguments == ["deadline-stop"];
  bootBaselineNeverStartsBlockingServices =
    !(builtins.any (node: builtins.elem "native-service-deadline" node.identity || builtins.elem "native-service-deadline-remove" node.identity) baselineNodes);
  selectedServiceRunsActualPinnedCommand =
    process.input.lifecycle.start
    == [
      {
        executable = {
          path = "${package}/bin/native-service-qualification";
          arguments = ["selected"];
        };
        ignore_failure = false;
      }
    ];
  serviceConsumesActualDirectory = process.dependencies != [];
  selectedMembershipHasPrincipalDependency = builtins.length membership.dependencies == 2;
  foreignMembershipHasSeparatePrincipalDependency = foreign.dependencies != membership.dependencies;
  controlledEffectsCanDisappear = !(builtins.any (node: builtins.elem "native-service-qualification" node.identity && (builtins.elem "identity" node.identity || builtins.elem "serviceManagement" node.identity)) absentNodes);
  foreignResourcesRemainSelected = builtins.any (node: builtins.elem "native-service-foreign" node.identity && builtins.elem "realize" node.identity) absentNodes;
}
