##! Checks that service flights consume concrete native resources and dependencies.
let
  lib = import ../../lib {system = "x86_64-linux";};
  package = {
    type = "derivation";
    name = "native-flight-payload";
    outPath = toString (import ./_fixture-payload.nix "native-flight-payload");
    meta.mainProgram = "native-flight-payload";
  };
  controlled = import ../fleet/_native-reference-service-configuration.nix {
    bash = package;
    coreutils = package;
  };
  evaluate = extra: lib.evalModules {
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
  originalNodes = builtins.attrValues original.config.aos.activation.graph.nodes;
  absentNodes = builtins.attrValues absent.config.aos.activation.graph.nodes;
  select = ability: operation: instance: builtins.head (builtins.filter (node: lib.drop (builtins.length node.identity - 3) node.identity == [ability operation instance]) originalNodes);
  process = select "serviceManagement" "realize" "native-service-qualification";
  membership = select "identity" "membership" "native-service-qualification";
  foreign = select "identity" "membership" "native-service-foreign";
in {
  selectedServiceRunsActualPinnedCommand = process.input.lifecycle.start == [{
    executable = {
      path = "${package}/bin/bash";
      arguments = ["-c" "printf 'invoked\\n' >> /var/lib/aos/native-service-qualification/selected.invocations; exec ${package}/bin/sleep infinity"];
    };
    ignore_failure = false;
  }];
  serviceConsumesActualDirectory = process.dependencies != [];
  selectedMembershipHasPrincipalDependency = builtins.length membership.dependencies == 2;
  foreignMembershipHasSeparatePrincipalDependency = foreign.dependencies != membership.dependencies;
  controlledEffectsCanDisappear = !(builtins.any (node: builtins.elem "native-service-qualification" node.identity && (builtins.elem "identity" node.identity || builtins.elem "serviceManagement" node.identity)) absentNodes);
  foreignResourcesRemainSelected = builtins.any (node: builtins.elem "native-service-foreign" node.identity && builtins.elem "realize" node.identity) absentNodes;
}
