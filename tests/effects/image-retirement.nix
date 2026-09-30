##! Keeps historical boot leases until an explicit native retirement request is committed.
let
  repo = ../..;
  lib = import (repo + /lib) {system = "x86_64-linux";};
  payload = import ./_fixture-payload.nix;
  package.packageRuntime = {
    type = "derivation";
    name = "image-runtime-fixture";
    outPath = payload "image-runtime";
    meta.mainProgram = "unused";
  };
  image = name: {
    toplevel = toString (payload name);
    boot-artifact-contract = toString (payload "${name}-boot");
    executor = toString (payload "executor");
    state-format = "1";
  };
  rollout = {
    predecessor = image "first";
    candidate = image "second";
    retention-expires-at-millis = 100;
  };
  evaluate = policy:
    lib.evalModules {
      inherit lib;
      specialArgs = {inherit package;};
      modules = [
        (repo + /lib/effects/module.nix)
        (repo + /pkgs/tools/aos/_abilities/configuration-provider/module.nix)
        {
          aos.activation.scope = ["profile" "system"];
          aos.imageRollout =
            policy
            // {
              platformExecutable = "${payload "systemd"}/bin/aos-systemd-boot-platform";
            };
        }
      ];
    };
  initial = evaluate {};
  selected = evaluate {requests = [{inherit rollout;}];};
  retired = evaluate {
    requests = [{inherit rollout;}];
    retiredRequests = [rollout];
  };
  nodes = builtins.attrValues retired.config.aos.activation.graph.nodes;
  retirement = builtins.head (builtins.filter (node: node.input.retirement or false) nodes);
  digest = builtins.hashString "sha256" (builtins.toJSON rollout);
  effect = retired.config.aos.imageRollout.retirementEffects.${digest};
in
  assert initial.config.aos.activation.graph.order == [];
  assert selected.config.aos.abilities.imageSelection.operations.ensure.effects.selected.lifetime == "persistent";
  assert builtins.length nodes == 2;
  assert retirement.input.rollout == rollout;
  assert retirement.input.retirement;
  assert retirement.lifetime == "persistent";
  assert builtins.hasAttr effect retired.config.aos.activation.graph.nodes;
    builtins.deepSeq retired.config.aos.activation.graph {explicitRetirementPreservesHistoricalLease = true;}
