##! Checks policy closure and the Rust fixture against the authoritative Nix data.
{pkgs}: let
  contract = import ../../qualification {packageNames = pkgs.allPackageNames;};
  fixture = import ../../qualification {packageNames = ["aos" "nginx" "containerd" "runc"];};
  capturedFixture = builtins.fromJSON (builtins.readFile ../../crates/aos-release/tests/fixtures/qualification-contract.json);
  names = map (rule: rule.name) contract.package_rules;
  phases = map (gate: gate.phase) contract.requirements;
in
  assert fixture == capturedFixture;
  assert names == builtins.sort builtins.lessThan pkgs.allPackageNames;
  assert builtins.all (rule: rule.inherit_dependency_obligations) contract.package_rules;
  assert builtins.all (phase: builtins.elem phase phases) ["build" "staging" "rollout" "complete"];
  assert builtins.length contract.targets == 4;
  assert contract.thresholds.edge.soak_seconds < contract.thresholds.stable.soak_seconds;
  assert contract.thresholds.stable.require_complete_matrix;
    pkgs.writeTextFile {
      name = "aos-qualification-policy-check";
      destination = "/contract.json";
      text = builtins.toJSON contract;
    }
