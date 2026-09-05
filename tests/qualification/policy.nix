##! Checks policy closure and the Rust fixture against the authoritative Nix data.
{
  pkgs,
  lib,
}: let
  contract = import ../../qualification {packageNames = pkgs.allPackageNames;};
  fixture = import ../../qualification {packageNames = ["aos" "nginx" "containerd" "runc"];};
  capturedFixture = builtins.fromJSON (builtins.readFile ../../crates/aos-release/tests/fixtures/qualification-contract.json);
  sourceTree = builtins.path {
    path = ../../qualification;
    name = "qualification-source-fixture";
  };
  nestedSource = /. + builtins.unsafeDiscardStringContext (sourceTree + "/contracts");
  sourceFixture = {
    type = "derivation";
    outPath = "/nix/store/00000000000000000000000000000000-source-fixture";
    drvPath = "/nix/store/00000000000000000000000000000000-source-fixture.drv";
    src = nestedSource;
    pname = "source-fixture";
    version = "1";
  };
  sourceEvidence = import ../../lib/containers/package-evidence.nix {
    inherit lib;
    pkgs = {
      packageNames = ["fixture"];
      fixture = sourceFixture;
    };
  };
  sourceRoot = builtins.head sourceEvidence.sourcePaths;
  names = map (rule: rule.name) contract.package_rules;
  phases = map (gate: gate.phase) contract.requirements;
in
  assert fixture == capturedFixture;
  assert builtins.match "^/nix/store/[0-9a-z]{32}-[^/]+$" (builtins.toString sourceRoot) != null;
  assert builtins.readFile (sourceRoot + "/server-v1.nix") == builtins.readFile (nestedSource + "/server-v1.nix");
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
