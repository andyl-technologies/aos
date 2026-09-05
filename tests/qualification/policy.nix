##! Checks policy closure and the Rust fixture against the authoritative Nix data.
{
  pkgs,
  lib,
}: let
  contract = import ../../qualification {
    inherit lib;
    packageNames = pkgs.allPackageNames;
  };
  fixture = import ../../qualification {
    inherit lib;
    packageNames = ["aos" "nginx" "containerd" "runc"];
  };
  capturedFixture = builtins.fromJSON (builtins.readFile ../../crates/aos-release/tests/fixtures/qualification-contract.json);
  sourceTree = builtins.path {
    path = ../../qualification;
    name = "qualification-source-fixture";
  };
  nestedSource = /. + builtins.unsafeDiscardStringContext (sourceTree + "/modules");
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
  composed = import ../../qualification/_eval.nix {
    inherit lib;
    packageNames = ["aos" "fixture"];
    modules = [
      {
        qualification.images.rebootCycles = 12;
        qualification.qemu.memory_mib = 12288;
        qualification.integrityPackages = lib.mkAfter ["fixture"];
        qualification.requirements.image-lifecycle.checks = lib.mkAfter ["fixture-extra-check"];
        qualification.targets.fixture = {
          platform = "x86_64-linux";
          kind = "container";
          required = false;
          environment = {
            boot = "linux-container";
            layers = [
              {
                platform = "x86_64-linux";
                backend = {
                  kind = "physical";
                  physical = {};
                };
              }
              {
                platform = "x86_64-linux";
                backend = {
                  kind = "container";
                  container.runtime = "containerd-runc";
                };
              }
            ];
          };
        };
        qualification.claims.fixture-reviewed = {
          target = "fixture";
          requirements = ["container-lifecycle"];
          minimum_assurance = "A1";
          phase = "staging";
          blocks_release = false;
        };
      }
    ];
  };
  configured = composed.config.qualification;
  rejects = module:
    !(builtins.tryEval (builtins.deepSeq (import ../../qualification {
        inherit lib;
        packageNames = ["aos"];
        modules = [module];
      })
      true)).success;
in
  assert fixture == capturedFixture;
  assert builtins.match "^/nix/store/[0-9a-z]{32}-[^/]+$" (builtins.toString sourceRoot) != null;
  assert builtins.readFile (sourceRoot + "/server.nix") == builtins.readFile (nestedSource + "/server.nix");
  assert names == builtins.sort builtins.lessThan pkgs.allPackageNames;
  assert builtins.all (rule: rule.inherit_dependency_obligations) contract.package_rules;
  assert builtins.all (phase: builtins.elem phase phases) ["build" "staging" "rollout" "complete"];
  assert builtins.length contract.targets == 4;
  assert builtins.all (target: builtins.length target.environment.layers == 2) contract.targets;
  assert builtins.length contract.claims == 8;
  assert builtins.all (claim: claim.blocks_release && builtins.elem claim.minimum_assurance ["A2" "A3"]) contract.claims;
  assert composed.options.qualification.targets._type == "option";
  assert configured.requirements.image-installation.measurements.reboot_cycles.minimum == 12;
  assert configured.targets.disk-x86_64-linux.environment.resources.memory_mib == 12288;
  assert configured.packageRules.fixture.role == "system-integrity";
  assert builtins.elem "fixture-extra-check" configured.requirements.image-lifecycle.checks;
  assert !builtins.hasAttr "fixture-functional" configured.claims;
  assert configured.claims.fixture-reviewed.minimum_assurance == "A1";
  assert builtins.length configured.export.targets == 5;
  assert rejects {qualification.images.rebootCycles = 9;};
  assert rejects {qualification.thresholds.stable.soak_seconds = lib.mkForce 1;};
  assert rejects {qualification.claims.disk-x86_64-linux-qualified.blocks_release = lib.mkForce false;};
  assert rejects {
    qualification.claims.invalid = {
      target = "absent";
      requirements = ["container-lifecycle"];
      minimum_assurance = "A3";
      phase = "staging";
      blocks_release = false;
    };
  };
  assert rejects {qualification.qemu.unknown = true;};
  assert contract.thresholds.edge.soak_seconds < contract.thresholds.stable.soak_seconds;
  assert contract.thresholds.stable.require_complete_matrix;
    pkgs.writeTextFile {
      name = "aos-qualification-policy-check";
      destination = "/contract.json";
      text = builtins.toJSON contract;
    }
