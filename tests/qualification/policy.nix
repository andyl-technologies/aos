##! Checks policy closure and the Rust fixture against the authoritative Nix data.
{
  pkgs,
  lib,
  packageCoverage,
  releaseExecutor,
}: let
  packageNames = pkgs.platformSupport.publicationEligibleNamesAny pkgs.allPackageNames;
  contract = import ../../qualification {
    inherit lib;
    inherit packageNames;
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
  testing = import ../../lib/testing {inherit pkgs lib;};
  declarativeProbe = testing.mkQualificationPackageProbe {
    name = "fixture";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "fixture";
      primary = {
        input = "A C source file that prints one fixed line.";
        operation = "Compile the source and execute the resulting program.";
        expected = "The compiled program prints fixture followed by a newline.";
        files."fixture.c" = ''
          #include <stdio.h>

          int main(void) {
              return fputs("fixture\n", stdout) == EOF;
          }
        '';
        steps = [
          {
            argv = ["@cc@" "fixture.c" "-o" "fixture"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@work@/primary/fixture"];
            exit_code = 0;
            stdout.exact = "fixture\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A path that does not exist.";
        operation = "Attempt to read the absent input.";
        expected = "The operation rejects the missing file with status 7 and a fixed diagnostic.";
        files = {};
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              "import sys; from pathlib import Path; missing = not Path('absent').exists(); sys.stderr.write('missing input\\n' if missing else 'unexpected input\\n'); raise SystemExit(7 if missing else 0)"
            ];
            exit_code = 7;
            stdout.exact = "";
            stderr.exact = "missing input\n";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };
  declarativeProbeCheck = pkgs.runCommand "qualification-package-declarative-probe-check" {} ''
    mkdir -p work/home work/tmp work/profile
    export HOME=$PWD/work/home
    export USER=aos-qualification
    export TMPDIR=$PWD/work/tmp
    export LC_ALL=C
    buildPath=$PATH
    export PATH=
    export AOS_QUALIFICATION_PACKAGE=fixture
    export AOS_QUALIFICATION_PLATFORM=x86_64-linux
    export AOS_QUALIFICATION_PACKAGE_OUTPUTS='{"out":"/nix/store/00000000000000000000000000000000-fixture"}'
    export AOS_QUALIFICATION_PACKAGE_CLOSURE='["/nix/store/00000000000000000000000000000000-fixture"]'
    export AOS_QUALIFICATION_PACKAGE_PROFILE=$PWD/work/profile
    export AOS_QUALIFICATION_PROBE_REPORT=$PWD/work/result.json
    export AOS_QUALIFICATION_PROBE_WORK=$PWD/work
    export AOS_QUALIFICATION_BASH=${pkgs.bash}/bin/bash
    export AOS_QUALIFICATION_CC=${pkgs.cc}/bin/cc
    export AOS_QUALIFICATION_CXX=${pkgs.cc}/bin/c++
    export AOS_QUALIFICATION_PYTHON=${pkgs.python3}/bin/python3

    ${declarativeProbe}
    export PATH=$buildPath
    ${pkgs.python3}/bin/python3 - "$AOS_QUALIFICATION_PROBE_REPORT" <<'PY'
    import json
    import pathlib
    import sys

    report = pathlib.Path(sys.argv[1]).read_bytes()
    parsed = json.loads(report)
    assert report == json.dumps(
        parsed, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode() + b"\n"
    assert parsed["primary"]["observed"].startswith("step1=exit:0")
    assert parsed["bad_input"]["observed"].startswith("step1=exit:7")
    PY
    ${pkgs.coreutils}/bin/cp "$AOS_QUALIFICATION_PROBE_REPORT" $out/result.json
  '';
  executor = testing.mkQualificationExecutor {
    name = "qualification-executor-contract-fixture";
    platform = "x86_64-linux";
    identity = "fixture-executor";
    scenarios.package-function = "/nix/store/00000000000000000000000000000000-scenario/bin/run";
    workRoot = "/var/lib/aos-release/qualification-fixture";
  };
  packageProbe = declarativeProbe;
  packageExecutor = testing.mkQualificationPackageScenario {
    name = "qualification-package-scenario-fixture";
    identity = "fixture-executor";
    packageNames = ["fixture"];
    probes.fixture = packageProbe;
    trustKeys = ["andyl-testing:Ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="];
  };
  partialPackageExecutor = testing.mkQualificationPackageScenario {
    name = "qualification-package-scenario-partial-fixture";
    identity = "fixture-executor";
    packageNames = ["fixture" "missing"];
    probes.fixture = packageProbe;
    trustKeys = ["andyl-testing:Ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="];
  };
  rejectsPackageExecutor = packageNames: probes:
    !(builtins.tryEval (builtins.deepSeq (testing.mkQualificationPackageScenario {
        name = "qualification-package-scenario-invalid";
        identity = "fixture-executor";
        inherit packageNames probes;
        trustKeys = ["andyl-testing:Ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="];
      })
      true))
    .success;
  names = map (rule: rule.name) contract.package_rules;
  phases = map (gate: gate.phase) contract.requirements;
  coveredAndMissingPackageNames = builtins.sort builtins.lessThan (
    packageCoverage.implementedPackages ++ packageCoverage.missingPackages
  );
  coveragePartitions = builtins.all (
    platform: let
      coverage = packageCoverage.platforms.${platform};
      eligible = pkgs.platformSupport.publicationEligibleNames platform pkgs.allPackageNames;
      coveredAndMissing = builtins.sort builtins.lessThan (
        coverage.implementedPackages ++ coverage.missingPackages
      );
    in
      coverage.total == builtins.length eligible
      && coverage.total == coverage.implemented + builtins.length coverage.missingPackages
      && coveredAndMissing == eligible
  )
  pkgs.platformSupport.canonicalSystems;
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
        qualification.support.trains."2026.9" = {
          kind = "lts";
          supported_until = "2028-09-30";
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
      true))
    .success;
in
  assert fixture == capturedFixture;
  assert builtins.match "^/nix/store/[0-9a-z]{32}-[^/]+$" (builtins.toString sourceRoot) != null;
  assert builtins.readFile (sourceRoot + "/server.nix") == builtins.readFile (nestedSource + "/server.nix");
  assert names == builtins.sort builtins.lessThan packageNames;
  assert packageCoverage.schema_version == "aos.release.package-probe-coverage/v1";
  assert packageCoverage.total == builtins.length packageNames;
  assert packageCoverage.total
  == packageCoverage.implemented + builtins.length packageCoverage.missingPackages;
  assert coveredAndMissingPackageNames == packageNames;
  assert coveragePartitions;
  assert builtins.all (
    name: !(builtins.elem name packageNames)
  )
  packageCoverage.neverPublicationEligiblePackages;
  assert builtins.all (rule: rule.inherit_dependency_obligations) contract.package_rules;
  assert builtins.all (phase: builtins.elem phase phases) ["build" "staging" "rollout" "complete"];
  assert builtins.length contract.targets == 4;
  assert builtins.all (target: builtins.length target.environment.layers == 2) contract.targets;
  assert builtins.match "^/nix/store/[0-9a-z]{32}-[^/]+/scenarios.json$" executor.passthru.qualification.registryPath != null;
  assert executor.passthru.qualification.platform == "x86_64-linux";
  assert executor.passthru.qualification.scenarios.package-function == "/nix/store/00000000000000000000000000000000-scenario/bin/run";
  assert packageExecutor.passthru.qualification.platform == "x86_64-linux";
  assert packageExecutor.passthru.qualification.packageNames == ["fixture"];
  assert packageExecutor.passthru.qualification.probes == ["fixture"];
  assert packageExecutor.passthru.qualification.missingProbes == [];
  assert packageExecutor.passthru.qualification.probeCoverage
  == {
    complete = true;
    implemented = 1;
    total = 1;
  };
  assert builtins.match "^/nix/store/[0-9a-z]{32}-[^/]+/probes.json$" packageExecutor.passthru.qualification.probeRegistry != null;
  assert partialPackageExecutor.passthru.qualification.missingProbes == ["missing"];
  assert partialPackageExecutor.passthru.qualification.probeCoverage
  == {
    complete = false;
    implemented = 1;
    total = 2;
  };
  assert rejectsPackageExecutor ["fixture"] {
    extra = packageProbe;
    fixture = packageProbe;
  };
  assert builtins.attrNames releaseExecutor.passthru.qualification.scenarios
  == [
    "claim-container-x86_64-linux-functional"
    "claim-container-x86_64-linux-qualified"
    "claim-disk-x86_64-linux-functional"
    "claim-disk-x86_64-linux-qualified"
    "operator-recovery"
    "package-function"
    "production-recovery"
    "rollout-health"
    "rollout-observation"
    "staging-delivery"
  ];
  assert builtins.match ".*/aos-qualification-x86_64-linux-package-function" releaseExecutor.passthru.qualification.scenarios.package-function != null;
  assert builtins.match ".*/aos-qualification-x86_64-linux-container-lifecycle" releaseExecutor.passthru.qualification.scenarios.claim-container-x86_64-linux-functional != null;
  assert builtins.match ".*/aos-qualification-x86_64-linux-image-lifecycle" releaseExecutor.passthru.qualification.scenarios.claim-disk-x86_64-linux-functional != null;
  assert builtins.length contract.claims == 8;
  assert contract.support.default
  == {
    kind = "standard";
    superseded_after_trains = 2;
  };
  assert contract.support.trains == {};
  assert composed.config.qualification.export.support.trains
  == {
    "2026.9" = {
      kind = "lts";
      supported_until = "2028-09-30";
    };
  };
  assert rejects {qualification.support.trains."2026.09" = {};};
  assert rejects {qualification.support.trains."2026.9".supported_until = "2028-13-01";};
  assert rejects {qualification.support.trains."2026.9".kind = "lts";};
  assert rejects {qualification.support.default.superseded_after_trains = 0;};
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
      checkPhase = ''
        test -f ${declarativeProbeCheck}/result.json
      '';
    }
