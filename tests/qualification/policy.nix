##! Checks policy closure and the Rust fixture against the authoritative Nix data.
{
  pkgs,
  lib,
  nativeAdapterMatrix,
  releaseExecutor,
}: let
  packageNames = pkgs.platformSupport.publicationEligibleNamesAny pkgs.allPackageNames;
  contract = import ../../qualification {
    inherit lib nativeAdapterMatrix;
    inherit packageNames;
  };
  packageFunctionRequirement = builtins.head (
    builtins.filter (requirement: requirement.id == "package-function") contract.requirements
  );
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
  sourceEvidence = pkgs.mkOciPackageEvidence {
    packageSet = {
      packageNames = ["fixture"];
      fixture = sourceFixture;
    };
  };
  sourceRoot = builtins.head sourceEvidence.sourcePaths;
  generatedArchive = pkgs.runCommand "qualification-generated-source-fixture" {} ''
    echo 'This fixture must not be realized during evidence evaluation.' >&2
    exit 1
  '';
  generatedSourceEvidence = import ../../lib/containers/package-evidence.nix {
    inherit lib;
    pkgs = {
      packageNames = ["fixture"];
      fixture = sourceFixture // {src = "${generatedArchive}/source.tar";};
    };
  };
  generatedSourceRoot = builtins.head generatedSourceEvidence.sourcePaths;
  testing = import ../../lib/testing {inherit pkgs lib;};
  containerReport = reportOnly:
    (import ../../lib/testing/qualification-container.nix {
      inherit lib;
      pkgs =
        pkgs
        // {
          # A guest report producer must not depend on the host response binder.
          aos =
            if reportOnly
            then throw "guest report uses aos"
            else pkgs.aos;
          writeShellScriptBin = _: script: script;
        };
    }) {
      name = "container-report-fixture";
      identity = "container-report-fixture";
      inherit reportOnly;
    };

  probeFixture = lib.qualification.commandProbe {
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
    badInput = {
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
  declarativeProbe = testing.mkQualificationPackageProbe {
    name = "fixture";
    spec = import ../../lib/testing/qualification-package-spec.nix {inherit lib;} {
      packageName = "fixture";
      packageProbe = probeFixture;
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
  packageExecutor = testing.mkQualificationPackageScenario {
    name = "qualification-package-scenario-fixture";
    identity = "fixture-executor";
    packageNames = ["gzip"];
    checks = packageFunctionRequirement.checks;
    trustKeys = ["andyl-testing:Ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="];
  };
  rejectsPackageExecutor = packageNames:
    !(builtins.tryEval (builtins.deepSeq (testing.mkQualificationPackageScenario {
        name = "qualification-package-scenario-invalid";
        identity = "fixture-executor";
        inherit packageNames;
        checks = packageFunctionRequirement.checks;
        trustKeys = ["andyl-testing:Ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="];
      })
      true))
    .success;
  names = map (rule: rule.name) contract.package_rules;
  phases = map (gate: gate.phase) contract.requirements;
  imageRecovery = builtins.head (
    builtins.filter (requirement: requirement.id == "image-update-recovery") contract.requirements
  );
  abilityRequirements = builtins.listToAttrs (map (requirement: {
    name = requirement.id;
    value = requirement;
  }) (builtins.filter (requirement: lib.hasPrefix "ability-" requirement.id) contract.requirements));
  nativeAdapterChecks = abilityRequirements.ability-native-adapter-matrix.checks;
  nativeCells = nativeAdapterMatrix.spec.cells;
  applicableNativeIds = nativeAdapterMatrix.spec.applicability.applicable_cell_ids;
  inapplicableNativeIds = map (entry: entry.cell_id) nativeAdapterMatrix.spec.applicability.inapplicable_cells;
  partitionedNativeIds = builtins.sort builtins.lessThan (applicableNativeIds ++ inapplicableNativeIds);
  nativeRoleRevocationCells = builtins.filter (cell:
    builtins.match "revoke-(caller|provider|enforcement|assignment)-(before-acquisition|after-acquisition|before-external-effect)"
    (builtins.elemAt (lib.splitString "/" cell.id) 4)
    != null)
  nativeCells;
  nativeFailureControlCells = builtins.filter (cell: let
    scenario = builtins.elemAt (lib.splitString "/" cell.id) 4;
  in
    builtins.elem scenario ["expire-attempt-deadline" "fail-cleanup" "fail-release"])
  nativeCells;
  recoveryPackage = builtins.head (
    builtins.filter (rule: rule.name == "aos-recovery") contract.package_rules
  );
  executedPackageRules = builtins.filter (rule: rule.execution != null) contract.package_rules;
  packageCaseScenarioNames =
    map
    (rule: "package-function/${rule.name}/x86_64-linux")
    executedPackageRules;
  isStoreScenario = scenario:
    builtins.match "^/nix/store/[0-9a-z]{32}-[^/]+(/.*)?$" (builtins.toString scenario)
    != null;
  composed = import ../../qualification/_eval.nix {
    inherit lib nativeAdapterMatrix;
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
        inherit lib nativeAdapterMatrix;
        packageNames = ["aos"];
        modules = [module];
      })
      true))
    .success;
in
  assert lib.hasInfix "cat scenario-report.json" (containerReport true);
  assert !(lib.hasInfix "release qualification respond" (containerReport true));
  assert lib.hasInfix "release qualification respond" (containerReport false);
  assert lib.hasInfix "lifecycle_cycles" (containerReport true);
  assert builtins.match "^/nix/store/[0-9a-z]{32}-[^/]+$" (builtins.toString sourceRoot) != null;
  assert builtins.readFile (sourceRoot + "/server.nix") == builtins.readFile (nestedSource + "/server.nix");
  assert generatedSourceRoot == builtins.toString generatedArchive;
  assert builtins.getContext generatedSourceRoot == builtins.getContext (builtins.toString generatedArchive);
  assert (builtins.head (builtins.head generatedSourceEvidence.catalog).sources).path == builtins.unsafeDiscardStringContext generatedSourceRoot;
  assert names == builtins.sort builtins.lessThan packageNames;
  assert imageRecovery.regressions != [];
  assert builtins.all (requirement:
    requirement.checks
    != []
    && requirement.regressions != []
    && builtins.length requirement.checks == builtins.length (lib.unique requirement.checks)
    && builtins.length requirement.regressions == builtins.length (lib.unique requirement.regressions)
    && builtins.all (regression: builtins.match "checks[.][A-Za-z0-9._-]+" regression != null) requirement.regressions)
  (builtins.attrValues abilityRequirements);
  assert abilityRequirements.ability-native-adapter-matrix.production_only;
  assert builtins.length applicableNativeIds
  == builtins.length (lib.unique applicableNativeIds);
  assert builtins.length inapplicableNativeIds
  == builtins.length (lib.unique inapplicableNativeIds);
  assert builtins.all (id: !builtins.elem id inapplicableNativeIds) applicableNativeIds;
  assert partitionedNativeIds == map (cell: cell.id) nativeCells;
  assert abilityRequirements.ability-native-adapter-matrix.matrix_spec == nativeAdapterMatrix.spec;
  assert builtins.all (cell: builtins.elem "dependent-effects-not-executed" cell.postconditions) nativeRoleRevocationCells;
  assert builtins.all (cell: builtins.elem "dependent-effects-not-executed" cell.postconditions) nativeFailureControlCells;
  assert builtins.all (cell: !(cell ? evidence)) nativeAdapterMatrix.spec.cells;
  assert builtins.elem nativeAdapterMatrix.check nativeAdapterChecks;
  assert builtins.any (check:
    builtins.match "container-execution-surface-v1-sha256-[0-9a-f]{64}" check != null)
  nativeAdapterChecks;
  assert builtins.all (requirement:
    requirement.phase
    == "staging"
    && requirement.scope == "release"
    && requirement.method == "automated"
    && requirement.invalidated_by == ["subject" "policy" "executor" "environment"])
  (builtins.attrValues abilityRequirements);
  assert rejects {
    qualification.requirements.ability-native-adapter-matrix.production_only = lib.mkForce false;
  };
  assert builtins.all (rule: rule.inherit_dependency_obligations) contract.package_rules;
  assert recoveryPackage.role == "system-integrity";
  assert recoveryPackage.execution
  == {
    kind = "recovery-image";
    system_variant = "aos-testing";
  };
  assert builtins.all (rule:
    (rule.execution or null) == null || rule.execution.system_variant == "aos-testing")
  contract.package_rules;
  assert builtins.all (phase: builtins.elem phase phases) ["build" "staging" "rollout" "complete"];
  assert builtins.all (target:
    builtins.length target.environment.layers
    == (
      if target.id == "container-aarch64-linux"
      then 3
      else 2
    ))
  contract.targets;
  assert builtins.match "^/nix/store/[0-9a-z]{32}-[^/]+/scenarios.json$" executor.passthru.qualification.registryPath != null;
  assert executor.passthru.qualification.platform == "x86_64-linux";
  assert executor.passthru.qualification.caseScenarios == {};
  assert executor.passthru.qualification.scenarios.package-function == "/nix/store/00000000000000000000000000000000-scenario/bin/run";
  assert packageExecutor.passthru.qualification.platform == "x86_64-linux";
  assert packageExecutor.passthru.qualification.packageNames == ["gzip"];
  assert packageExecutor.passthru.qualification.probes == ["gzip"];
  assert builtins.match "^/nix/store/[0-9a-z]{32}-[^/]+/probes.json$" packageExecutor.passthru.qualification.probeRegistry != null;
  assert rejectsPackageExecutor ["gzip" "gzip"];
  assert builtins.all
  (id: builtins.hasAttr id releaseExecutor.passthru.qualification.scenarios)
  (builtins.attrNames abilityRequirements);
  assert isStoreScenario releaseExecutor.passthru.qualification.scenarios.package-function;
  assert builtins.all
  (id: isStoreScenario releaseExecutor.passthru.qualification.scenarios.${id})
  (builtins.attrNames abilityRequirements);
  assert isStoreScenario releaseExecutor.passthru.qualification.scenarios.claim-container-x86_64-linux-functional;
  assert isStoreScenario releaseExecutor.passthru.qualification.scenarios.claim-disk-x86_64-linux-functional;
  assert builtins.attrNames releaseExecutor.passthru.qualification.caseScenarios
  == packageCaseScenarioNames;
  assert builtins.all (rule:
    isStoreScenario releaseExecutor.passthru.qualification.caseScenarios."package-function/${rule.name}/x86_64-linux")
  executedPackageRules;
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
        ${pkgs.python3}/bin/python3 \
          ${./ability-check-details.py} \
          $out/contract.json \
          ${../../lib/testing/qualification-ability.py}
      '';
    }
