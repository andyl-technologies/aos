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
  imageRecovery = builtins.head (
    builtins.filter (requirement: requirement.id == "image-update-recovery") contract.requirements
  );
  abilityRequirements = builtins.listToAttrs (map (id: {
      name = id;
      value = builtins.head (
        builtins.filter (requirement: requirement.id == id) contract.requirements
      );
    }) [
      "ability-native-activation"
      "ability-native-adapter-matrix"
      "ability-native-image-rollout"
      "ability-native-kubernetes"
      "ability-native-postgresql"
      "ability-native-recovery"
    ]);
  nativeAdapterMatrix = import ../../qualification/modules/_native-adapter-matrix.nix {inherit lib;};
  containerExecutionMatrix = import ../../qualification/modules/_container-execution-matrix.nix {inherit lib;};
  nativeAdapterSurface = builtins.fromJSON (builtins.readFile ../../qualification/native-adapter-surface.json);
  nativeCells = nativeAdapterMatrix.cells;
  firstNativeCell = builtins.head nativeCells;
  remainingNativeCells = builtins.tail nativeCells;
  replaceFirstNativeCell = replacement: [replacement] ++ remainingNativeCells;
  rejectsNativeMatrix = arguments:
    !(builtins.tryEval (builtins.deepSeq (import ../../qualification/modules/_native-adapter-matrix.nix ({inherit lib;} // arguments)) true)).success;
  recoveryPackage = builtins.head (
    builtins.filter (rule: rule.name == "aos-recovery") contract.package_rules
  );
  coveredAndMissingPackageNames = builtins.sort builtins.lessThan (
    packageCoverage.implementedPackages ++ packageCoverage.missingPackages
  );
  coveragePartitions =
    builtins.all (
      platform: let
        coverage = packageCoverage.platforms.${platform};
        eligible = pkgs.platformSupport.publicationEligibleNames platform pkgs.allPackageNames;
        coveredAndMissing = builtins.sort builtins.lessThan (
          coverage.implementedPackages ++ coverage.missingPackages
        );
      in
        coverage.total
        == builtins.length eligible
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
  assert imageRecovery.regressions
  == [
    "checks.fleet.system-image-rollback"
    "checks.fleet.boot-identity-fail-closed"
    "checks.fleet.measured-boot"
  ];
  assert abilityRequirements.ability-native-activation.regressions
  == ["checks.fleet.ability-native-activation"];
  assert abilityRequirements.ability-native-activation.checks
  == [
    "authenticated-package-policy-and-operator-authority"
    "exact-interface-binding-effect-plan-and-artifact-identities"
    "consumer-scoped-access-and-independent-service-observation"
    "aggregate-publication-reload-and-unchanged-input-no-op"
    "post-publication-reload-failure-retains-new-configuration-and-old-or-unknown-consumer-state"
    "rollback-revalidates-and-retains-transaction-evidence"
    "typed-opaque-tls-credential-version-delivery-and-validation-binding"
    "independent-served-certificate-observation-matches-declared-version"
    "missing-credential-and-invalid-certificate-reject-with-live-target-preserved"
    "tls-private-key-sentinel-absent-from-durable-and-rendered-records"
    "credential-renewal-reloads-and-serves-new-version"
    "selected-tls-generation-and-credential-view-survive-gc-and-reboot"
    "tls-disable-and-cleartext-transition-release-credential-views-after-service-change"
    "endpoint-and-ingress-policy-precede-service-readiness-and-release-in-reverse-order"
  ];
  assert abilityRequirements.ability-native-image-rollout.regressions
  == ["checks.fleet.ability-native-image-rollout"];
  assert abilityRequirements.ability-native-image-rollout.checks
  == [
    "advisory-exact-candidate-staging-without-selection-or-reboot"
    "authenticated-rollout-plan-and-exact-native-request"
    "booted-candidate-health-hook-before-config-generation-commit"
    "healthy-provider-and-journal-evidence-before-physical-commit"
    "failed-health-mark-reboot-and-predecessor-retention"
    "exact-generation-roots-and-uki-retention"
    "post-expiry-rollout-root-retirement"
  ];
  assert abilityRequirements.ability-native-image-rollout.production_only;
  assert abilityRequirements.ability-native-kubernetes.regressions
  == ["checks.fleet.ability-native-kubernetes"];
  assert abilityRequirements.ability-native-kubernetes.checks
  == [
    "authenticated-k3s-bootstrap-and-provider-authority"
    "exact-service-and-kubernetes-object-resource-mapping"
    "consumer-observed-kubernetes-readiness"
    "forged-mapping-grant-and-namespace-rejected-without-mutation"
    "object-update-removal-and-retained-owner-evidence"
    "bounded-bootstrap-planning-rejections-before-effect-construction"
  ];
  assert abilityRequirements.ability-native-postgresql.regressions
  == ["checks.fleet.ability-native-postgresql"];
  assert abilityRequirements.ability-native-postgresql.checks
  == [
    "authenticated-provider-bindings-and-exact-handler-artifacts"
    "exact-seven-operation-ten-edge-provisioning-graph"
    "runtime-output-data-flow-and-schema-valid-observations"
    "loopback-sql-readiness-and-enforced-non-loopback-denial"
    "stopped-divergent-and-child-drift-reconciliation"
    "exact-six-operation-five-edge-teardown-and-persistent-retention"
  ];
  assert abilityRequirements.ability-native-recovery.regressions
  == [
    "checks.fleet.ability-initrd-activation"
    "checks.fleet.ability-initrd-handoff-fail-closed"
    "checks.fleet.ability-native-power-loss"
  ];
  assert abilityRequirements.ability-native-recovery.checks
  == [
    "exact-boot-initrd-artifact-and-static-stage-handoff-contract"
    "process-loss-after-external-effect-reconciles-before-retry"
    "power-loss-after-external-effect-reconciles-after-boot"
    "fresh-receiving-authority-and-resource-incarnations"
    "retained-plan-journal-and-independent-service-observation"
    "gc-after-crashed-unlocked-partial-activation-retains-recovery-set"
  ];
  assert abilityRequirements.ability-native-adapter-matrix.regressions
  == [
    "checks.fleet.ability-native-activation"
    "checks.fleet.ability-native-image-rollout"
    "checks.fleet.ability-native-kubernetes"
    "checks.fleet.ability-native-postgresql"
    "checks.fleet.ability-native-power-loss"
  ];
  assert abilityRequirements.ability-native-adapter-matrix.production_only;
  assert nativeAdapterMatrix.cell_count == 1316;
  assert nativeAdapterMatrix.required_production_vm_cells == 1316;
  assert nativeAdapterMatrix.spec.cells == nativeAdapterMatrix.cells;
  assert builtins.all (cell: !(cell ? evidence)) nativeAdapterMatrix.cells;
  assert abilityRequirements.ability-native-adapter-matrix.checks
  == [
    nativeAdapterMatrix.check
    containerExecutionMatrix.check
  ];
  assert containerExecutionMatrix.missing_container_cells == 2;
  assert rejectsNativeMatrix {cells = remainingNativeCells;};
  assert rejectsNativeMatrix {cells = [firstNativeCell] ++ nativeCells;};
  assert rejectsNativeMatrix {cells = [(builtins.elemAt nativeCells 1) firstNativeCell] ++ lib.drop 2 nativeCells;};
  assert rejectsNativeMatrix {subject = nativeAdapterMatrix.subject // {surface_digest = "sha256:stale";};};
  assert rejectsNativeMatrix {
    surface =
      nativeAdapterSurface
      // {
        scenarios =
          [(builtins.head nativeAdapterSurface.scenarios // {failure = "none";})]
          ++ builtins.tail nativeAdapterSurface.scenarios;
      };
  };
  assert rejectsNativeMatrix {invalidatedBy = ["subject" "policy" "executor"];};
  assert rejectsNativeMatrix {
    regressions = abilityRequirements.ability-native-adapter-matrix.regressions ++ ["checks.fleet.foreign"];
  };
  assert rejectsNativeMatrix {
    regressions =
      builtins.filter (regression: regression != "checks.fleet.ability-native-postgresql")
      abilityRequirements.ability-native-adapter-matrix.regressions;
  };
  assert rejectsNativeMatrix {
    cells = replaceFirstNativeCell (firstNativeCell
      // {
        interface = firstNativeCell.interface // {abi = 2;};
      });
  };
  assert rejectsNativeMatrix {
    cells = replaceFirstNativeCell (firstNativeCell
      // {
        interface = firstNativeCell.interface // {descriptor = "sha256:${builtins.hashString "sha256" "foreign interface"}";};
      });
  };
  assert rejectsNativeMatrix {cells = replaceFirstNativeCell (firstNativeCell // {adapter = "foreign";});};
  assert rejectsNativeMatrix {
    cells = replaceFirstNativeCell (firstNativeCell
      // {
        interface = firstNativeCell.interface // {name = "aos.foreign";};
      });
  };
  assert rejectsNativeMatrix {cells = replaceFirstNativeCell (firstNativeCell // {method = "foreign";});};
  assert rejectsNativeMatrix {cells = replaceFirstNativeCell (firstNativeCell // {scope = "host-manager";});};
  assert rejectsNativeMatrix {cells = replaceFirstNativeCell (firstNativeCell // {boundary = "deadline";});};
  assert rejectsNativeMatrix {cells = replaceFirstNativeCell (firstNativeCell // {failure = "foreign";});};
  assert rejectsNativeMatrix {cells = replaceFirstNativeCell (firstNativeCell // {predecessor = "foreign";});};
  assert rejectsNativeMatrix {cells = replaceFirstNativeCell (firstNativeCell // {candidate = "foreign";});};
  assert rejectsNativeMatrix {
    cells = replaceFirstNativeCell (firstNativeCell
      // {
        evidence = {
          environment = "production-vm";
          status = "passed";
          regressions = ["checks.fleet.foreign"];
        };
      });
  };
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
  assert rejects {
    qualification.requirements.ability-native-image-rollout.production_only = lib.mkForce false;
  };
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
  assert recoveryPackage.role == "system-integrity";
  assert recoveryPackage.execution
  == {
    kind = "recovery-image";
    system_variant = "server";
  };
  assert builtins.all (phase: builtins.elem phase phases) ["build" "staging" "rollout" "complete"];
  assert builtins.length contract.targets == 4;
  assert builtins.all (target: builtins.length target.environment.layers == 2) contract.targets;
  assert builtins.match "^/nix/store/[0-9a-z]{32}-[^/]+/scenarios.json$" executor.passthru.qualification.registryPath != null;
  assert executor.passthru.qualification.platform == "x86_64-linux";
  assert executor.passthru.qualification.caseScenarios == {};
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
    "ability-native-activation"
    "ability-native-adapter-matrix"
    "ability-native-kubernetes"
    "ability-native-postgresql"
    "ability-native-recovery"
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
  assert !builtins.hasAttr "ability-native-image-rollout" releaseExecutor.passthru.qualification.scenarios;
  assert builtins.match ".*/aos-qualification-x86_64-linux-package-function" releaseExecutor.passthru.qualification.scenarios.package-function != null;
  assert builtins.all (id:
    builtins.match ".*/aos-qualification-${id}" releaseExecutor.passthru.qualification.scenarios.${id}
    != null) (builtins.filter (id:
    id != "ability-native-image-rollout")
  (builtins.attrNames abilityRequirements));
  assert builtins.match ".*/aos-qualification-x86_64-linux-container-lifecycle" releaseExecutor.passthru.qualification.scenarios.claim-container-x86_64-linux-functional != null;
  assert builtins.match ".*/aos-qualification-x86_64-linux-image-lifecycle" releaseExecutor.passthru.qualification.scenarios.claim-disk-x86_64-linux-functional != null;
  assert builtins.attrNames releaseExecutor.passthru.qualification.caseScenarios == ["package-function/aos-recovery/x86_64-linux"];
  assert builtins.match ".*/aos-qualification-x86_64-linux-aos-recovery" releaseExecutor.passthru.qualification.caseScenarios."package-function/aos-recovery/x86_64-linux" != null;
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
        ${pkgs.python3}/bin/python3 \
          ${./ability-check-details.py} \
          $out/contract.json \
          ${../../lib/testing/qualification-ability.py}
      '';
    }
