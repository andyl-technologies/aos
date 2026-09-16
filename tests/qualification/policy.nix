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
  nativeAdapterSurface = nativeAdapterMatrix.spec.surface;
  nativeAdapterChecks = abilityRequirements.ability-native-adapter-matrix.checks;
  providerContract = adapterName:
    (builtins.head (builtins.filter (adapter: adapter.adapter == adapterName) nativeAdapterSurface.adapters)).provider_contract;
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
  assert builtins.match "^/nix/store/[0-9a-z]{32}-[^/]+$" (builtins.toString sourceRoot) != null;
  assert builtins.readFile (sourceRoot + "/server.nix") == builtins.readFile (nestedSource + "/server.nix");
  assert names == builtins.sort builtins.lessThan packageNames;
  assert imageRecovery.regressions
  == [
    "checks.fleet.system-image-rollback"
    "checks.fleet.boot-identity-fail-closed"
    "checks.fleet.measured-boot"
  ];
  assert abilityRequirements.ability-crucible-baseline.regressions
  == ["checks.fleet.ability-crucible-baseline"];
  assert abilityRequirements.ability-crucible-baseline.checks
  == [
    "connected-generic-markers-before-selected-interruption"
    "retained-boundary-selection-and-digest-bound-adapter-acknowledgement"
    "reproduced-reconciliation-through-production-executor"
    "inspector-explains-retained-crucible-recovery-finding"
    "disabled-production-executor-has-no-crucible-closure"
  ];
  assert abilityRequirements.ability-native-activation.regressions
  == ["checks.fleet.runtime-module-composition"];
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
    "authenticated-nginx-storage-ownership-lifetime-and-service-ordering"
  ];
  assert abilityRequirements.ability-native-kubernetes.regressions
  == ["checks.fleet.k3s-control-plane-worker"];
  assert abilityRequirements.ability-native-kubernetes.checks
  == [
    "authenticated-k3s-bootstrap-and-provider-authority"
    "exact-service-and-kubernetes-object-resource-mapping"
    "consumer-observed-kubernetes-readiness"
    "forged-mapping-grant-and-namespace-rejected-without-mutation"
    "object-update-removal-and-retained-owner-evidence"
    "bounded-bootstrap-planning-rejections-before-effect-construction"
  ];
  assert abilityRequirements.ability-native-recovery.regressions
  == [
    "checks.fleet.ability-initrd-activation"
    "checks.fleet.ability-initrd-handoff-fail-closed"
    "checks.fleet.runtime-module-composition"
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
    "checks.fleet.runtime-module-composition"
    "checks.fleet.ability-native-foreground-container"
    "checks.fleet.k3s-control-plane-worker"
    "checks.fleet.ability-native-power-loss"
    "checks.fleet.system-image-rollback"
  ];
  assert abilityRequirements.ability-native-adapter-matrix.production_only;
  assert builtins.length applicableNativeIds
  == builtins.length (lib.unique applicableNativeIds);
  assert builtins.length inapplicableNativeIds
  == builtins.length (lib.unique inapplicableNativeIds);
  assert builtins.all (id: !builtins.elem id inapplicableNativeIds) applicableNativeIds;
  assert partitionedNativeIds == map (cell: cell.id) nativeCells;
  assert abilityRequirements.ability-native-adapter-matrix.matrix_spec == nativeAdapterMatrix.spec;
  assert (providerContract "image-rollout")
  == {
    lifecycle = {
      persistent_delete_method = null;
    };
    resource_lifetimes = ["attempt" "persistent"];
    state_format = null;
  };
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
    system_variant = "server";
  };
  assert builtins.all (phase: builtins.elem phase phases) ["build" "staging" "rollout" "complete"];
  assert builtins.all (target: builtins.length target.environment.layers == 2) contract.targets;
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
  assert builtins.match ".*/aos-qualification-x86_64-linux-package-function" releaseExecutor.passthru.qualification.scenarios.package-function != null;
  assert builtins.all (id:
    builtins.match ".*/aos-qualification-${id}" releaseExecutor.passthru.qualification.scenarios.${id}
    != null) (builtins.attrNames abilityRequirements);
  assert builtins.match ".*/aos-qualification-x86_64-linux-container-lifecycle" releaseExecutor.passthru.qualification.scenarios.claim-container-x86_64-linux-functional != null;
  assert builtins.match ".*/aos-qualification-x86_64-linux-image-lifecycle" releaseExecutor.passthru.qualification.scenarios.claim-disk-x86_64-linux-functional != null;
  assert builtins.attrNames releaseExecutor.passthru.qualification.caseScenarios == ["package-function/aos-recovery/x86_64-linux"];
  assert builtins.match ".*/aos-qualification-x86_64-linux-aos-recovery" releaseExecutor.passthru.qualification.caseScenarios."package-function/aos-recovery/x86_64-linux" != null;
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
