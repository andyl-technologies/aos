##! Executes one native ability contract or adapter cohort against an exact published server image.
{
  pkgs,
  lib,
}: {
  name,
  identity,
  scenarioId,
  checks,
  testScript ? "",
  setupBody ? "",
  extraClosures ? [],
  candidateRuntimeCompanions ? [],
  selectedEvaluation ? null,
  adoptionEvaluation ? null,
  stagingHubUrl ? null,
  nativeOperationSpec ? null,
  nativeOperationCohorts ? [],
  cohorts ? [
    {
      id = "ability";
      requiredInputs = [];
      execution = {
        bootInput = "candidate-image";
        fixtureRole = null;
        recordsGuestKernel = true;
      };
      report = {kind = "ordinary";};
    }
  ],
}: let
  platform = pkgs.stdenv.hostPlatform.system;
  fixtureScriptRoot = pkgs.writeTextFile {
    name = "${name}-fleet-script";
    destination = "/script.py";
    text = testScript;
  };
  fixtureScript = "${fixtureScriptRoot}/script.py";
  nativeOperationSpecRoot =
    if nativeOperationSpec == null
    then null
    else
      pkgs.writeTextFile {
        name = "${name}-native-adapter-matrix";
        destination = "/matrix-spec.json";
        text = builtins.toJSON nativeOperationSpec;
      };
  nativeOperationSpecPath =
    if nativeOperationSpecRoot == null
    then ""
    else "${nativeOperationSpecRoot}/matrix-spec.json";
  setupModuleRoot = pkgs.writeTextFile {
    name = "${name}-setup";
    destination = "/module.nix";
    text = ''
      { lib, pkgs, ... }: {
        ${setupBody}
      }
    '';
  };
  setupModule = "${setupModuleRoot}/module.nix";
  additionalCohorts = map (cohort: let
    scriptRoot = pkgs.writeTextFile {
      name = "${name}-${cohort.id}-fleet-script";
      destination = "/script.py";
      text = cohort.testScript;
    };
    setupRoot = pkgs.writeTextFile {
      name = "${name}-${cohort.id}-setup";
      destination = "/module.nix";
      text = ''
        { pkgs, ... }: {
          ${cohort.setupBody}
        }
      '';
    };
  in
    {
      requiredInputs = cohort.requiredInputs or [];
      execution =
        cohort.execution or {
          bootInput = "candidate-image";
          fixtureRole = null;
          recordsGuestKernel = true;
        };
      report = cohort.report or {kind = "matrix";};
    }
    // cohort
    // {
      inherit scriptRoot setupRoot;
      script = "${scriptRoot}/script.py";
      setup = "${setupRoot}/module.nix";
    })
  nativeOperationCohorts;
  allCandidateRuntimeCompanions =
    candidateRuntimeCompanions
    ++ lib.concatMap (cohort: cohort.candidateRuntimeCompanions) additionalCohorts;
  cohortInput = cohort: script: setup: qualifiedCells:
    {
      inherit (cohort) id requiredInputs execution report;
      inherit script setup qualifiedCells;
    }
    // lib.optionalAttrs (cohort.report.kind == "matrix") {
      matrixSpec = cohort.matrixSpec;
    }
    // lib.optionalAttrs (cohort ? selectedEvaluation) {
      inherit (cohort) selectedEvaluation adoptionEvaluation;
    };
  matrixCohortInputs = map (cohort:
    cohortInput cohort cohort.script cohort.setup cohort.qualifiedCells)
  additionalCohorts;
  scenarioCohortInputs = map (cohort:
    cohortInput (cohort // lib.optionalAttrs (selectedEvaluation != null) {inherit selectedEvaluation adoptionEvaluation;}) fixtureScript setupModule [])
  cohorts;
  qualificationCohorts =
    if nativeOperationSpec == null
    then scenarioCohortInputs
    else matrixCohortInputs;
  requiresStagingHub =
    builtins.any (
      cohort: builtins.elem "predecessor-image" cohort.requiredInputs
    )
    qualificationCohorts;
  selectedEvaluationCohorts = builtins.filter (cohort: cohort ? selectedEvaluation) qualificationCohorts;
  selectedEvaluationRoots = lib.concatMap (cohort: let
    selections = [cohort.selectedEvaluation cohort.adoptionEvaluation];
    sourceRoot = locator: let
      match = builtins.match "^(/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[^/]+)(/.*)?$" locator;
    in
      if match == null
      then throw "Qualification scenario source must belong to an immutable store root."
      # Regex captures discard Nix string context. Carry the original source
      # dependency into the explicit root so it is realized and retained.
      else builtins.appendContext (builtins.head match) (builtins.getContext locator);
  in
    lib.concatMap (selection: [selection.locator] ++ map sourceRoot selection.scenario_sources) selections)
  selectedEvaluationCohorts;
  fixtureEvaluations = pkgs.writeTextFile {
    name = "${name}-fixture-evaluations";
    destination = "/evaluations.json";
    text = builtins.toJSON (builtins.listToAttrs (map (cohort: {
        name = cohort.id;
        value = {
          selected_evaluation = cohort.selectedEvaluation;
          adoption_evaluation = cohort.adoptionEvaluation;
        };
      })
      selectedEvaluationCohorts));
  };
  fixtureRoots = lib.unique (
    map builtins.toString (
      [fixtureScriptRoot setupModuleRoot fixtureEvaluations pkgs.aos.testSupport]
      ++ selectedEvaluationRoots
      ++ lib.concatMap (cohort: [cohort.scriptRoot cohort.setupRoot]) additionalCohorts
      ++ lib.optional (nativeOperationSpecRoot != null) nativeOperationSpecRoot
      ++ extraClosures
      ++ lib.concatMap (cohort: cohort.extraClosures) additionalCohorts
    )
  );
  fixtureGraph =
    import ../build/reference-graph.nix {
      inherit lib;
      inherit (pkgs) mkDerivation coreutils jq;
    } {
      rootPaths = fixtureRoots;
      pname = "${name}-fixture-graph";
    };
  fixtureArchiveRoot = pkgs.mkDerivation {
    pname = "${name}-fixture-export";
    version = "1";
    src = null;
    buildDeps = [pkgs.coreutils pkgs.nix pkgs.python3];
    outputChecks.out = {};
    dontStrip = true;
    dontNukeRefs = true;
    phases = [
      {
        name = "export-fixture";
        script = ''
          set -eu

          mkdir -p "$out"
          PYTHONDONTWRITEBYTECODE=1 \
            ${pkgs.python3}/bin/python3 \
              ${./qualification-fixture-export.py} \
              ${fixtureGraph}/inventory.json \
              "$out/fixture.export" \
              ${pkgs.nix}/bin/nix-store \
              "$TMPDIR/qualification-fixture-export"
          test -s "$out/fixture.export"
          # Preserve the original graph used to verify each streamed NAR. The
          # configured executor registry commits these exact bytes at build time.
          cp ${fixtureGraph}/inventory.json "$out/inventory.json"
          cp ${fixtureEvaluations}/evaluations.json "$out/evaluations.json"

          bytecode="$(${pkgs.findutils}/bin/find "$out" \
            \( -type d -name __pycache__ -o -type f \
            \( -name '*.pyc' -o -name '*.pyo' \) \) -print -quit)"
          if [ -n "$bytecode" ]; then
            echo "Python bytecode escaped into qualification fixture export: $bytecode" >&2
            exit 1
          fi
        '';
      }
    ];
  };
  fixtureArchive = "${fixtureArchiveRoot}/fixture.export";
  fixtureInventoryPath = "${fixtureArchiveRoot}/inventory.json";
  fixtureEvaluationsPath = "${fixtureArchiveRoot}/evaluations.json";
  fixtureContractDigest = "sha256:${builtins.hashString "sha256" (builtins.toJSON (
    {
      inherit scenarioId checks setupBody;
      candidateRuntimeCompanions = allCandidateRuntimeCompanions;
      roots = fixtureRoots;
      script = testScript;
    }
    // {
      inherit qualificationCohorts;
    }
    // lib.optionalAttrs (nativeOperationSpec != null) {
      inherit nativeOperationSpec;
    }
  ))}";
  narSelfReference = pkgs.mkDerivation {
    pname = "qualification-nar-self-reference";
    version = "1";
    src = null;
    outputChecks.out = {};
    dontStrip = true;
    dontNukeRefs = true;
    phases = [
      {
        name = "install";
        script = ''
          set -eu

          mkdir -p "$out"
          printf '%s\n' "$out" > "$out/self-reference"
        '';
      }
    ];
  };
  qemu = "${pkgs.qemu}/bin/qemu-system-x86_64";
  runtimePath = lib.makeBinPath [
    pkgs.bash
    pkgs.coreutils
    pkgs.e2fsprogs
    pkgs.findutils
    pkgs.gptfdisk
    pkgs.jq
    pkgs.nix
    pkgs.openssh
    pkgs.qemu
    pkgs.swtpm
    pkgs.zstd
  ];
  support = pkgs.writeTextFile {
    name = "${name}-support";
    destination = "/share/aos-release/qualification-image.py";
    text = builtins.readFile ./qualification-image.py;
  };
  nativeImageSupport = pkgs.writeTextFile {
    name = "${name}-native-image-support";
    destination = "/share/aos-release/qualification-native-image.py";
    text = builtins.readFile ./qualification-native-image.py;
    checkPhase = ''
      PYTHONPYCACHEPREFIX=$TMPDIR/qualification-native-image-pycache \
        ${pkgs.buildPackages.python3}/bin/python3 -m py_compile \
          $out/share/aos-release/qualification-native-image.py
      PYTHONDONTWRITEBYTECODE=1 ${pkgs.buildPackages.python3}/bin/python3 \
        ${./qualification-native-image-self-test.py} \
        $out/share/aos-release/qualification-native-image.py
    '';
  };
  nativeCustodySupport = pkgs.writeTextFile {
    name = "${name}-native-custody-support";
    destination = "/share/aos-release/qualification-native-custody.py";
    text = builtins.readFile ./qualification-native-custody.py;
    checkPhase = ''
      PYTHONPYCACHEPREFIX=$TMPDIR/qualification-native-custody-pycache \
        ${pkgs.buildPackages.python3}/bin/python3 -m py_compile \
        $out/share/aos-release/qualification-native-custody.py
      PYTHONPYCACHEPREFIX=$TMPDIR/qualification-native-custody-tests \
        ${pkgs.buildPackages.python3}/bin/python3 \
        ${./qualification-native-custody-self-test.py} \
        $out/share/aos-release/qualification-native-custody.py
    '';
  };
  narSupport = pkgs.writeTextFile {
    name = "${name}-nar-support";
    destination = "/share/aos-release/qualification-nar.py";
    text = builtins.readFile ./qualification-nar.py;
    checkPhase = ''
      PYTHONPYCACHEPREFIX=$TMPDIR/qualification-nar-pycache \
        ${pkgs.buildPackages.python3}/bin/python3 -m py_compile \
        $out/share/aos-release/qualification-nar.py

      PYTHONPYCACHEPREFIX=$TMPDIR/qualification-nar-self-test-pycache \
        ${pkgs.buildPackages.python3}/bin/python3 \
          ${./qualification-nar-self-test.py} \
          $out/share/aos-release/qualification-nar.py \
          ${pkgs.nix}/bin/nix-store \
          ${pkgs.zstd}/bin/zstd \
          ${narSelfReference} \
          $TMPDIR/qualification-nar-self-test

      bytecode="$(${pkgs.findutils}/bin/find "$out" \
        \( -type d -name __pycache__ -o -type f \
        \( -name '*.pyc' -o -name '*.pyo' \) \) -print -quit)"
      if [ -n "$bytecode" ]; then
        echo "Python bytecode escaped into qualification NAR support: $bytecode" >&2
        exit 1
      fi
    '';
  };
  scenario = pkgs.writeTextFile {
    name = "${name}-scenario";
    destination = "/share/aos-release/qualification-ability.py";
    text = builtins.readFile ./qualification-ability.py;
    checkPhase = ''
      PYTHONPYCACHEPREFIX=$TMPDIR/qualification-ability-pycache \
        ${pkgs.buildPackages.python3}/bin/python3 -m py_compile \
        $out/share/aos-release/qualification-ability.py

      bytecode="$(${pkgs.findutils}/bin/find "$out" \
        \( -type d -name __pycache__ -o -type f \
        \( -name '*.pyc' -o -name '*.pyo' \) \) -print -quit)"
      if [ -n "$bytecode" ]; then
        echo "Python bytecode escaped into qualification scenario: $bytecode" >&2
        exit 1
      fi
    '';
  };
  matrixCohortSupport = pkgs.runCommand "${name}-native-adapter-cohort-support" {} ''
    mkdir -p $out/share/aos-release
    cp ${./qualification-native-adapter-cohort.py} \
      $out/share/aos-release/qualification-native-adapter-cohort.py
    cp ${../../qualification/providers/native_adapter_evidence.py} \
      $out/share/aos-release/native_adapter_evidence.py
    cp ${../../qualification/providers/native_adapter_evidence_common.py} \
      $out/share/aos-release/native_adapter_evidence_common.py
    cp ${../../qualification/providers/native_adapter_runtime_evidence.py} \
      $out/share/aos-release/native_adapter_runtime_evidence.py

    PYTHONPYCACHEPREFIX=$TMPDIR/qualification-native-adapter-cohort-pycache \
      ${pkgs.buildPackages.python3}/bin/python3 -m py_compile \
      $out/share/aos-release/qualification-native-adapter-cohort.py \
      $out/share/aos-release/native_adapter_evidence.py \
      $out/share/aos-release/native_adapter_evidence_common.py \
      $out/share/aos-release/native_adapter_runtime_evidence.py

    PYTHONPYCACHEPREFIX=$TMPDIR/qualification-native-adapter-cohort-test-pycache \
      ${pkgs.buildPackages.python3}/bin/python3 \
      ${./qualification-native-adapter-cohort-self-test.py} \
      $out/share/aos-release/qualification-native-adapter-cohort.py \
      ${../../tests/fleet/native-activation-evidence.py}

  '';
  matrixCohortSupportPath =
    if nativeOperationSpec == null
    then ""
    else "${matrixCohortSupport}/share/aos-release/qualification-native-adapter-cohort.py";
  executable = pkgs.writeShellScriptBin name ''
    set -euo pipefail

    export PATH=${lib.escapeShellArg runtimePath}
    export HOME=$PWD/home
    export TMPDIR=$PWD/tmp
    export LC_ALL=C
    export AOS_QUALIFICATION_PLATFORM=${lib.escapeShellArg platform}
    export AOS_QUALIFICATION_IDENTITY=${lib.escapeShellArg identity}
    export AOS_QUALIFICATION_SCENARIO_ID=${lib.escapeShellArg scenarioId}
    export AOS_QUALIFICATION_CHECKS=${lib.escapeShellArg (builtins.toJSON checks)}
    export AOS_QUALIFICATION_FIXTURE_CONTRACT=${lib.escapeShellArg fixtureContractDigest}
    export AOS_QUALIFICATION_FIXTURE_DRIVER=${lib.escapeShellArg "${pkgs.aos.testSupport}/bin/aos-release-fleet-fixture"}
    export AOS_QUALIFICATION_FIXTURE_ARCHIVE=${lib.escapeShellArg fixtureArchive}
    export AOS_QUALIFICATION_FIXTURE_INVENTORY=${lib.escapeShellArg fixtureInventoryPath}
    export AOS_QUALIFICATION_FIXTURE_EVALUATIONS=${lib.escapeShellArg fixtureEvaluationsPath}
    export AOS_QUALIFICATION_CANDIDATE_RUNTIME_COMPANIONS=${lib.escapeShellArg (builtins.toJSON allCandidateRuntimeCompanions)}
    export AOS_QUALIFICATION_STAGING_HUB_URL=${lib.escapeShellArg (
      if stagingHubUrl == null
      then ""
      else stagingHubUrl
    )}
    export AOS_QUALIFICATION_FIXTURE_SCRIPT=${lib.escapeShellArg fixtureScript}
    export AOS_QUALIFICATION_NATIVE_OPERATION_SPEC=${lib.escapeShellArg nativeOperationSpecPath}
    export AOS_QUALIFICATION_COHORTS=${lib.escapeShellArg (builtins.toJSON qualificationCohorts)}
    export AOS_QUALIFICATION_NATIVE_ADAPTER_COHORT_SUPPORT=${lib.escapeShellArg matrixCohortSupportPath}
    export AOS_QUALIFICATION_SETUP_MODULE=${lib.escapeShellArg setupModule}
    export AOS_QUALIFICATION_IMAGE_SUPPORT=${lib.escapeShellArg "${support}/share/aos-release/qualification-image.py"}
    export AOS_QUALIFICATION_EVALUATOR=${lib.escapeShellArg "${pkgs.aos}/bin/aos"}
    export AOS_QUALIFICATION_NATIVE_CUSTODY_SUPPORT=${lib.escapeShellArg "${nativeCustodySupport}/share/aos-release/qualification-native-custody.py"}
    export AOS_QUALIFICATION_NATIVE_IMAGE_SUPPORT=${lib.escapeShellArg "${nativeImageSupport}/share/aos-release/qualification-native-image.py"}
    export AOS_QUALIFICATION_NAR_SUPPORT=${lib.escapeShellArg "${narSupport}/share/aos-release/qualification-nar.py"}
    export AOS_QUALIFICATION_QEMU=${lib.escapeShellArg qemu}
    export AOS_QUALIFICATION_QEMU_IMG=${lib.escapeShellArg "${pkgs.qemu}/bin/qemu-img"}
    export AOS_QUALIFICATION_FIRMWARE_CODE=${lib.escapeShellArg "${pkgs.edk2}/FV/OVMF_CODE.fd"}
    export AOS_QUALIFICATION_FIRMWARE_VARS=${lib.escapeShellArg "${pkgs.edk2}/FV/OVMF_VARS.fd"}
    export AOS_QUALIFICATION_SWTPM=${lib.escapeShellArg "${pkgs.swtpm}/bin/swtpm"}
    export AOS_QUALIFICATION_SGDISK=${lib.escapeShellArg "${pkgs.gptfdisk}/bin/sgdisk"}
    export AOS_QUALIFICATION_MKE2FS=${lib.escapeShellArg "${pkgs.e2fsprogs}/sbin/mke2fs"}
    export AOS_QUALIFICATION_ZSTD=${lib.escapeShellArg "${pkgs.zstd}/bin/zstd"}
    export AOS_QUALIFICATION_SSH=${lib.escapeShellArg "${pkgs.openssh}/bin/ssh"}
    export AOS_QUALIFICATION_SCP=${lib.escapeShellArg "${pkgs.openssh}/bin/scp"}
    export AOS_QUALIFICATION_SSH_KEYGEN=${lib.escapeShellArg "${pkgs.openssh}/bin/ssh-keygen"}
    export AOS_QUALIFICATION_OPENSSL=${lib.escapeShellArg "${pkgs.openssl}/bin/openssl"}
    export AOS_QUALIFICATION_OBJCOPY=${lib.escapeShellArg "${pkgs.binutils}/bin/objcopy"}
    export AOS_QUALIFICATION_NIX_STORE=${lib.escapeShellArg "${pkgs.nix}/bin/nix-store"}

    umask 077
    mkdir -p "$HOME" "$TMPDIR"
    rm -f scenario-report.json qualification-response.json qualification-response.log
    cleanup_failed_response() {
      status=$?
      if [ "$status" -ne 0 ]; then
        rm -f scenario-report.json qualification-response.json
      fi
    }
    trap cleanup_failed_response EXIT

    # The coordinator retains the same request as request.json. Draining its
    # bounded stdin writer prevents a large request from blocking execution.
    cat >/dev/null

    if ! ${pkgs.python3}/bin/python3 \
        ${scenario}/share/aos-release/qualification-ability.py \
        > scenario-execution.log 2>&1; then
      tail -c 65536 scenario-execution.log >&2
      exit 1
    fi

    if ${pkgs.aos}/bin/aos release qualification respond \
      --request request.json \
      --scenarios scenario-registry.json \
      --report scenario-report.json \
      --identity ${lib.escapeShellArg identity} \
      > qualification-response.json \
      2> qualification-response.log; then
      cat qualification-response.json
    else
      status=$?
      rm -f scenario-report.json qualification-response.json
      tail -c 65536 qualification-response.log >&2
      exit "$status"
    fi
  '';
in
  assert platform == "x86_64-linux";
  assert identity != "";
  assert builtins.elem scenarioId [
    "ability-crucible-baseline"
    "ability-native-activation"
    "ability-native-adapter-matrix"
    "ability-native-recovery"
  ];
  assert (nativeOperationSpec != null) == (scenarioId == "ability-native-adapter-matrix");
  assert qualificationCohorts != [];
  assert nativeOperationSpec != null || testScript != "";
  assert builtins.all (cohort:
    builtins.sort builtins.lessThan (builtins.attrNames cohort)
    == (
      if cohort.report.kind == "matrix"
      then ["adoptionEvaluation" "execution" "id" "matrixSpec" "qualifiedCells" "report" "requiredInputs" "script" "selectedEvaluation" "setup"]
      else ["adoptionEvaluation" "execution" "id" "qualifiedCells" "report" "requiredInputs" "script" "selectedEvaluation" "setup"]
    )
    && cohort.id != ""
    && builtins.all (input: builtins.elem input ["predecessor-image"]) cohort.requiredInputs
    && builtins.length cohort.requiredInputs == builtins.length (lib.unique cohort.requiredInputs)
    && builtins.sort builtins.lessThan (builtins.attrNames cohort.execution) == ["bootInput" "fixtureRole" "recordsGuestKernel"]
    && builtins.elem cohort.execution.bootInput ["candidate-image" "predecessor-image"]
    && (cohort.execution.fixtureRole == null || cohort.execution.fixtureRole != "")
    && builtins.isBool cohort.execution.recordsGuestKernel
    && builtins.elem cohort.execution.bootInput (["candidate-image"] ++ cohort.requiredInputs)
    && builtins.elem cohort.report.kind ["matrix" "ordinary" "release-transition"]
    && (
      if cohort.report.kind == "release-transition"
      then
        builtins.sort builtins.lessThan (builtins.attrNames cohort.report)
        == ["evidenceVariable" "expectedEvidence" "kind"]
        && cohort.report.evidenceVariable != ""
        && cohort.execution.fixtureRole != null
        && cohort.execution.bootInput == "predecessor-image"
        && builtins.sort builtins.lessThan (builtins.attrNames cohort.report.expectedEvidence)
        == ["branch" "outcome" "retired"]
        && cohort.report.expectedEvidence.branch == cohort.execution.fixtureRole
        && cohort.report.expectedEvidence.outcome != ""
        && builtins.isBool cohort.report.expectedEvidence.retired
      else builtins.attrNames cohort.report == ["kind"]
    ))
  qualificationCohorts;
  assert nativeOperationSpec
  == null
  || builtins.all (cohort: cohort.report.kind == "matrix") qualificationCohorts;
  assert !(builtins.any (cohort: cohort.report.kind == "release-transition") qualificationCohorts)
  || builtins.all (cohort: cohort.report.kind == "release-transition") qualificationCohorts;
  assert (nativeOperationCohorts != []) == (nativeOperationSpec != null);
  assert nativeOperationSpec
  == null
  || map (cohort: {
    inherit (cohort) id;
    matrix_spec = cohort.matrixSpec;
    selected_evaluation = cohort.selectedEvaluation;
    adoption_evaluation = cohort.adoptionEvaluation;
  })
  matrixCohortInputs
  == nativeOperationSpec.cohorts;
  assert builtins.all (cohort:
    cohort.qualifiedCells
    == cohort.matrixSpec.applicability.applicable_cell_ids
    && cohort.qualifiedCells != [])
  matrixCohortInputs;
  assert builtins.length matrixCohortInputs == builtins.length (lib.unique (map (cohort: cohort.id) matrixCohortInputs));
  assert builtins.all (cohort:
    (cohort.id
      != ""
      && cohort.qualifiedCells != []
      && cohort.testScript != ""
      && cohort.candidateRuntimeCompanions != [])
    || throw "native adapter matrix cohort '${cohort.id}' is incomplete: ${toString (builtins.length cohort.qualifiedCells)} cells, ${toString (builtins.length cohort.candidateRuntimeCompanions)} companions, ${toString (builtins.stringLength cohort.testScript)} script bytes")
  nativeOperationCohorts;
  assert checks != [];
  assert (stagingHubUrl != null) == requiresStagingHub;
  assert stagingHubUrl == null || builtins.match "https://[^/]+/?" stagingHubUrl != null;
    executable
    // {
      passthru =
        (executable.passthru or {})
        // {
          qualification = {
            inherit
              checks
              fixtureArchive
              fixtureArchiveRoot
              fixtureInventoryPath
              fixtureEvaluationsPath
              fixtureContractDigest
              fixtureRoots
              fixtureScript
              nativeOperationSpecPath
              matrixCohortSupport
              narSupport
              nativeImageSupport
              nativeCustodySupport
              scenarioId
              setupModule
              ;
            imageVariant = "server";
            publishedGuestTools = true;
          };
        };
    }
