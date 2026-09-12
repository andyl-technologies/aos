##! Executes one native ability contract or adapter cohort against an exact published server image.
{
  pkgs,
  lib,
}: {
  name,
  identity,
  scenarioId,
  checks,
  testScript,
  setupBody,
  extraClosures,
  candidateRuntimeCompanions,
  stagingHubUrl ? null,
  matrixSpec ? null,
  matrixQualifiedCells ? [],
  matrixAdditionalCohorts ? [],
}: let
  platform = pkgs.stdenv.hostPlatform.system;
  fixtureScriptRoot = pkgs.writeTextFile {
    name = "${name}-fleet-script";
    destination = "/script.py";
    text = testScript;
  };
  fixtureScript = "${fixtureScriptRoot}/script.py";
  matrixSpecRoot =
    if matrixSpec == null
    then null
    else
      pkgs.writeTextFile {
        name = "${name}-native-adapter-matrix";
        destination = "/matrix-spec.json";
        text = builtins.toJSON matrixSpec;
      };
  matrixSpecPath =
    if matrixSpecRoot == null
    then ""
    else "${matrixSpecRoot}/matrix-spec.json";
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
    cohort
    // {
      inherit scriptRoot setupRoot;
      script = "${scriptRoot}/script.py";
      setup = "${setupRoot}/module.nix";
    })
  matrixAdditionalCohorts;
  allCandidateRuntimeCompanions =
    candidateRuntimeCompanions
    ++ lib.concatMap (cohort: cohort.candidateRuntimeCompanions) additionalCohorts;
  additionalQualifiedCells = lib.concatMap (cohort: cohort.qualifiedCells) additionalCohorts;
  primaryQualifiedCells =
    builtins.filter (
      cellId: !builtins.elem cellId additionalQualifiedCells
    )
    matrixQualifiedCells;
  matrixCohortInputs =
    lib.optional (matrixSpec != null) {
      id = "managed-configuration-negative";
      script = fixtureScript;
      setup = setupModule;
      qualifiedCells = primaryQualifiedCells;
    }
    ++ map (cohort: {
      inherit (cohort) id script setup qualifiedCells;
    })
    additionalCohorts;
  fixtureRoots = lib.unique (
    map builtins.toString (
      [fixtureScriptRoot setupModuleRoot]
      ++ lib.concatMap (cohort: [cohort.scriptRoot cohort.setupRoot]) additionalCohorts
      ++ lib.optional (matrixSpecRoot != null) matrixSpecRoot
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
  fixtureContractDigest = "sha256:${builtins.hashString "sha256" (builtins.toJSON (
    {
      inherit scenarioId checks setupBody;
      candidateRuntimeCompanions = allCandidateRuntimeCompanions;
      roots = fixtureRoots;
      script = testScript;
    }
    // lib.optionalAttrs (matrixSpec != null) {
      matrixCohorts = matrixCohortInputs;
      inherit matrixQualifiedCells matrixSpec;
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
  matrixCohortSupport = pkgs.writeTextFile {
    name = "${name}-native-adapter-cohort-support";
    destination = "/share/aos-release/qualification-native-adapter-cohort.py";
    text = builtins.readFile ./qualification-native-adapter-cohort.py;
    checkPhase = ''
      PYTHONPYCACHEPREFIX=$TMPDIR/qualification-native-adapter-cohort-pycache \
        ${pkgs.buildPackages.python3}/bin/python3 -m py_compile \
        $out/share/aos-release/qualification-native-adapter-cohort.py

      PYTHONPYCACHEPREFIX=$TMPDIR/qualification-native-adapter-cohort-test-pycache \
        ${pkgs.buildPackages.python3}/bin/python3 \
        ${./qualification-native-adapter-cohort-self-test.py} \
        $out/share/aos-release/qualification-native-adapter-cohort.py

      PYTHONPYCACHEPREFIX=$TMPDIR/qualification-native-adapter-effect-test-pycache \
        ${pkgs.buildPackages.python3}/bin/python3 \
        ${./qualification-native-adapter-effect-self-test.py} \
        $out/share/aos-release/qualification-native-adapter-cohort.py \
        ${../..}/tests/fleet/ability-effect-boundary-evidence.py
    '';
  };
  matrixCohortSupportPath =
    if matrixSpec == null
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
    export AOS_QUALIFICATION_FIXTURE_ARCHIVE=${lib.escapeShellArg fixtureArchive}
    export AOS_QUALIFICATION_CANDIDATE_RUNTIME_COMPANIONS=${lib.escapeShellArg (builtins.toJSON allCandidateRuntimeCompanions)}
    export AOS_QUALIFICATION_STAGING_HUB_URL=${lib.escapeShellArg (
      if stagingHubUrl == null
      then ""
      else stagingHubUrl
    )}
    export AOS_QUALIFICATION_FIXTURE_SCRIPT=${lib.escapeShellArg fixtureScript}
    export AOS_QUALIFICATION_NATIVE_ADAPTER_MATRIX_SPEC=${lib.escapeShellArg matrixSpecPath}
    export AOS_QUALIFICATION_NATIVE_ADAPTER_QUALIFIED_CELLS=${lib.escapeShellArg (builtins.toJSON matrixQualifiedCells)}
    export AOS_QUALIFICATION_NATIVE_ADAPTER_COHORTS=${lib.escapeShellArg (builtins.toJSON matrixCohortInputs)}
    export AOS_QUALIFICATION_NATIVE_ADAPTER_COHORT_SUPPORT=${lib.escapeShellArg matrixCohortSupportPath}
    export AOS_QUALIFICATION_SETUP_MODULE=${lib.escapeShellArg setupModule}
    export AOS_QUALIFICATION_IMAGE_SUPPORT=${lib.escapeShellArg "${support}/share/aos-release/qualification-image.py"}
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
    "ability-native-image-rollout"
    "ability-native-kubernetes"
    "ability-native-postgresql"
    "ability-native-recovery"
  ];
  assert (matrixSpec != null) == (scenarioId == "ability-native-adapter-matrix");
  assert (matrixQualifiedCells != []) == (matrixSpec != null);
  assert matrixQualifiedCells == lib.concatMap (cohort: cohort.qualifiedCells) matrixCohortInputs;
  assert builtins.length matrixQualifiedCells == builtins.length (lib.unique matrixQualifiedCells);
  assert builtins.length matrixCohortInputs == builtins.length (lib.unique (map (cohort: cohort.id) matrixCohortInputs));
  assert builtins.all (cohort:
    cohort.id
    != ""
    && cohort.qualifiedCells != []
    && cohort.testScript != ""
    && cohort.candidateRuntimeCompanions != [])
  matrixAdditionalCohorts;
  assert checks != [];
  assert (stagingHubUrl != null) == (scenarioId == "ability-native-image-rollout");
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
              fixtureContractDigest
              fixtureRoots
              fixtureScript
              matrixQualifiedCells
              matrixSpecPath
              narSupport
              scenarioId
              setupModule
              ;
            imageVariant = "server";
            publishedGuestTools = true;
          };
        };
    }
