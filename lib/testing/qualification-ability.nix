##! Executes one native ability contract against an exact published server image.
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
}: let
  platform = pkgs.stdenv.hostPlatform.system;
  fixtureScriptRoot = pkgs.writeTextFile {
    name = "${name}-fleet-script";
    destination = "/script.py";
    text = testScript;
  };
  fixtureScript = "${fixtureScriptRoot}/script.py";
  setupModuleRoot = pkgs.writeTextFile {
    name = "${name}-setup";
    destination = "/module.nix";
    text = ''
      { pkgs, ... }: {
        ${setupBody}
      }
    '';
  };
  setupModule = "${setupModuleRoot}/module.nix";
  fixtureRoots = lib.unique (
    map builtins.toString ([fixtureScriptRoot setupModuleRoot] ++ extraClosures)
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
  fixtureContractDigest = "sha256:${builtins.hashString "sha256" (builtins.toJSON {
    inherit candidateRuntimeCompanions scenarioId checks setupBody;
    roots = fixtureRoots;
    script = testScript;
  })}";
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
    export AOS_QUALIFICATION_CANDIDATE_RUNTIME_COMPANIONS=${lib.escapeShellArg (builtins.toJSON candidateRuntimeCompanions)}
    export AOS_QUALIFICATION_FIXTURE_SCRIPT=${lib.escapeShellArg fixtureScript}
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
    "ability-native-activation"
    "ability-native-kubernetes"
    "ability-native-postgresql"
    "ability-native-recovery"
  ];
  assert checks != [];
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
              narSupport
              scenarioId
              setupModule
              ;
            imageVariant = "server";
            publishedGuestTools = true;
          };
        };
    }
