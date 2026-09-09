##! Exercises one published package cell through APM and a reviewed probe.
{
  pkgs,
  lib,
}: {
  name,
  identity,
  packageNames,
  probes,
  trustKeys,
  stagingHubUrl ? "https://aos.staging.andyl.org",
}: let
  sortedPackageNames = builtins.sort builtins.lessThan packageNames;
  probeNames = builtins.attrNames probes;
  missingProbeNames =
    builtins.filter (
      packageName: !(builtins.hasAttr packageName probes)
    )
    sortedPackageNames;
  probeRegistry = pkgs.writeTextFile {
    name = "${name}-probes";
    destination = "/probes.json";
    text = builtins.toJSON {
      schema_version = "aos.release.package-probes/v1";
      packages = probes;
    };
  };
  scenario = pkgs.writeTextFile {
    name = "${name}-scenario";
    destination = "/share/aos-release/qualification-package.py";
    text = builtins.readFile ./qualification-package.py;
    checkPhase = ''
      PYTHONPYCACHEPREFIX=$TMPDIR/qualification-package-pycache \
        ${pkgs.buildPackages.python3}/bin/python3 -m py_compile \
        $out/share/aos-release/qualification-package.py
    '';
  };
  k3sBindings = pkgs.writeTextFile {
    name = "${name}-k3s-bindings";
    destination = "/qualification_k3s_bindings.py";
    text = builtins.readFile ./qualification_k3s_bindings.py;
  };
  runtimePath = lib.makeBinPath [
    pkgs.bash
    pkgs.coreutils
    pkgs.git
    pkgs.grep
    pkgs.nix
    pkgs.python3
    pkgs.zstd
  ];
  executor = pkgs.writeShellScriptBin name ''
    set -euo pipefail

    export PATH=${lib.escapeShellArg runtimePath}
    export HOME=$PWD/home
    export USER=aos-qualification
    export XDG_CACHE_HOME=$HOME/.cache
    export XDG_CONFIG_HOME=$HOME/.config
    export XDG_DATA_HOME=$HOME/.local/share
    export XDG_STATE_HOME=$HOME/.local/state
    export TMPDIR=$PWD/tmp
    export AOS_PROFILE_ROOT=$PWD/profiles
    export APM_SYSTEM_CONFIG_DIR=$PWD/empty-system-config
    export LC_ALL=C
    export PYTHONPATH=${k3sBindings}

    export AOS_QUALIFICATION_PLATFORM=${lib.escapeShellArg pkgs.stdenv.hostPlatform.system}
    export AOS_QUALIFICATION_IDENTITY=${lib.escapeShellArg identity}
    export AOS_QUALIFICATION_PROBES=${lib.escapeShellArg "${probeRegistry}/probes.json"}
    export AOS_QUALIFICATION_TRUST_KEYS=${lib.escapeShellArg (builtins.toJSON trustKeys)}
    export AOS_QUALIFICATION_STAGING_HUB_URL=${lib.escapeShellArg stagingHubUrl}
    export AOS_QUALIFICATION_APM=${lib.escapeShellArg "${pkgs.aos.apm}/bin/apm"}
    export AOS_QUALIFICATION_NIX_STORE=${lib.escapeShellArg "${pkgs.nix}/bin/nix-store"}
    export AOS_QUALIFICATION_ZSTD=${lib.escapeShellArg "${pkgs.zstd}/bin/zstd"}
    export AOS_QUALIFICATION_UNAME=${lib.escapeShellArg "${pkgs.coreutils}/bin/uname"}
    export AOS_QUALIFICATION_BASH=${lib.escapeShellArg "${pkgs.bash}/bin/bash"}
    export AOS_QUALIFICATION_CC=${lib.escapeShellArg "${pkgs.cc}/bin/cc"}
    export AOS_QUALIFICATION_CXX=${lib.escapeShellArg "${pkgs.cc}/bin/c++"}
    export AOS_QUALIFICATION_PYTHON=${lib.escapeShellArg "${pkgs.python3}/bin/python3"}

    umask 077
    mkdir -p \
      "$HOME" "$TMPDIR" "$AOS_PROFILE_ROOT" "$APM_SYSTEM_CONFIG_DIR"

    # The coordinator retained this exact canonical request beside the
    # downloaded objects. Drain stdin so its bounded writer always exits.
    cat >/dev/null

    ${pkgs.python3}/bin/python3 \
      ${scenario}/share/aos-release/qualification-package.py

    exec ${pkgs.aos}/bin/aos release qualification respond \
      --request request.json \
      --scenarios scenario-registry.json \
      --report scenario-report.json \
      --identity ${lib.escapeShellArg identity}
  '';
in
  assert identity != "";
  assert packageNames != [];
  assert builtins.length sortedPackageNames == builtins.length (lib.unique sortedPackageNames);
  # Partial registries let reviewed probes land incrementally. A request for
  # any missing package still fails before the scenario can write a report.
  assert builtins.all (packageName: builtins.elem packageName sortedPackageNames) probeNames;
  assert trustKeys != [];
  assert builtins.all (key: builtins.match "[A-Za-z0-9_-]+:Ed25519:[A-Za-z0-9+/]+=*" key != null) trustKeys;
  assert builtins.match "https://[^/]+/?" stagingHubUrl != null;
    executor
    // {
      passthru =
        (executor.passthru or {})
        // {
          qualification = {
            inherit identity packageNames stagingHubUrl trustKeys;
            platform = pkgs.stdenv.hostPlatform.system;
            probes = probeNames;
            missingProbes = missingProbeNames;
            probeCoverage = {
              complete = missingProbeNames == [];
              implemented = builtins.length probeNames;
              total = builtins.length sortedPackageNames;
            };
            probeRegistry = "${probeRegistry}/probes.json";
          };
        };
    }
