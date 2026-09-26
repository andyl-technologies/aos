##! Exercises one published package cell through APM and a reviewed probe.
{
  pkgs,
  lib,
}: {
  name,
  identity,
  packageNames,
  checks,
  trustKeys,
  stagingHubUrl ? "https://aos.staging.andyl.org",
}: let
  sortedPackageNames = builtins.sort builtins.lessThan packageNames;
  mkPackageProbe = import ./qualification-package-probe.nix {inherit pkgs lib;};
  packageProbeSpec = import ./qualification-package-spec.nix {inherit lib;};
  harnessNamesIn = value:
    if builtins.isList value
    then builtins.concatMap harnessNamesIn value
    else if builtins.isAttrs value
    then
      if (value.kind or null) == "harness"
      then [value.tool]
      else builtins.concatMap harnessNamesIn (builtins.attrValues value)
    else [];
  requiredHarnessNames = builtins.sort builtins.lessThan (lib.unique (builtins.concatMap (packageName:
    harnessNamesIn pkgs.${packageName}.contract.value.qualification.package_probe)
  sortedPackageNames));
  # Python drives every probe. Other tools enter the executor closure only
  # when a typed harness fragment requests them.
  optionalHarnesses = {
    bash = {
      variable = "AOS_QUALIFICATION_BASH";
      executable = "${pkgs.bash}/bin/bash";
    };
    "c-compiler" = {
      variable = "AOS_QUALIFICATION_CC";
      executable = "${pkgs.cc}/bin/cc";
    };
    "cxx-compiler" = {
      variable = "AOS_QUALIFICATION_CXX";
      executable = "${pkgs.cc}/bin/c++";
    };
    perl = {
      variable = "AOS_QUALIFICATION_PERL";
      executable = "${pkgs.perl}/bin/perl";
    };
    "rust-compiler" = {
      variable = "AOS_QUALIFICATION_RUSTC";
      executable = "${pkgs.rust}/bin/rustc";
    };
  };
  optionalHarnessNames = builtins.filter (name: name != "python") requiredHarnessNames;
  optionalHarnessVariables =
    map
    (name: optionalHarnesses.${name}.variable)
    (builtins.attrNames optionalHarnesses);
  optionalHarnessExports = builtins.concatStringsSep "\n" (map (name: let
    harness = optionalHarnesses.${name} or (throw "unknown qualification harness '${name}'");
  in "export ${harness.variable}=${lib.escapeShellArg harness.executable}")
  optionalHarnessNames);
  probeFor = packageName: let
    package = pkgs.${packageName};
    contract = package.contract or (throw "qualification package '${packageName}' has no contract");
    packageProbe = contract.value.qualification.package_probe or (throw "qualification package '${packageName}' has no package probe");
  in
    mkPackageProbe {
      name = packageName;
      spec = packageProbeSpec {inherit packageName packageProbe;};
    };
  probes = builtins.listToAttrs (map (packageName: {
      name = packageName;
      value = probeFor packageName;
    })
    sortedPackageNames);
  probeNames = builtins.attrNames probes;
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

    export AOS_QUALIFICATION_PLATFORM=${lib.escapeShellArg pkgs.stdenv.hostPlatform.system}
    export AOS_QUALIFICATION_IDENTITY=${lib.escapeShellArg identity}
    export AOS_QUALIFICATION_CHECKS=${lib.escapeShellArg (builtins.toJSON checks)}
    export AOS_QUALIFICATION_PROBES=${lib.escapeShellArg "${probeRegistry}/probes.json"}
    export AOS_QUALIFICATION_TRUST_KEYS=${lib.escapeShellArg (builtins.toJSON trustKeys)}
    export AOS_QUALIFICATION_STAGING_HUB_URL=${lib.escapeShellArg stagingHubUrl}
    export AOS_QUALIFICATION_APM=${lib.escapeShellArg "${pkgs.aos.apm}/bin/apm"}
    export AOS_QUALIFICATION_NIX_STORE=${lib.escapeShellArg "${pkgs.nix}/bin/nix-store"}
    export AOS_QUALIFICATION_ZSTD=${lib.escapeShellArg "${pkgs.zstd}/bin/zstd"}
    export AOS_QUALIFICATION_UNAME=${lib.escapeShellArg "${pkgs.coreutils}/bin/uname"}
    unset ${builtins.concatStringsSep " " optionalHarnessVariables}
    ${optionalHarnessExports}
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
  assert checks != [];
  assert builtins.all builtins.isString checks;
  assert builtins.length checks == builtins.length (lib.unique checks);
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
            probeRegistry = "${probeRegistry}/probes.json";
          };
        };
    }
