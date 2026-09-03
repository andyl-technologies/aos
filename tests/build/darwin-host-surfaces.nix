# Evaluation contract for native Darwin development-shell inputs.
{pkgs}: let
  lib = pkgs.lib;
  buildSystem = pkgs.stdenv.buildPlatform.system;
  targetSystems = [
    "x86_64-darwin"
    "aarch64-darwin"
  ];

  contractFor = targetSystem: let
    aos = import ../.. {
      system = buildSystem;
      crossSystem = targetSystem;
    };
    shell = import ../../lib/flake-dev-shell.nix {
      inherit aos;
      system = targetSystem;
    };
    packagePaths = map toString shell.passthru.packages;
    requiredPackages = [
      aos.pkgs.bash
      aos.pkgs.cc
      aos.pkgs.coreutils
      aos.pkgs.nix
      aos.pkgs.rust
      aos.pkgs.rust.dev
    ];
    requiredPathsPresent =
      builtins.all (
        package: builtins.elem (toString package) packagePaths
      )
      requiredPackages;
    cliOutputs = map (package: package.outputName or "out") (
      builtins.filter (package: (package.pname or "") == "aos") shell.passthru.packages
    );
    cargoPrefix =
      if targetSystem == "aarch64-darwin"
      then "AARCH64_APPLE_DARWIN"
      else "X86_64_APPLE_DARWIN";
  in
    assert shell.system == targetSystem;
    assert shell.passthru.hostSystem == targetSystem;
    assert shell.passthru.targetSystem == targetSystem;
    assert shell.passthru.buildSystem == buildSystem;
    assert requiredPathsPresent;
    assert builtins.all (output: builtins.elem output cliOutputs) ["out" "apm" "apr"];
    assert !(builtins.elem (toString aos.pkgs.bootstrapTools) packagePaths);
    assert lib.hasInfix "CARGO_TARGET_${cargoPrefix}_RUSTFLAGS" shell.shellHook;
    assert lib.hasInfix "CARGO_TARGET_${cargoPrefix}_LINKER" shell.shellHook;
    assert lib.hasInfix "export SDKROOT=\"${aos.stdenv.sdk}\"" shell.shellHook; {
      inherit shell targetSystem;
      packageCount = builtins.length packagePaths;
      drvPath = builtins.unsafeDiscardStringContext shell.drvPath;
    };

  contracts = map contractFor targetSystems;
in
  pkgs.mkDerivation {
    pname = "darwin-host-surfaces-check";
    version = "0";
    src = null;
    preferLocalBuild = true;
    allowSubstitutes = false;

    phases = [
      {
        name = "check";
        script = ''
          mkdir -p "$out"
          cat > "$out/result" <<'EOF'
          ${lib.concatMapStringsSep "\n" (contract: "${contract.targetSystem} ${toString contract.packageCount} ${contract.drvPath}") contracts}
          EOF
        '';
      }
    ];
  }
