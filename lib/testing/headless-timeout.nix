# Focused host controls for the actual evaluated headless Firecracker phase.
{
  pkgs,
  lib,
}: let
  vm = import ./vm.nix {inherit pkgs lib;};
  args = {
    name = "headless-timeout-control";
    rootfsDeps = [];
    testScript = "exit 0";
  };
  phase = extra: (builtins.head (vm.mkVMTest (args // extra)).passthru.phases).script;
  phases = {
    default = phase {};
    null = phase {timeout = null;};
    bounded = phase {timeout = 1;};
    fractional = phase {timeout = 0.25;};
    tiny = phase {timeout = 0.0000001;};
    pinned = phase {
      timeout = 1;
      hostCpuPin = true;
    };
  };
  refused = timeout: !(builtins.tryEval (phase {inherit timeout;})).success;
  phaseFiles = builtins.mapAttrs (name: text:
    pkgs.writeTextFile {
      name = "headless-timeout-${name}.bash";
      inherit text;
      destination = "/phase.bash";
    })
  phases;
  configuration = pkgs.writeTextFile {
    name = "headless-timeout-controls.json";
    destination = "/configuration.json";
    text = builtins.toJSON {
      bash = "${pkgs.bash}/bin/bash";
      child = "./firecracker";
      phases = builtins.mapAttrs (_: file: "${file}/phase.bash") phaseFiles;
    };
  };
in
  assert phases.default == phases.null;
  assert !(lib.hasInfix "/bin/timeout " phases.default);
  assert refused 0 && refused (-1);
  assert lib.hasInfix "timeout --foreground -k 15 1 " phases.bounded;
  assert lib.hasInfix "timeout --foreground -k 15 0.25 " phases.fractional;
  assert lib.hasInfix "timeout --foreground -k 15 1e-07 " phases.tiny;
    pkgs.mkDerivation {
      pname = "headless-timeout-controls";
      version = "0";
      src = null;
      buildDeps = [pkgs.bash pkgs.coreutils pkgs.grep pkgs.sed pkgs.python3 pkgs.util-linux];
      phases = [
        {
          name = "check";
          script = ''
              set -eu
              cc -O2 -Wall -Wextra -Werror ${./headless-timeout-child.c} -o firecracker
              export PATH="$PWD:$PATH"
            ${pkgs.python3}/bin/python3 -B ${./headless-timeout.py} ${configuration}/configuration.json
              mkdir -p "$out"
              cp controls.json "$out/controls.json"
              cp -r controls "$out/controls"
              echo PASS > "$out/result"
          '';
        }
      ];
    }
