# Builds GCC 11's private shell with the completed GCC 8 target toolchain.
{
  prev,
  buildPlatform,
  hostPlatform,
  targetPlatform,
}: let
  lib = import ../../../lib {
    system = buildPlatform.system;
    bash = prev.bash;
  };

  mkTierStdenv = import ../../tier-stdenv.nix {
    inherit lib buildPlatform hostPlatform targetPlatform;
  };

  mkTool = import ../lib/mk-autotools-tool.nix {
    inherit lib buildPlatform hostPlatform;
    phases = import ../../phases.nix;
    tierStdenv = mkTierStdenv {
      tc = prev;
      staticDefault = true;
    };
  };

  manifest = import ./manifest.nix {
    inherit buildPlatform hostPlatform;
    inherit (prev) m4 flex bison perl autoconf automake texinfo help2man;
  };
in
  mkTool (manifest.bash
    // {
      name = "bash-5.1-gcc11-bootstrap";
      gccVersion = "8.5.0";
      postInstall =
        manifest.bash.postInstall
        + ''
          # Automake tests make flags in a failing subshell before entering another.
          "$out/bin/bash" -c 'if (false); then exit 1; fi; (true && true)'
        '';
    })
