##! Linux-hosted GNU cross-toolchain assembly.
{
  buildStdenv,
  buildPackages,
  buildPlatform,
  hostPlatform,
}: let
  sources = import ./sources.nix;

  binutils = import ./binutils.nix {
    inherit buildStdenv buildPackages buildPlatform hostPlatform sources;
  };

  linuxHeaders = import ./linux-headers.nix {
    inherit buildStdenv buildPackages buildPlatform hostPlatform sources;
  };

  gccStage1 = import ./gcc.nix {
    inherit
      buildStdenv
      buildPackages
      buildPlatform
      hostPlatform
      sources
      binutils
      linuxHeaders
      ;
    stage = "stage1";
  };

  glibc = import ./glibc.nix {
    inherit
      buildStdenv
      buildPackages
      buildPlatform
      hostPlatform
      sources
      binutils
      linuxHeaders
      gccStage1
      ;
  };

  gccDerivation = import ./gcc.nix {
    inherit
      buildStdenv
      buildPackages
      buildPlatform
      hostPlatform
      sources
      binutils
      linuxHeaders
      ;
    libc = glibc;
    stage = "final";
  };
  gcc =
    gccDerivation
    // {
      passthru =
        (gccDerivation.passthru or {})
        // {
          evidenceSources = [
            sources.gcc
            sources.gmp
            sources.mpfr
            sources.mpc
            sources.isl
          ];
        };
    };

  gccRuntime = import ./gcc-runtime.nix {
    inherit buildStdenv buildPlatform hostPlatform binutils gcc;
  };
in {
  inherit gcc gccRuntime binutils glibc linuxHeaders;
}
