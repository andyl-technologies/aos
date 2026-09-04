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

  gcc = import ./gcc.nix {
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
in {
  inherit gcc binutils glibc linuxHeaders;
}
