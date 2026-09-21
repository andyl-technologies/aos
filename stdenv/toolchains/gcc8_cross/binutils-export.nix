##! Keeps static linking in the public binutils compiler frontend.
args @ {
  prev,
  crossGccStage2,
  crossBinutils,
  crossGlibc,
  buildPlatform,
  hostPlatform,
  ...
}: let
  # Libtool strips -static from LDFLAGS; the compiler frontend must retain it.
  compiler = import ../lib/retarget-compiler.nix {
    compiler = crossGccStage2;
    gccVersion = "8.5.0";
    glibc = crossGlibc;
    binutils = crossBinutils;
    buildTools = prev;
    inherit buildPlatform hostPlatform;
  };
in
  import ./binutils.nix (args
    // {
      cc = "${compiler}/bin/gcc";
      cxx = "${compiler}/bin/g++";
    })
