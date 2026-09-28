##! Bazel — build tool (default = Bazel 9)
{
  mkDerivation,
  mkManualUpstream,
  callPackage,
  fetchurl,
  lib,
  stdenv,
  buildPackages,
  bash,
  coreutils,
  which,
  zip,
  unzip,
  gawk,
  python3,
  openjdk-21,
  gcc,
  binutils,
  grep,
  gzip,
  patch,
  diffutils,
  findutils,
  sed,
  tar,
  xz,
  file,
  patchelf,
  qemu-img,
  bootstrapTools,
  gcc-libs,
  llvm,
}: let
  target = import ./bazel-9.nix {
    inherit
      mkDerivation
      mkManualUpstream
      callPackage
      fetchurl
      lib
      stdenv
      buildPackages
      bash
      coreutils
      which
      zip
      unzip
      gawk
      python3
      openjdk-21
      gcc
      binutils
      grep
      gzip
      patch
      diffutils
      findutils
      sed
      tar
      xz
      file
      patchelf
      qemu-img
      bootstrapTools
      gcc-libs
      llvm
      ;
  };
in
  target
  // {
    passthru =
      (target.passthru or {})
      // {
        aos = builtins.removeAttrs (target.passthru.aos or {}) ["maintenance"];
      };
  }
