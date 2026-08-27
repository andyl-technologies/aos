##! Bazel 9 — build tool
{
  mkDerivation,
  fetchurl,
  lib,
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
  bazel-bootstrap,
  bootstrapTools,
  gcc-libs,
}: let
  mkBazel = import ./_bazel.nix {
    inherit
      mkDerivation
      fetchurl
      lib
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
      bazel-bootstrap
      bootstrapTools
      gcc-libs
      ;
  };
in
  mkBazel {
    version = "9.0.1";
    srcHash = "sha256-PzNrRRCoIQ+VT6On1s+9JxtvnWOXMv3BHAALb7/KP74=";
    vendorDepsHash = "sha256-5uXnaXDvl0DAzg0V7Z2JKki5u7ISLL58DltwQgIeUvc=";
  }
