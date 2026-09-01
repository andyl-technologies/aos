##! Bazel 7 — build tool
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
    version = "7.7.1";
    srcHash = "sha256-YYGzVwwvZX2YmxFB+wwaCOtfCBBspXfcfcUufQI4N5o=";
    vendorDepsHash = "sha256-UIedT89X6y12snR54HGoZyLuFaHupcSDxu9ZibkzYeA=";
  }
