##! Bazel 8 — build tool
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
    version = "8.6.0";
    srcHash = "sha256-E6hFhkKbYISxO9UEDXje2ljVIwEhUecefUvgxj3YMfk=";
    vendorDepsHash = "sha256-vfJK+o/us+cwar8YVr+7c85qn2Umsx0qUrcUcj7XjeM=";
  }
