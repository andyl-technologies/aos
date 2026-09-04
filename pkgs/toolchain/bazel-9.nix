##! Bazel 9 — build tool
{
  mkDerivation,
  mkManualUpstream,
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
  bazel-bootstrap,
  bootstrapTools,
  gcc-libs,
  llvm,
}: let
  upstream = mkManualUpstream {
    unitId = "bazel-9";
    family = "bazel";
    stream = "9";
    owner = "pkgs/toolchain/bazel-9.nix";
    member = "bazel-9";
    version = "9.0.1";
    reason = "Bazel source and repository dependencies form one curated artifact graph that requires maintainer review.";
  };
  mkBazel = import ./_bazel.nix {
    inherit
      mkDerivation
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
      bazel-bootstrap
      bootstrapTools
      gcc-libs
      llvm
      ;
  };
in
  mkBazel {
    inherit (upstream) version update;
    srcHash = "sha256-PzNrRRCoIQ+VT6On1s+9JxtvnWOXMv3BHAALb7/KP74=";
    vendorDepsHash = "sha256-Lk2PZdE1eT4opu/TWQy5glbrIOBTlScNO1CA79X7S3Y=";
  }
