##! Bazel 8 — build tool
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
  upstream = mkManualUpstream {
    unitId = "bazel-8";
    family = "bazel";
    stream = "8";
    owner = "pkgs/toolchain/bazel-8.nix";
    member = "bazel-8";
    version = "8.6.0";
    reason = "Bazel source and repository dependencies form one curated artifact graph that requires maintainer review.";
    successorUnit = "bazel-9";
  };
  # The bootstrap runs on the Linux build machine even for Darwin outputs.
  bootstrapArguments =
    builtins.intersectAttrs
    (builtins.functionArgs (import ./bazel-bootstrap.nix))
    buildPackages;
  bazelBootstrap8 = callPackage ./bazel-bootstrap.nix (bootstrapArguments
    // {
      inherit buildPackages;
      bootstrapVersion = "8.6.0";
    });
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
      qemu-img
      bootstrapTools
      gcc-libs
      llvm
      ;
    bazel-bootstrap = bazelBootstrap8;
    nativeBazelBootstrap = bazelBootstrap8;
  };
in
  mkBazel {
    inherit (upstream) version update;
    source = bazelBootstrap8.passthru.offlineSource8Prepared;
    srcHash = "sha256-E6hFhkKbYISxO9UEDXje2ljVIwEhUecefUvgxj3YMfk=";
    vendorDepsHash = "sha256-dQ80bgW+bLADowhNA5IDSxkBnRC2rqbaUhqoFs2LwO0=";
  }
