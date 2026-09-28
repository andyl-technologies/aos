##! Bazel 9 — build tool
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
    unitId = "bazel-9";
    family = "bazel";
    stream = "9";
    owner = "pkgs/toolchain/bazel-9.nix";
    member = "bazel-9";
    version = "9.2.0";
    reason = "Bazel source and repository dependencies form one curated artifact graph that requires maintainer review.";
    successorUnit = "bazel-9";
  };
  # Bootstrap tools execute on the Linux build host for every output target.
  bootstrapArguments =
    builtins.intersectAttrs
    (builtins.functionArgs (import ./bazel-bootstrap.nix))
    buildPackages;
  bazelBootstrap9 = callPackage ./bazel-bootstrap.nix (bootstrapArguments
    // {
      inherit buildPackages;
      bootstrapVersion = "9.2.0";
    });
  preparedSource = import ./_bazel-source-9-prepared.nix {
    inherit buildPackages;
    inherit (buildPackages) mkDerivation fetchurl;
    bazelSource9 = bazelBootstrap9.passthru.offlineSource;
    bazelJacoco = bazelBootstrap9.passthru.offlineJacoco;
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
      qemu-img
      bootstrapTools
      gcc-libs
      llvm
      ;
    bazel-bootstrap = bazelBootstrap9;
    nativeBazelBootstrap = bazelBootstrap9;
  };
in
  mkBazel {
    inherit (upstream) version update;
    source = preparedSource;
    srcHash = "sha256-ga8CszEo7BkixrYCEt8/thULqpa7M9Mv+gIOX+1H/vw=";
    vendorDepsHash = "sha256-T8v/c1qFiVTTSnlhUW30TPZZ0bk6VQ9gO6IUnFoMS8s=";
  }
