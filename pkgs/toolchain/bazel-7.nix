##! Bazel 7 — build tool
{
  mkDerivation,
  mkManualUpstream,
  fetchurl,
  fetchgit,
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
    unitId = "bazel-7";
    family = "bazel";
    stream = "7";
    owner = "pkgs/toolchain/bazel-7.nix";
    member = "bazel-7";
    version = "7.7.1";
    reason = "Bazel source and repository dependencies form one curated artifact graph that requires maintainer review.";
    successorUnit = "bazel-8";
  };
  bazelAsm = import ./_bazel-asm.nix {
    mkDerivation = buildPackages.mkDerivation;
    fetchurl = buildPackages.fetchurl;
    inherit buildPackages;
  };
  bazelMavenBootstrap = import ./_bazel-maven-bootstrap.nix {
    mkDerivation = buildPackages.mkDerivation;
    fetchurl = buildPackages.fetchurl;
    inherit buildPackages;
  };
  bazelGrpcJavaPlugin = import ./_bazel-grpc-java-plugin.nix {
    mkDerivation = buildPackages.mkDerivation;
    inherit fetchgit buildPackages;
    protobuf = buildPackages.protobuf;
    abseil-cpp = buildPackages.abseil-cpp;
    zlib = buildPackages.zlib;
  };
  bazelSource = import ./_bazel-source.nix {
    inherit fetchgit buildPackages;
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
    inherit bazelAsm bazelMavenBootstrap bazelGrpcJavaPlugin;
  };
in
  mkBazel {
    inherit (upstream) version update;
    source = bazelSource;
    srcHash = "sha256-YYGzVwwvZX2YmxFB+wwaCOtfCBBspXfcfcUufQI4N5o=";
    vendorDepsHash = "sha256-UIedT89X6y12snR54HGoZyLuFaHupcSDxu9ZibkzYeA=";
  }
