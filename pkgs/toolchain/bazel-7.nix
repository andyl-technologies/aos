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
  bazelZstdJni155 = import ./_bazel-zstd-jni.nix {
    mkDerivation = buildPackages.mkDerivation;
    fetchurl = buildPackages.fetchurl;
    stdenv = buildPackages.stdenv;
    inherit buildPackages;
    version = "1.5.5-11";
  };
  bazelMavenBootstrap = import ./_bazel-maven-bootstrap.nix {
    mkDerivation = buildPackages.mkDerivation;
    fetchurl = buildPackages.fetchurl;
    inherit buildPackages bazelZstdJni155;
  };
  bazelLogkit = import ./_bazel-logkit.nix {
    mkDerivation = buildPackages.mkDerivation;
    fetchurl = buildPackages.fetchurl;
    inherit buildPackages bazelMavenBootstrap;
  };
  bazelMailApi = import ./_bazel-mail-api.nix {
    mkDerivation = buildPackages.mkDerivation;
    fetchurl = buildPackages.fetchurl;
    inherit buildPackages bazelMavenBootstrap;
  };
  bazelLog4j = import ./_bazel-log4j.nix {
    mkDerivation = buildPackages.mkDerivation;
    fetchurl = buildPackages.fetchurl;
    inherit buildPackages bazelMavenBootstrap bazelMailApi;
  };
  bazelAvalonApi = import ./_bazel-avalon-framework-api.nix {
    mkDerivation = buildPackages.mkDerivation;
    fetchurl = buildPackages.fetchurl;
    inherit buildPackages bazelLogkit bazelLog4j;
  };
  bazelLegacyJavaHttp = import ./_bazel-legacy-java-http.nix {
    mkDerivation = buildPackages.mkDerivation;
    fetchurl = buildPackages.fetchurl;
    inherit buildPackages bazelMavenBootstrap bazelAvalonApi bazelMailApi bazelLog4j;
  };
  bazelGoogleHttp = import ./_bazel-google-http.nix {
    mkDerivation = buildPackages.mkDerivation;
    fetchurl = buildPackages.fetchurl;
    inherit buildPackages bazelMavenBootstrap bazelLegacyJavaHttp bazelLog4j bazelAvalonApi bazelMailApi;
  };
  bazelZstdJni = import ./_bazel-zstd-jni.nix {
    mkDerivation = buildPackages.mkDerivation;
    fetchurl = buildPackages.fetchurl;
    stdenv = buildPackages.stdenv;
    inherit buildPackages;
  };
  bazelGrpcJavaPlugin = import ./_bazel-grpc-java-plugin.nix {
    mkDerivation = buildPackages.mkDerivation;
    inherit fetchgit buildPackages;
    protobuf = buildPackages.protobuf;
    abseil-cpp = buildPackages.abseil-cpp;
    zlib = buildPackages.zlib;
  };
  bazelProtobufJava = import ./_bazel-protobuf-java.nix {
    mkDerivation = buildPackages.mkDerivation;
    inherit buildPackages;
    protobuf = buildPackages.protobuf;
  };
  bazelProtobufJavaUtil = import ./_bazel-protobuf-java-util.nix {
    mkDerivation = buildPackages.mkDerivation;
    inherit buildPackages bazelMavenBootstrap;
    protobuf = buildPackages.protobuf;
    protobufJava = bazelProtobufJava;
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
    inherit bazelAsm bazelMavenBootstrap bazelAvalonApi bazelMailApi bazelLog4j bazelLegacyJavaHttp bazelGoogleHttp bazelZstdJni bazelGrpcJavaPlugin bazelProtobufJava bazelProtobufJavaUtil;
  };
in
  mkBazel {
    inherit (upstream) version update;
    source = bazelSource;
    srcHash = "sha256-YYGzVwwvZX2YmxFB+wwaCOtfCBBspXfcfcUufQI4N5o=";
    vendorDepsHash = "sha256-UIedT89X6y12snR54HGoZyLuFaHupcSDxu9ZibkzYeA=";
  }
