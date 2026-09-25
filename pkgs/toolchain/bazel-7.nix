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
  bazelGoogleJavaFormat = import ./_bazel-google-java-format.nix {
    mkDerivation = buildPackages.mkDerivation;
    fetchurl = buildPackages.fetchurl;
    inherit buildPackages bazelMavenBootstrap;
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
  bazelAsyncProfilerApi = import ./_bazel-async-profiler-api.nix {
    mkDerivation = buildPackages.mkDerivation;
    inherit fetchgit buildPackages;
  };
  bazelAsyncProfilerNative =
    if stdenv.hostPlatform.isLinux
    then
      import ./_bazel-async-profiler-native.nix {
        inherit mkDerivation fetchgit buildPackages stdenv gcc-libs;
      }
    else null;
  bazelAsyncProfiler =
    if bazelAsyncProfilerNative != null
    then
      import ./_bazel-async-profiler-jar.nix {
        inherit mkDerivation buildPackages stdenv bazelAsyncProfilerApi bazelAsyncProfilerNative;
      }
    else null;
  bazelJna = import ./_bazel-jna.nix {
    mkDerivation = buildPackages.mkDerivation;
    inherit fetchgit buildPackages;
  };
  bazelByteBuddy = import ./_bazel-byte-buddy-bootstrap.nix {
    mkDerivation = buildPackages.mkDerivation;
    fetchurl = buildPackages.fetchurl;
    inherit fetchgit buildPackages bazelAsm bazelJna bazelMavenBootstrap;
  };
  bazelByteBuddy114 = import ./_bazel-byte-buddy-1_14.nix {
    mkDerivation = buildPackages.mkDerivation;
    fetchurl = buildPackages.fetchurl;
    inherit fetchgit buildPackages bazelJna bazelMavenBootstrap;
  };
  bazelMockito = import ./_bazel-mockito.nix {
    mkDerivation = buildPackages.mkDerivation;
    fetchurl = buildPackages.fetchurl;
    inherit buildPackages bazelByteBuddy114 bazelMavenBootstrap;
  };
  bazelBlockHound = import ./_bazel-blockhound.nix {
    mkDerivation = buildPackages.mkDerivation;
    fetchurl = buildPackages.fetchurl;
    inherit buildPackages bazelByteBuddy bazelMavenBootstrap;
  };
  bazelNettyCommon = import ./_bazel-netty-common.nix {
    mkDerivation = buildPackages.mkDerivation;
    fetchurl = buildPackages.fetchurl;
    inherit buildPackages bazelMavenBootstrap bazelLog4j bazelLegacyJavaHttp bazelBlockHound bazelByteBuddy;
  };
  bazelNettyBase = import ./_bazel-netty-base.nix {
    mkDerivation = buildPackages.mkDerivation;
    fetchurl = buildPackages.fetchurl;
    inherit buildPackages bazelNettyCommon bazelMavenBootstrap bazelLog4j bazelLegacyJavaHttp bazelBlockHound bazelByteBuddy;
  };
  bazelJbossModules = import ./_bazel-jboss-modules.nix {
    mkDerivation = buildPackages.mkDerivation;
    inherit fetchgit buildPackages;
  };
  bazelNettyCodecJavaDeps = import ./_bazel-netty-codec-java-deps.nix {
    mkDerivation = buildPackages.mkDerivation;
    fetchurl = buildPackages.fetchurl;
    inherit buildPackages bazelJbossModules bazelNettyCommon bazelNettyBase bazelMavenBootstrap;
  };
  bazelNettyCodec = import ./_bazel-netty-codec.nix {
    mkDerivation = buildPackages.mkDerivation;
    fetchurl = buildPackages.fetchurl;
    inherit buildPackages bazelMavenBootstrap bazelNettyCommon bazelNettyBase bazelNettyCodecJavaDeps bazelProtobufJava;
    bazelZstdJni155 = bazelZstdJni155;
  };
  bazelNettyTransportExtras = import ./_bazel-netty-transport-extras.nix {
    mkDerivation = buildPackages.mkDerivation;
    fetchurl = buildPackages.fetchurl;
    inherit buildPackages bazelNettyCommon bazelNettyBase bazelNettyCodec bazelMavenBootstrap;
  };
  bazelBouncycastle = import ./_bazel-bouncycastle.nix {
    mkDerivation = buildPackages.mkDerivation;
    fetchurl = buildPackages.fetchurl;
    inherit buildPackages;
  };
  bazelNettyHandlerApis = import ./_bazel-netty-handler-apis.nix {
    mkDerivation = buildPackages.mkDerivation;
    fetchurl = buildPackages.fetchurl;
    inherit buildPackages;
  };
  bazelConscryptJava = import ./_bazel-conscrypt-java.nix {
    mkDerivation = buildPackages.mkDerivation;
    fetchurl = buildPackages.fetchurl;
    inherit buildPackages;
  };
  bazelNettyHandler = import ./_bazel-netty-handler.nix {
    mkDerivation = buildPackages.mkDerivation;
    fetchurl = buildPackages.fetchurl;
    inherit buildPackages bazelNettyCommon bazelNettyBase bazelNettyCodec bazelNettyTransportExtras bazelBouncycastle bazelNettyHandlerApis bazelConscryptJava;
  };
  bazelNettyCodecHttp = import ./_bazel-netty-codec-http.nix {
    mkDerivation = buildPackages.mkDerivation;
    fetchurl = buildPackages.fetchurl;
    inherit buildPackages bazelNettyCommon bazelNettyBase bazelNettyCodec bazelNettyCodecJavaDeps bazelNettyHandler;
  };
  bazelNettyHttp2Proxy = import ./_bazel-netty-http2-proxy.nix {
    mkDerivation = buildPackages.mkDerivation;
    fetchurl = buildPackages.fetchurl;
    inherit buildPackages bazelNettyCommon bazelNettyBase bazelNettyCodec bazelNettyCodecJavaDeps bazelNettyTransportExtras bazelNettyHandler bazelNettyCodecHttp;
  };
  bazelGrpcNetty = import ./_bazel-grpc-netty.nix {
    mkDerivation = buildPackages.mkDerivation;
    fetchurl = buildPackages.fetchurl;
    inherit buildPackages bazelMavenBootstrap bazelNettyCommon bazelNettyBase bazelNettyCodec bazelNettyTransportExtras bazelNettyHandler bazelNettyCodecHttp bazelNettyHttp2Proxy;
  };
  bazelNettyDns = import ./_bazel-netty-dns.nix {
    mkDerivation = buildPackages.mkDerivation;
    fetchurl = buildPackages.fetchurl;
    inherit buildPackages bazelNettyCommon bazelNettyBase bazelNettyCodec bazelNettyHandler;
  };
  bazelPcollections = import ./_bazel-pcollections.nix {
    mkDerivation = buildPackages.mkDerivation;
    inherit fetchgit buildPackages;
  };
  bazelListenableFutureEmpty = import ./_bazel-listenablefuture-empty.nix {
    mkDerivation = buildPackages.mkDerivation;
    fetchurl = buildPackages.fetchurl;
    inherit buildPackages;
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
    inherit
      bazelAsm
      bazelMavenBootstrap
      bazelAvalonApi
      bazelMailApi
      bazelLog4j
      bazelLegacyJavaHttp
      bazelGoogleHttp
      bazelGoogleJavaFormat
      bazelByteBuddy114
      bazelMockito
      bazelZstdJni
      bazelGrpcJavaPlugin
      bazelProtobufJava
      bazelProtobufJavaUtil
      bazelAsyncProfiler
      bazelNettyCommon
      bazelNettyBase
      bazelNettyCodec
      bazelNettyTransportExtras
      bazelNettyHandler
      bazelNettyCodecHttp
      bazelNettyHttp2Proxy
      bazelGrpcNetty
      bazelNettyDns
      bazelPcollections
      bazelListenableFutureEmpty
      ;
  };
in
  mkBazel {
    inherit (upstream) version update;
    source = bazelSource;
    srcHash = "sha256-YYGzVwwvZX2YmxFB+wwaCOtfCBBspXfcfcUufQI4N5o=";
    vendorDepsHash = "sha256-UIedT89X6y12snR54HGoZyLuFaHupcSDxu9ZibkzYeA=";
  }
