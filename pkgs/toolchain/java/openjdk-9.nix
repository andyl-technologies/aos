##! OpenJDK 9 — bootstrap chain intermediate (built with openjdk-8)
{
  mkDerivation,
  fetchurl,
  stdenv,
  buildPackages,
  gnumake,
  autoconf,
  bash,
  which,
  zip,
  unzip,
  gawk,
  coreutils,
  zlib,
  alsa-lib,
  binutils,
  cups,
  file,
  fontconfig,
  freetype,
  xorg-stubs,
  bootstrapTools,
  krb5,
  java-native-foundation,
  openjdk-8,
}: let
  mkOpenJDKBootstrap = import ./_openjdk-bootstrap.nix {
    inherit
      fetchurl
      mkDerivation
      stdenv
      buildPackages
      gnumake
      autoconf
      bash
      which
      zip
      unzip
      gawk
      coreutils
      zlib
      alsa-lib
      binutils
      cups
      file
      fontconfig
      freetype
      xorg-stubs
      bootstrapTools
      krb5
      ;
  };
in
  mkOpenJDKBootstrap {
    major = 9;
    version = "9.0.4";
    build = "12";
    srcHash = "sha256-Y1hwtR++gwC9zF6xrFEArtBnVvHSES0+g6KYuJ3OPtI=";
    prevJdk = openjdk-8;
    extraDarwinFrameworks = [java-native-foundation];

    # Run each compiler invocation directly. The shared compiler server loses
    # its connection during the second bootstrap build in the isolated builder.
    # Both bootstrap stages still compile the complete JDK image from source.
    extraConfigureFlags = ["--disable-javac-server"];

    # GCC rejects the duplicated using declaration in the AArch64 interpreter.
    extraPatches =
      if stdenv.hostPlatform.isLinux && stdenv.hostPlatform.isAarch64
      then [./openjdk-patches/remove-duplicate-aarch64-using-jdk9.patch]
      else [];
  }
