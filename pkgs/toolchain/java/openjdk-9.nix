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
  }
