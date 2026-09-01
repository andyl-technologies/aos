##! OpenJDK 12 — bootstrap chain intermediate (built with openjdk-11)
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
  openjdk-11,
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
    major = 12;
    version = "12.0.2";
    build = "10";
    srcHash = "sha256-hJT6Om/+9ZDIa0AzeUIvMlEBvIZgdVfLJ8Z3TVlxC4Q=";
    prevJdk = openjdk-11;
    extraDarwinFrameworks = [java-native-foundation];
  }
